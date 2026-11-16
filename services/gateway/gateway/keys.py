"""In-memory key snapshots and authentication."""

import base64
import hashlib
import hmac
import re
import time
from datetime import UTC, datetime

from .limits import Rejected


def unpad(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid base64url")
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("invalid base64url")
    return decoded


class Keys:
    def __init__(self, pepper, environment):
        if not 32 <= len(pepper) <= 4096:
            raise ValueError("invalid pepper")
        self.pepper, self.environment = pepper, environment
        self.fingerprint = hashlib.sha256(b"confidential.ai/gateway-pepper-fingerprint/v1" + pepper).hexdigest()
        self.revision = None
        self.rows = []
        self.index = {}
        self.index_secret = hmac.digest(pepper, b"confidential.ai/gateway-verifier-index/v1", "sha256")
        self.updated = None
        self.skipped = 0
        self.limits = KeyLimits()
        self.metrics = None

    def apply(self, snapshot):
        try:
            result = self._apply(snapshot)
        except Rejected as error:
            if self.metrics:
                self.metrics.inc("gateway_key_registry_push_rejected_total", reason=error.code)
                if error.code == "pepper_mismatch":
                    self.metrics.set("gateway_key_registry_pepper_mismatch", 1)
            raise
        if self.metrics:
            self.metrics.set("gateway_key_registry_revision", self.revision)
            self.metrics.set("gateway_key_registry_stale_seconds", 0)
            self.metrics.set("gateway_key_registry_pepper_mismatch_rows", self.skipped)
            self.metrics.set("gateway_key_registry_pepper_mismatch", 0)
        return result

    def _apply(self, snapshot):
        if not isinstance(snapshot, dict):
            raise Rejected(400, "invalid_request")
        if snapshot.get("schemaVersion") != "confidential.ai/key-registry-snapshot/v1" or snapshot.get("environment") != self.environment:
            raise Rejected(400, "invalid_request")
        revision, rows = snapshot.get("revision"), snapshot.get("keys")
        if type(revision) is not int or revision < 1 or not isinstance(rows, list) or len(rows) > 10_000:
            raise Rejected(400, "invalid_request")
        fingerprint = snapshot.get("pepperFingerprint", "")
        if not isinstance(fingerprint, str) or not isinstance(snapshot.get("generatedAt", ""), str):
            raise Rejected(400, "invalid_request")
        if fingerprint and not hmac.compare_digest(fingerprint.encode(), self.fingerprint.encode()):
            raise Rejected(409, "pepper_mismatch")
        if self.revision is not None and revision < self.revision:
            raise Rejected(409, "stale_revision")
        try:
            usage = self.limits.parse_usage(snapshot.get("tokenUsage"))
        except (ValueError, TypeError, KeyError) as error:
            raise Rejected(400, "invalid_request") from error
        applied = self.revision != revision
        parsed, skipped, policies = [], 0, {}
        if applied:
            try:
                for row in rows:
                    if not isinstance(row, dict) or not all(isinstance(row.get(field), str) for field in ("id", "name", "owner", "prefix", "createdAt", "createdBy", "keyHash", "pepperFingerprint")):
                        raise ValueError("invalid key row")
                    if type(row.get("version")) is not int or not -(2**63) <= row["version"] < 2**63:
                        raise ValueError("invalid key version")
                    if not isinstance(row.get("tags", []), list) or not all(isinstance(tag, str) for tag in row.get("tags", [])):
                        raise ValueError("invalid key tags")
                    if row.get("revokedBy") is not None and not isinstance(row["revokedBy"], str):
                        raise ValueError("invalid revocation metadata")
                    algorithm = row.get("hashAlgorithm", "hmac-sha256")
                    if algorithm not in ("sha256", "hmac-sha256"):
                        raise ValueError("invalid algorithm")
                    digest = unpad(row["keyHash"])
                    policy = self.limits.policy(row)
                    timestamp(row["createdAt"])
                    if row.get("revokedAt") is not None:
                        timestamp(row["revokedAt"])
                    if algorithm == "sha256" and row["pepperFingerprint"]:
                        raise ValueError("unexpected pepper")
                    if algorithm == "hmac-sha256" and not hmac.compare_digest(row["pepperFingerprint"].encode(), self.fingerprint.encode()):
                        skipped += 1
                        continue
                    parsed.append((row["id"], algorithm, digest, row.get("revokedAt") is not None))
                    if row.get("revokedAt") is None:
                        policies[row["id"]] = policy
            except (KeyError, TypeError, ValueError) as error:
                raise Rejected(400, "invalid_request") from error
            index = {}
            for position, (identifier, algorithm, digest, revoked) in enumerate(parsed):
                tag = hmac.digest(self.index_secret, digest, "sha256")[:16]
                index.setdefault((algorithm, tag), []).append((position, identifier, digest, revoked))
            self.rows, self.index, self.skipped, self.revision = parsed, index, skipped, revision
            self.limits.replace(policies)
        self.limits.apply_usage(usage)
        self.updated = int(time.time())
        return {"revision": revision, "cachedRevision": revision, "accepted": len(parsed) if applied else 0,
                "skippedPepperMismatch": skipped if applied else 0, "applied": applied}

    def authenticate(self, authorization):
        if self.revision is None:
            raise Rejected(503, "key_registry_not_ready")
        if not authorization.isascii() or not authorization.startswith("Bearer ") or not 1 <= len(authorization[7:].encode()) <= 256:
            raise Rejected(401, "invalid_api_key")
        key = authorization[7:].encode()
        digests = {"sha256": hashlib.sha256(key).digest(), "hmac-sha256": hmac.digest(self.pepper, key, "sha256")}
        matches = []
        for algorithm, supplied in digests.items():
            # The lookup compares keyed index tags, not verifier digests.
            tag = hmac.digest(self.index_secret, supplied, "sha256")[:16]
            for position, identifier, digest, revoked in self.index.get((algorithm, tag), ()):
                if not revoked and hmac.compare_digest(digest, supplied):
                    matches.append((position, identifier))
        if matches:
            return min(matches)[1]
        raise Rejected(401, "invalid_api_key")

    def status(self):
        return {"cachedRevision": self.revision, "lastSuccessUnix": self.updated,
                "staleSeconds": max(0, int(time.time()) - self.updated) if self.updated else None,
                "rowCount": len(self.rows), "pepperMismatchCount": self.skipped, "pepperFingerprint": self.fingerprint}


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value):
        raise ValueError("invalid timestamp")
    return int(datetime.fromisoformat(value.upper().replace("Z", "+00:00")).timestamp())


def window_edges(window, now):
    moment = datetime.fromtimestamp(now, UTC)
    if window == "day":
        start = int(now // 86400) * 86400
        return start, start + 86400
    start = moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1)
    return int(start.timestamp()), int(end.timestamp())


class KeyLimits:
    def __init__(self):
        self.policies, self.buckets, self.local, self.admin = {}, {}, {}, {}
        self.as_of = None

    @staticmethod
    def policy(row):
        rate, budget = row.get("rateLimit"), row.get("tokenBudget")
        if rate is not None and not isinstance(rate, dict) or budget is not None and not isinstance(budget, dict):
            raise ValueError("invalid key policy")
        if rate is not None:
            burst = rate.get("burst")
            values = (rate["requestsPerMinute"], rate["requestsPerMinute"] if burst is None else burst)
            if any(type(value) is not int or not 1 <= value <= 1_000_000 for value in values):
                raise ValueError("invalid rate")
        if budget is not None:
            if type(budget["tokens"]) is not int or not 1 <= budget["tokens"] <= 10**15 or budget["window"] not in ("day", "month"):
                raise ValueError("invalid budget")
        return rate, budget

    def replace(self, policies):
        self.policies = policies
        self.buckets = {key: [min(level, policies[key][0].get("burst") or policies[key][0]["requestsPerMinute"]), updated]
                        for key, (level, updated) in self.buckets.items() if key in policies and policies[key][0]}
        self.local = {key: value for key, value in self.local.items() if key in policies and policies[key][1]}

    def apply_usage(self, parsed):
        if parsed is None:
            return
        as_of, keys = parsed
        if self.as_of is not None and as_of <= self.as_of:
            return
        self.as_of, self.admin = as_of, keys
        for key, (start, totals) in list(self.local.items()):
            self.local[key] = start, {second: tokens for second, tokens in totals.items() if second >= as_of - 30}

    @staticmethod
    def parse_usage(value):
        if value is None:
            return None
        if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
            raise ValueError("invalid usage totals")
        if len(value["keys"]) > 10_000:
            raise ValueError("too many usage rows")
        parsed = {}
        for row in value["keys"]:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise ValueError("invalid usage row")
            if type(row["tokens"]) is not int or not 0 <= row["tokens"] < 2**64:
                raise ValueError("invalid tokens")
            parsed[row["id"]] = timestamp(row["windowStart"]), row["tokens"]
        return timestamp(value["asOf"]), parsed

    def spent(self, key, start):
        admin_start, admin = self.admin.get(key, (None, 0))
        local_start, local = self.local.get(key, (None, {}))
        return (admin if admin_start == start else 0) + (sum(local.values()) if local_start == start else 0)

    def admit(self, key):
        import math
        rate, budget = self.policies.get(key, (None, None))
        now = time.time()
        if budget:
            start, end = window_edges(budget["window"], now)
            if self.spent(key, start) >= budget["tokens"]:
                raise Rejected(429, "insufficient_quota", max(1, end - int(now)))
        if rate:
            capacity = rate.get("burst") or rate["requestsPerMinute"]
            level, updated = self.buckets.get(key, (capacity, now))
            refill = rate["requestsPerMinute"] / 60
            level = min(capacity, level + max(0, now - updated) * refill)
            self.buckets[key] = [level, max(now, updated)]
            if level < 1:
                raise Rejected(429, "rate_limit_exceeded", max(1, math.ceil((1 - level) / refill)))
            self.buckets[key][0] -= 1

    def record(self, key, tokens):
        from collections import defaultdict
        budget = self.policies.get(key, (None, None))[1]
        if not budget or not tokens:
            return
        now = int(time.time())
        start, _ = window_edges(budget["window"], now)
        held_start, totals = self.local.get(key, (start, defaultdict(int)))
        if held_start != start:
            totals = defaultdict(int)
        self.local[key] = start, totals
        totals[now] = totals.get(now, 0) + tokens
        # A compact older bucket bounds state even through a long admin outage.
        cutoff = max(start, now - 600)
        older = sum(value for second, value in totals.items() if second < cutoff)
        for second in list(totals):
            if second < cutoff:
                del totals[second]
        if older:
            totals[cutoff - 1] = older


class AdminAuth:
    def __init__(self, certificate, hashes):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        key = x509.load_pem_x509_certificate(certificate).public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("invalid admin signer")
        if len(hashes) > 2 or any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value) for value in hashes):
            raise ValueError("invalid admin key hashes")
        self.public_key, self.hashes, self.nonces = key, hashes, {}

    @staticmethod
    def one(headers, name):
        values = headers.getall(name, [])
        if not values:
            raise Rejected(401, "missing_signature")
        if len(values) != 1:
            raise Rejected(401, "duplicate_signature_header")
        return values[0]

    def verify(self, request, body):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        if "Authorization" in request.headers:
            value = self.one(request.headers, "Authorization")
            if not value.isascii() or not value.startswith("Bearer "):
                raise Rejected(401, "invalid_authorization")
            supplied = hashlib.sha256(value[7:].encode()).hexdigest()
            matched = 0
            for accepted in self.hashes:
                matched |= hmac.compare_digest(supplied, accepted)
            if not matched:
                raise Rejected(401, "invalid_api_key")
            return
        version, stamp, nonce, digest, signature = (self.one(request.headers, name) for name in (
            "X-Admin-Signature-Version", "X-Admin-Timestamp", "X-Admin-Nonce", "X-Admin-Body-SHA256", "X-Admin-Signature"))
        if version != "v1":
            raise Rejected(401, "unsupported_signature_version")
        if not stamp.isascii() or not stamp.isdecimal() or int(stamp) >= 2**64:
            raise Rejected(401, "invalid_timestamp")
        now, signed_at = int(time.time()), int(stamp)
        if abs(now - signed_at) > 60:
            raise Rejected(401, "stale_signature")
        if len(nonce) != 32 or any(c not in "0123456789abcdefABCDEF" for c in nonce):
            raise Rejected(401, "invalid_nonce")
        actual = hashlib.sha256(body).hexdigest()
        if digest != actual:
            raise Rejected(401, "body_hash_mismatch")
        canonical = f"v1\n{stamp}\n{nonce}\n{request.method}\n{request.raw_path}\n{actual}\n".encode()
        try:
            self.public_key.verify(unpad(signature), canonical, ec.ECDSA(hashes.SHA256()))
        except (ValueError, InvalidSignature) as error:
            raise Rejected(401, "invalid_signature") from error
        self.nonces = {value: expiry for value, expiry in self.nonces.items() if expiry >= now}
        if nonce in self.nonces:
            raise Rejected(401, "replayed_signature")
        if len(self.nonces) >= 4096:
            raise Rejected(401, "nonce_store_full")
        self.nonces[nonce] = max(now, signed_at) + 60
