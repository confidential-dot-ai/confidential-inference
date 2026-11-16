"""Validate startup inputs before opening either listener."""

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


@dataclass
class Config:
    environment: str = ""
    models: list[str] = field(default_factory=list)
    catalog: list[str] = field(default_factory=list)
    upstream: str = "http://127.0.0.1:30001"
    maximum_body: int = 2_097_152
    body_memory: int = 268_435_456
    body_timeout: int = 10
    first_timeout: int = 60
    idle_timeout: int = 60
    upstream_timeout: int = 900
    execution: int = 64
    queue: int = 64
    queue_timeout: int = 2
    per_key: int = 4
    public_capacity: int = 256
    per_address: int = 16
    address_rate: int = 30
    trusted_proxies: list[str] = field(default_factory=list)
    maximum_headers: int = 64
    maximum_header_bytes: int = 16_384
    maximum_uri: int = 2048
    header_timeout: int = 5
    admin_endpoint: str = ""
    usage_enabled: bool = False
    usage_models: dict = field(default_factory=dict)
    listen: str = "0.0.0.0:9443"
    metrics_listen: str = "0.0.0.0:9090"
    secret_wait: int = 300
    shutdown_grace: int = 900
    endpoint_drain: int = 35
    pepper_file: str = "/run/c8s/secrets/GATEWAY_API_KEY_PEPPER"
    admin_file: str = "/run/c8s/secrets/product-usage"
    signer_file: str = "/mnt/c8s-data/admin-auth/client.crt"
    hashes_file: str = "/mnt/c8s-data/admin-api-key/sha256"
    instance: str | None = None
    router_namespace: str | None = None
    direct: bool = False

    @classmethod
    def from_env(cls, arguments=None):
        config = cls()
        mappings = {
            "environment": ("DEPLOYMENT_ENVIRONMENT", str, "environment"),
            "upstream": ("GATEWAY_INFERENCE_URL", str, "inference-url"),
            "maximum_body": ("GATEWAY_MAXIMUM_BODY_BYTES", int, "maximum-body-bytes"),
            "body_memory": ("GATEWAY_BODY_MEMORY_BYTES", int, "body-memory-bytes"),
            "body_timeout": (
                "GATEWAY_BODY_TIMEOUT_SECONDS",
                int,
                "body-timeout-seconds",
            ),
            "first_timeout": (
                "GATEWAY_FIRST_TOKEN_TIMEOUT_SECONDS",
                int,
                "first-token-timeout-seconds",
            ),
            "idle_timeout": (
                "GATEWAY_STREAM_IDLE_TIMEOUT_SECONDS",
                int,
                "stream-idle-timeout-seconds",
            ),
            "upstream_timeout": (
                "GATEWAY_UPSTREAM_TIMEOUT_SECONDS",
                int,
                "upstream-timeout-seconds",
            ),
            "execution": (
                "GATEWAY_INFERENCE_CONCURRENCY",
                int,
                "inference-concurrency",
            ),
            "queue": ("GATEWAY_INFERENCE_QUEUE", int, "inference-queue"),
            "queue_timeout": (
                "GATEWAY_QUEUE_TIMEOUT_SECONDS",
                int,
                "queue-timeout-seconds",
            ),
            "per_key": ("GATEWAY_PER_KEY_CONCURRENCY", int, "per-key-concurrency"),
            "public_capacity": (
                "GATEWAY_GLOBAL_REQUEST_CONCURRENCY",
                int,
                "global-request-concurrency",
            ),
            "per_address": (
                "GATEWAY_PER_ADDRESS_CONCURRENCY",
                int,
                "per-address-concurrency",
            ),
            "address_rate": (
                "GATEWAY_REQUESTS_PER_ADDRESS_PER_SECOND",
                int,
                "requests-per-address-per-second",
            ),
            "maximum_headers": ("GATEWAY_MAXIMUM_HEADERS", int, "maximum-headers"),
            "maximum_header_bytes": (
                "GATEWAY_MAXIMUM_HEADER_BYTES",
                int,
                "maximum-header-bytes",
            ),
            "maximum_uri": ("GATEWAY_MAXIMUM_URI_BYTES", int, "maximum-uri-bytes"),
            "header_timeout": (
                "GATEWAY_HEADER_TIMEOUT_SECONDS",
                int,
                "header-timeout-seconds",
            ),
            "admin_endpoint": ("GATEWAY_ADMIN_ENDPOINT", str, "admin-endpoint"),
            "listen": ("GATEWAY_LISTEN", str, "listen"),
            "metrics_listen": ("GATEWAY_METRICS_LISTEN", str, "metrics-listen"),
            "secret_wait": ("GATEWAY_SECRET_WAIT_SECONDS", int, "secret-wait-seconds"),
            "shutdown_grace": (
                "GATEWAY_SHUTDOWN_GRACE_SECONDS",
                int,
                "shutdown-grace-seconds",
            ),
            "endpoint_drain": (
                "GATEWAY_ENDPOINT_DRAIN_SECONDS",
                int,
                "endpoint-drain-seconds",
            ),
            "pepper_file": ("GATEWAY_API_KEY_PEPPER_FILE", str, "api-key-pepper-file"),
            "admin_file": ("GATEWAY_ADMIN_CONFIG_FILE", str, "admin-config-file"),
            "signer_file": (
                "GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE",
                str,
                "admin-signer-certificate-file",
            ),
            "hashes_file": (
                "GATEWAY_ADMIN_API_KEY_HASHES_FILE",
                str,
                "admin-api-key-hashes-file",
            ),
            "instance": ("GATEWAY_INSTANCE_ID", str, "gateway-instance-id"),
            "router_namespace": ("GATEWAY_ROUTER_NAMESPACE", str, "router-namespace"),
        }
        parser = argparse.ArgumentParser(prog="confidential-gateway")
        for attribute, (name, parse, flag) in mappings.items():
            parser.add_argument(
                "--" + flag,
                dest=attribute,
                type=parse,
                default=os.environ.get(name, getattr(config, attribute)),
            )
        parser.add_argument("--model", default=os.environ.get("GATEWAY_MODEL", ""))
        parser.add_argument(
            "--runtime-config", default=os.environ.get("GATEWAY_RUNTIME_CONFIG", "null")
        )
        parser.add_argument(
            "--usage-models", default=os.environ.get("GATEWAY_USAGE_MODELS", "{}")
        )
        for flag, name in (
            ("usage-enabled", "GATEWAY_USAGE_ENABLED"),
            ("allow-direct-inference-url", "GATEWAY_ALLOW_DIRECT_INFERENCE_URL"),
        ):
            value = os.environ.get(name, "false")
            if value not in ("true", "false"):
                raise ValueError("invalid boolean setting")
            parser.add_argument(
                "--" + flag, action="store_true", default=value == "true"
            )
        parser.add_argument(
            "--trusted-proxy-cidrs",
            default=os.environ.get("GATEWAY_TRUSTED_PROXY_CIDRS", ""),
        )
        args = parser.parse_args(arguments)
        for attribute in mappings:
            setattr(config, attribute, getattr(args, attribute))
        config.models, config.catalog = [args.model], [args.model]
        config.direct = args.allow_direct_inference_url
        config.usage_enabled, config.usage_models = (
            args.usage_enabled,
            json.loads(args.usage_models),
        )
        config.trusted_proxies = list(filter(None, args.trusted_proxy_cidrs.split(",")))
        settings = json.loads(args.runtime_config)
        if settings is not None:
            config.apply(settings)
        config.validate()
        return config

    def apply(self, settings):
        names = {
            "maximumBodyBytes": "maximum_body",
            "bodyMemoryBytes": "body_memory",
            "bodyTimeoutSeconds": "body_timeout",
            "firstTokenTimeoutSeconds": "first_timeout",
            "streamIdleTimeoutSeconds": "idle_timeout",
            "upstreamTimeoutSeconds": "upstream_timeout",
            "inferenceConcurrency": "execution",
            "inferenceQueue": "queue",
            "queueTimeoutSeconds": "queue_timeout",
            "perKeyConcurrency": "per_key",
            "globalRequestConcurrency": "public_capacity",
            "perAddressConcurrency": "per_address",
            "requestsPerAddressPerSecond": "address_rate",
        }
        allowed = set(names) | {
            "schemaVersion",
            "routerService",
            "catalogModelIds",
            "inferenceModelIds",
            "attestationCacheSeconds",
            "attestationConcurrency",
        }
        required = allowed - {
            "routerService",
            "firstTokenTimeoutSeconds",
            "bodyMemoryBytes",
        }
        if (
            not isinstance(settings, dict)
            or type(settings.get("schemaVersion")) is not int
            or settings.get("schemaVersion") != 1
            or set(settings) - allowed
            or required - set(settings)
            or any(settings[name] is None for name in required)
        ):
            raise ValueError("invalid gateway settings")
        for name in ("attestationCacheSeconds", "attestationConcurrency"):
            if type(settings[name]) is not int or not 0 <= settings[name] < 2**64:
                raise ValueError("invalid gateway settings")
        self.models, self.catalog = (
            settings["inferenceModelIds"],
            settings["catalogModelIds"],
        )
        for name, attribute in names.items():
            if name in settings and settings[name] is not None:
                setattr(self, attribute, settings[name])
        self.first_timeout = (
            self.idle_timeout
            if settings.get("firstTokenTimeoutSeconds") is None
            else settings["firstTokenTimeoutSeconds"]
        )
        service = settings.get("routerService")
        if service is not None:
            if (
                not isinstance(service, str)
                or not re.fullmatch(r"(?:sglang-router|router-[a-z0-9-]+)", service)
                or len(service) > 63
                or service.endswith("-")
            ):
                raise ValueError("invalid router service")
            if not self.router_namespace or not self.direct:
                raise ValueError("router service requires its fixed namespace")
            origin = urlsplit(self.upstream)
            if (
                origin.username
                or origin.password
                or origin.query
                or origin.fragment
                or origin.path not in ("", "/")
            ):
                raise ValueError("invalid router origin")
            port = origin.port or (443 if origin.scheme == "https" else 80)
            self.upstream = urlunsplit(
                (
                    origin.scheme,
                    f"{service}.{self.router_namespace}.svc.cluster.local:{port}",
                    "",
                    "",
                    "",
                )
            )

    def validate(self):
        import ipaddress

        dns = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if (
            not re.fullmatch(dns, self.environment)
            or self.instance is not None
            and not re.fullmatch(dns, self.instance)
        ):
            raise ValueError("invalid environment or instance name")
        if self.router_namespace is not None and not re.fullmatch(
            dns, self.router_namespace
        ):
            raise ValueError("invalid router namespace")
        for names in (self.models, self.catalog):
            if (
                not isinstance(names, list)
                or len(names) > 1024
                or any(
                    not isinstance(name, str)
                    or not name
                    or len(name.encode()) > 256
                    or any(ord(c) < 32 or ord(c) == 127 for c in name)
                    for name in names
                )
                or len(set(names)) != len(names)
            ):
                raise ValueError("invalid model list")
        if not self.models or not set(self.catalog) <= set(self.models):
            raise ValueError("invalid catalog")
        bounds = {
            "maximum_body": (1024, 64 * 1024**2),
            "body_memory": (5 * self.maximum_body + 65536, 1 << 40),
            "maximum_headers": (1, 256),
            "maximum_header_bytes": (8192, 128 * 1024),
            "maximum_uri": (256, 8192),
            "header_timeout": (1, 30),
            "body_timeout": (1, 60),
            "first_timeout": (1, 14400),
            "idle_timeout": (1, 300),
            "upstream_timeout": (1, 86400),
            "execution": (1, 1024),
            "queue": (0, 4096),
            "queue_timeout": (1, 30),
            "per_key": (1, 128),
            "public_capacity": (1, 4096),
            "per_address": (1, 256),
            "address_rate": (1, 10000),
            "secret_wait": (1, 600),
            "shutdown_grace": (0, 86400),
            "endpoint_drain": (0, 3600),
        }
        if any(
            type(getattr(self, name)) is not int
            or not low <= getattr(self, name) <= high
            for name, (low, high) in bounds.items()
        ):
            raise ValueError("invalid protection limits")
        if (
            self.first_timeout > self.upstream_timeout
            or self.idle_timeout > self.upstream_timeout
        ):
            raise ValueError("invalid response deadlines")
        if not self.direct and self.upstream != "http://127.0.0.1:30001":
            raise ValueError("direct inference requires explicit configuration")
        origin = urlsplit(self.upstream)
        if origin.scheme not in ("http", "https") or not origin.hostname:
            raise ValueError("invalid inference origin")
        if self.router_namespace and (
            origin.username
            or origin.password
            or origin.query
            or origin.fragment
            or origin.path not in ("", "/")
        ):
            raise ValueError("invalid router origin")
        for address, expected in ((self.listen, 9443), (self.metrics_listen, 9090)):
            host, port = address.rsplit(":", 1)
            ipaddress.ip_address(host.strip("[]"))
            if int(port) != expected:
                raise ValueError("invalid listener port")
        for value in self.trusted_proxies:
            ipaddress.ip_network(value)
        if not isinstance(self.usage_models, dict):
            raise ValueError("invalid usage model bindings")
        for model, binding in self.usage_models.items():
            if (
                not isinstance(model, str)
                or not isinstance(binding, dict)
                or not all(
                    isinstance(binding.get(field), str)
                    for field in ("served_model", "model_revision")
                )
            ):
                raise ValueError("invalid usage model bindings")
