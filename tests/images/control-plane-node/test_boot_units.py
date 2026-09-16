"""Layer 1 (seconds): systemd verification of every unit the control-plane
node profile writes at boot.

Every unit test_profile.py checks is checked there by pattern-matching the
heredoc text. This file goes one step further: it assembles every unit the
generator writes (control-plane-state-disk.sh's heredocs), every unit the
profile bakes (mkosi.extra), and the base c8s units they reference, into one
tree that mirrors the real boot-time layout, and asks systemd itself
(`systemd-analyze verify`) whether the result is valid. This is how PR #31's
defect (an ExecStart copied without the build-time drop-in that defines
${CRED_PLATFORM}) and the RefuseManualStart-in-the-wrong-section defect would
have failed CI before reaching a locked image bake: both are systemd-level
mistakes no static string match reliably catches for every future edit.

Base c8s units this profile's units order against or copy from
(cred-release.service, rke2-role.service, rke2-server.service.d/*,
rke2-agent.service.d/*, scratch-enforce.service, gpu-cc-enforce.service) are
vendored verbatim under fixtures/c8s-base/ and hash-checked against the
commit contracts/c8s-admission-source-lock.json pins, via `git show` against
a local c8s checkout when one is available (see C8S_CHECKOUT below).

Two units this profile's units reference are NOT part of the c8s repository
at that pin and cannot be hash-verified against it:
  - attestation-api.service is baked by a lower image layer (node-guest-base)
    this repository does not vendor.
  - rke2-server.service / rke2-agent.service (the main units, not the c8s
    drop-ins for them) are installed by RKE2's own installer at image build
    time, not shipped as files in the c8s tree.
Both are hand-written stubs under fixtures/external-stubs/, clearly marked
as such, sufficient only to let systemd resolve the unit name and its
dependents; see FixtureHashTests for what IS hash-verified.
"""
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from test_profile import PROFILE, ROOT, SCRIPT, heredoc_body

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
C8S_BASE = FIXTURES / "c8s-base"
EXTERNAL_STUBS = FIXTURES / "external-stubs"

SOURCE_LOCK = json.loads(
    (ROOT / "contracts/c8s-admission-source-lock.json").read_text()
)
C8S_PIN = SOURCE_LOCK["commit"]
# The c8s checkout is not part of this repository. Set C8S_CHECKOUT to the
# path of one. There is no default path: a maintainer path must not become a
# default in this repository. The fixture hash tests skip when it is unset.
C8S_CHECKOUT_ENV = "C8S_CHECKOUT"
_c8s_checkout = os.environ.get(C8S_CHECKOUT_ENV)
C8S_CHECKOUT = Path(_c8s_checkout) if _c8s_checkout else None

# Binaries this profile's units, and the c8s units they reference, run that
# are not part of a bare Ubuntu CI runner. systemd-analyze verify refuses an
# ExecStart whose command is not an executable file on disk; these five are
# the ones a locked node image provides and a CI runner does not, so a
# "Command ... is not executable" line naming exactly one of these is
# expected, not a defect. Anything else on that line is.
EXPECTED_MISSING_BINARIES = {
    "/usr/local/bin/c8s",
    "/usr/local/bin/rke2",
    "/usr/local/bin/rke2-role.sh",
    "/usr/local/bin/scratch-enforce.sh",
    "/usr/local/bin/gpu-cc-enforce.sh",
}

# The build-time drop-in the c8s sync hook renders from C8S_PLATFORM. Not a
# file in any git tree (it is generated during the image build), so it is
# synthesized here from builder-lock.json's pinned platform, for both
# locations that need it: the base cred-release.service.d/ (built once) and
# the copy control-plane-state-disk.sh makes into
# cred-release-bootstrap.service.d/ (see CRED_PLATFORM_DROPIN in the
# script).
_BUILDER_LOCK = json.loads(
    (ROOT / "images/control-plane-node/builder-lock.json").read_text()
)
CRED_PLATFORM_DROPIN_CONTENT = (
    f"[Service]\nEnvironment=CRED_PLATFORM={_BUILDER_LOCK['platform']}\n"
)

# path (relative to a flat systemd search directory) -> source of the unit
# fragment written by the SCRIPT's heredocs.
GENERATED_UNIT_MARKERS = {
    "cred-release-bootstrap.service": "BOOTSTRAP_SERVICE_EOF",
    "cred-release-bootstrap-stop.service": "BOOTSTRAP_STOP_EOF",
    "cred-release-bootstrap-schedule.service": "BOOTSTRAP_SCHEDULE_EOF",
    "cred-release.service.d/50-restricted-identity.conf": "RESTRICTED_IDENTITY_EOF",
    "rke2-agent.service.d/zz-confidential-inference-hardening.conf": "AGENT_REQUIRES_EOF",
}

# path (relative) -> path under PROFILE (the profile's five baked files that
# are systemd units, not scripts).
BAKED_UNIT_FILES = {
    "control-plane-state-disk.service": "etc/systemd/system/control-plane-state-disk.service",
    "rke2-server.service.d/zz-control-plane-state.conf": "etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf",
}

# path (relative) -> (source repo path in c8s at C8S_PIN, vendored fixture path)
C8S_FIXTURE_FILES = {
    "cred-release.service": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/cred-release.service",
    "scratch-enforce.service": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/scratch-enforce.service",
    "gpu-cc-enforce.service": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/gpu-cc-enforce.service",
    "rke2-role.service": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/rke2-role.service",
    "rke2-server.service.d/20-role.conf": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/rke2-server.service.d/20-role.conf",
    "rke2-server.service.d/no-modprobe.conf": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/rke2-server.service.d/no-modprobe.conf",
    "rke2-agent.service.d/20-role.conf": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/rke2-agent.service.d/20-role.conf",
    "rke2-agent.service.d/no-modprobe.conf": "node-guest-image/c8s/mkosi.extra/etc/systemd/system/rke2-agent.service.d/no-modprobe.conf",
}

EXTERNAL_STUB_FILES = {
    "attestation-api.service": "attestation-api.service",
    "rke2-server.service": "rke2-server.service",
    "rke2-agent.service": "rke2-agent.service",
}

SYNTHETIC_FILES = {
    "cred-release.service.d/10-platform.conf": CRED_PLATFORM_DROPIN_CONTENT,
    "cred-release-bootstrap.service.d/10-platform.conf": CRED_PLATFORM_DROPIN_CONTENT,
}

# The top-level unit names to hand to `systemd-analyze verify`. Drop-ins are
# not listed: verify loads a unit file's sibling "<name>.d/*.conf" directory
# on its own, so passing the base unit is enough to pull every fragment in.
TOP_LEVEL_UNITS = [
    "control-plane-state-disk.service",
    "cred-release-bootstrap.service",
    "cred-release-bootstrap-stop.service",
    "cred-release-bootstrap-schedule.service",
    "cred-release.service",
    "scratch-enforce.service",
    "gpu-cc-enforce.service",
    "rke2-role.service",
    "attestation-api.service",
    "rke2-server.service",
    "rke2-agent.service",
]


def collect_fragments() -> dict:
    """Return {relative_path: content} for every unit fragment in play."""
    script_text = SCRIPT.read_text()
    fragments = {}
    for path, marker in GENERATED_UNIT_MARKERS.items():
        fragments[path] = heredoc_body(script_text, marker)
    for path, relative in BAKED_UNIT_FILES.items():
        fragments[path] = (PROFILE / relative).read_text()
    for path, _source in C8S_FIXTURE_FILES.items():
        fragments[path] = (C8S_BASE / "etc/systemd/system" / path).read_text()
    for path, name in EXTERNAL_STUB_FILES.items():
        fragments[path] = (EXTERNAL_STUBS / "etc/systemd/system" / name).read_text()
    fragments.update(SYNTHETIC_FILES)
    return fragments


def write_unit_tree(root: Path, fragments: dict) -> None:
    for relative, content in fragments.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


class FixtureHashTests(unittest.TestCase):
    """The c8s-base fixtures must be byte-for-byte what the pinned commit
    ships. Skips (does not fail) when no c8s checkout is available, so this
    suite still runs layer 1's other tests in an environment without one."""

    @classmethod
    def setUpClass(cls):
        if C8S_CHECKOUT is None or not (C8S_CHECKOUT / ".git").exists():
            raise unittest.SkipTest(
                f"no c8s checkout; set {C8S_CHECKOUT_ENV} to the path of one. "
                "Fixture hashes are not verified this run"
            )
        result = subprocess.run(
            ["git", "-C", str(C8S_CHECKOUT), "cat-file", "-e", f"{C8S_PIN}^{{commit}}"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise unittest.SkipTest(
                f"c8s checkout at {C8S_CHECKOUT} does not have commit {C8S_PIN}"
            )

    def test_fixture_matches_the_pinned_c8s_commit(self):
        for relative, source_path in C8S_FIXTURE_FILES.items():
            with self.subTest(relative=relative):
                pinned = subprocess.run(
                    ["git", "-C", str(C8S_CHECKOUT), "show", f"{C8S_PIN}:{source_path}"],
                    capture_output=True, text=True, check=True,
                ).stdout
                vendored = (C8S_BASE / "etc/systemd/system" / relative).read_text()
                self.assertEqual(
                    vendored, pinned,
                    f"fixtures/c8s-base/etc/systemd/system/{relative} has drifted "
                    f"from c8s@{C8S_PIN}:{source_path}",
                )


class SystemdAnalyzeVerifyTests(unittest.TestCase):
    """Assemble every unit into one tree mirroring the boot-time layout and
    ask systemd-analyze verify whether it is valid: unknown keys, unknown
    lvalues, and ordering cycles all surface here."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("systemd-analyze") is None:
            raise unittest.SkipTest("systemd-analyze is not installed")
        import tempfile
        cls.tmpdir = tempfile.mkdtemp(prefix="ci-profile-boot-units-")
        cls.root = Path(cls.tmpdir)
        write_unit_tree(cls.root, collect_fragments())
        args = ["systemd-analyze", "verify"] + [
            str(cls.root / unit) for unit in TOP_LEVEL_UNITS
        ]
        proc = subprocess.run(args, capture_output=True, text=True)
        cls.returncode = proc.returncode
        cls.stdout = proc.stdout
        cls.stderr = proc.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def unexpected_lines(self):
        """Every output line, minus the ones that only report an
        EXPECTED_MISSING_BINARIES executable absent from a bare CI runner."""
        unexpected = []
        executable_pattern = re.compile(r"Command (\S+) is not executable")
        for line in (self.stdout + self.stderr).splitlines():
            match = executable_pattern.search(line)
            if match and match.group(1) in EXPECTED_MISSING_BINARIES:
                continue
            if line.strip():
                unexpected.append(line)
        return unexpected

    def test_no_unknown_keys_or_lvalues(self):
        for line in self.unexpected_lines():
            self.assertNotIn("Unknown key", line, line)
            self.assertNotIn("Unknown lvalue", line, line)

    def test_no_ordering_cycle(self):
        for line in self.unexpected_lines():
            self.assertNotIn("ordering cycle", line, line)
            self.assertNotIn("cyclic", line, line)

    def test_verify_reports_no_other_problem(self):
        # The return code alone is not the signal: verify exits 1 for an
        # EXPECTED_MISSING_BINARIES executable absent from a bare CI runner
        # too. The real signal is whether any UNEXPECTED line remains after
        # that known, environmental class is filtered out.
        unexpected = self.unexpected_lines()
        self.assertEqual(unexpected, [], "\n".join(unexpected))


class VariableResolutionTests(unittest.TestCase):
    """Every ${VAR} / $VAR an ExecStart or ExecStartPre references must have
    a matching Environment=VAR= or EnvironmentFile= in the same unit's own
    text, or in a drop-in for that exact unit — a drop-in applies only to
    its own unit, which is exactly the mistake PR #31 fixed."""

    def setUp(self):
        self.fragments = collect_fragments()

    def unit_group(self, unit_name: str) -> list:
        """All fragment keys (base unit + its own .d/*.conf) for one unit."""
        return [
            path for path in self.fragments
            if path == unit_name or path.startswith(unit_name + ".d/")
        ]

    @staticmethod
    def join_continuations(text: str) -> list:
        """Collapse a trailing-backslash line continuation (ExecStart=...
        \\\\\\n    --flag ...) into one logical line, the way systemd itself
        reads a unit file, so a $VAR on a continuation line is not missed."""
        joined = []
        buffer = ""
        for line in text.splitlines():
            if buffer:
                line = buffer + " " + line.strip()
                buffer = ""
            if line.endswith("\\"):
                buffer = line[:-1].rstrip()
                continue
            joined.append(line)
        if buffer:
            joined.append(buffer)
        return joined

    def defined_variables(self, group: list) -> set:
        defined = set()
        for path in group:
            text = self.fragments[path]
            for line in self.join_continuations(text):
                if line.startswith("Environment="):
                    body = line[len("Environment="):].strip()
                    for assignment in body.split():
                        if "=" in assignment:
                            defined.add(assignment.split("=", 1)[0])
                elif line.startswith("EnvironmentFile="):
                    # An EnvironmentFile= can define anything; treat its
                    # presence as satisfying every reference in this unit.
                    defined.add("__ENVIRONMENT_FILE_PRESENT__")
        return defined

    def referenced_variables(self, group: list) -> set:
        referenced = set()
        for path in group:
            text = self.fragments[path]
            for line in self.join_continuations(text):
                if line.startswith("ExecStart=") or line.startswith("ExecStartPre="):
                    referenced |= set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", line))
                    referenced |= set(re.findall(r"\$([A-Z_][A-Z0-9_]*)\b", line))
        return referenced

    def test_every_referenced_variable_has_a_definition_in_its_own_unit(self):
        unit_names = {
            path for path in self.fragments if not path.endswith(".conf")
        }
        for unit_name in sorted(unit_names):
            with self.subTest(unit=unit_name):
                group = self.unit_group(unit_name)
                defined = self.defined_variables(group)
                referenced = self.referenced_variables(group)
                if "__ENVIRONMENT_FILE_PRESENT__" in defined:
                    continue
                missing = referenced - defined
                self.assertEqual(
                    missing, set(),
                    f"{unit_name} references {sorted(missing)} but no "
                    f"Environment= in {group} defines it",
                )


class UnitTargetResolutionTests(unittest.TestCase):
    """Every After=/Requires=/Wants= target in a generated or baked unit
    must exist somewhere in the union of profile, generated, and base
    units — a target only the profile author assumed existed is exactly the
    class of mistake a systemd unit rename or a c8s bump can reintroduce."""

    # Standard systemd targets always present on a real boot; not part of
    # this profile's or c8s's own unit set.
    STANDARD_TARGETS = {
        "multi-user.target", "network-online.target", "basic.target",
        "sysinit.target", "local-fs.target", "shutdown.target",
        "umount.target",
    }

    # Units this profile's or c8s's units soft-order against (After=, never
    # Requires=) that live in a lower image layer this repository does not
    # vendor. nvidia-cc-ready.service is confos's own unit (see
    # gpu-cc-enforce.service's comment: "confos's nvidia-cc-ready sets the CC
    # ready state"); a GPU-less boot never needs it and gpu-cc-enforce.sh
    # no-ops, so this is a real, deliberately soft, external reference.
    EXTERNAL_KNOWN_UNITS = {"nvidia-cc-ready.service"}

    def setUp(self):
        self.fragments = collect_fragments()
        self.known_units = (
            {path.split(".d/", 1)[0] for path in self.fragments}
            | self.STANDARD_TARGETS
            | self.EXTERNAL_KNOWN_UNITS
        )

    def test_every_ordering_and_requirement_target_is_known(self):
        for path, text in self.fragments.items():
            if not path.endswith((".service", ".conf")):
                continue
            with self.subTest(path=path):
                for line in text.splitlines():
                    for key in ("After=", "Before=", "Requires=", "Wants=", "RequiredBy=", "WantedBy="):
                        if line.startswith(key):
                            for target in line[len(key):].split():
                                self.assertIn(
                                    target, self.known_units,
                                    f"{path}: {key}{target} names a unit not in "
                                    "the profile, generator output, or base fixtures",
                                )


class ScratchMinimumConsistencyTests(unittest.TestCase):
    """The profile's README documents a scratch-disk minimum that the base
    image's scratch-enforce.sh actually enforces (MIN_SECTORS). Keep the
    number in one place: this test, not a second hardcoded constant."""

    MIN_SECTORS = 125_000_000  # 64 GB at 512-byte sectors, decimal.

    def test_base_scratch_enforce_script_uses_the_documented_minimum(self):
        if C8S_CHECKOUT is None or not (C8S_CHECKOUT / ".git").exists():
            self.skipTest(f"no c8s checkout; set {C8S_CHECKOUT_ENV}")
        result = subprocess.run(
            ["git", "-C", str(C8S_CHECKOUT), "cat-file", "-e", f"{C8S_PIN}^{{commit}}"],
            capture_output=True,
        )
        if result.returncode != 0:
            self.skipTest(f"c8s checkout at {C8S_CHECKOUT} lacks commit {C8S_PIN}")
        script = subprocess.run(
            ["git", "-C", str(C8S_CHECKOUT), "show",
             f"{C8S_PIN}:node-guest-image/c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh"],
            capture_output=True, text=True, check=True,
        ).stdout
        match = re.search(r"MIN_SECTORS=(\d+)", script)
        assert match is not None, "scratch-enforce.sh no longer defines MIN_SECTORS"
        self.assertEqual(int(match.group(1)), self.MIN_SECTORS)

    def test_readme_documents_the_same_minimum(self):
        readme = (ROOT / "images/control-plane-node/README.md").read_text()
        self.assertIn(f"{self.MIN_SECTORS} sectors", readme)
        self.assertIn("64 GB", readme)


if __name__ == "__main__":
    unittest.main()
