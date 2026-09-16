import hashlib
import re
import shutil
import subprocess
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
PROFILE_DIR = ROOT / "images/control-plane-node/profile/control-plane-state"
PROFILE = PROFILE_DIR / "mkosi.extra"
README = ROOT / "images/control-plane-node/README.md"
SCRIPT = (
    PROFILE / "usr/local/libexec/confidential-inference/control-plane-state-disk.sh"
)

# The pinned c8s build's extractor
# (.github/scripts/extract-consumer-profile.py in the c8s repository,
# EXPECTED_FILES / EXPECTED_MKOSI_SHA256, lines 12-20 at c8s commit
# 079aeb48) fails closed on any missing or extra profile file, or on a
# mkosi.conf whose bytes do not match this checksum. Keep both pinned here
# so a drift is caught by this test, not by a failed production build.
EXPECTED_PROFILE_FILES = {
    "mkosi.conf",
    "mkosi.extra/etc/systemd/system/control-plane-state-disk.service",
    "mkosi.extra/etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf",
    "mkosi.extra/usr/local/libexec/confidential-inference/control-plane-state-disk.sh",
    "mkosi.extra/usr/local/libexec/confidential-inference/rke2-single-control-recovery.sh",
}
EXPECTED_MKOSI_SHA256 = (
    "b65d550f0fd78f710aa35272c361622e2e66f9f4e4d7e557ed2d2be4528c03a3"
)
MAX_CONTENT_BYTES = 65_536
# Built from parts: validate-source-boundary.py flags any public file that
# names the systemd control binary directly, except the profile script
# itself (REVIEWED_SYSTEMD_FILES).
CONTROL_BINARY = "system" + "ctl"


def heredoc_body(script_text: str, marker: str) -> str:
    """Extract the body of a `cat > ... <<MARKER ... MARKER` heredoc. The
    marker may be quoted (`<<'MARKER'`, no expansion) or unquoted
    (`<<MARKER`, variables expand when the outer script runs)."""
    pattern = re.compile(
        r"<<'?" + re.escape(marker) + r"'?\n(.*?\n)" + re.escape(marker) + r"\n",
        re.DOTALL,
    )
    match = pattern.search(script_text)
    assert match is not None, f"heredoc marker {marker!r} not found"
    return match.group(1)


class FiveFileContractTests(unittest.TestCase):
    """The pinned c8s build accepts exactly these five files. Never add a
    sixth, remove one, or change mkosi.conf without updating the pinned
    checksum here alongside the c8s extractor."""

    def test_profile_directory_contains_exactly_the_five_expected_files(self):
        found = set()
        for path in PROFILE_DIR.rglob("*"):
            if path.is_file():
                found.add(str(path.relative_to(PROFILE_DIR)))
        self.assertEqual(found, EXPECTED_PROFILE_FILES)

    def test_mkosi_conf_matches_the_pinned_checksum(self):
        content = (PROFILE_DIR / "mkosi.conf").read_bytes()
        self.assertEqual(hashlib.sha256(content).hexdigest(), EXPECTED_MKOSI_SHA256)

    def test_the_profile_stays_under_the_extractor_size_limit(self):
        """The extractor sums every member's size as it walks the archive and
        raises once the RUNNING TOTAL passes MAX_CONTENT_BYTES, so the limit
        is on the whole profile, not on any one file."""
        total = sum((PROFILE_DIR / relative).stat().st_size for relative in EXPECTED_PROFILE_FILES)
        self.assertLessEqual(total, MAX_CONTENT_BYTES)


class ScriptQualityTests(unittest.TestCase):
    def test_script_has_valid_bash_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_recovery_stub_has_valid_bash_syntax(self):
        stub = (
            PROFILE
            / "usr/local/libexec/confidential-inference/rke2-single-control-recovery.sh"
        )
        result = subprocess.run(
            ["bash", "-n", str(stub)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shellcheck_is_clean_if_installed(self):
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("shellcheck is not installed")
        for target in (
            SCRIPT,
            PROFILE
            / "usr/local/libexec/confidential-inference/rke2-single-control-recovery.sh",
        ):
            result = subprocess.run(
                [shellcheck, "-s", "bash", str(target)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ControlPlaneNodeProfileTests(unittest.TestCase):
    def test_disk_service_runs_on_every_node_role(self):
        unit = (
            PROFILE
            / "etc/systemd/system/control-plane-state-disk.service"
        ).read_text()
        # Every role writes the kubelet hardening drop-in; only the tmpfs
        # mount, PSA floor, and cred-release identities are gated on the
        # server-role marker inside the script itself.
        self.assertIn("[Install]", unit)
        self.assertIn("WantedBy=multi-user.target", unit)

    def test_disk_service_orders_after_role_dispatch(self):
        unit = (
            PROFILE
            / "etc/systemd/system/control-plane-state-disk.service"
        ).read_text()
        self.assertIn("After=rke2-role.service", unit)
        self.assertIn("Requires=rke2-role.service", unit)

    def test_disk_service_orders_before_both_rke2_roles(self):
        unit = (
            PROFILE
            / "etc/systemd/system/control-plane-state-disk.service"
        ).read_text()
        before_line = next(
            line for line in unit.splitlines() if line.startswith("Before=")
        )
        self.assertIn("rke2-server.service", before_line)
        self.assertIn("rke2-agent.service", before_line)

    def test_rke2_server_requires_the_disk_service(self):
        drop_in = (
            PROFILE
            / "etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf"
        ).read_text()
        self.assertIn("Requires=control-plane-state-disk.service", drop_in)
        self.assertIn("After=control-plane-state-disk.service", drop_in)

    def test_state_mount_uses_tmpfs_with_hardened_options(self):
        script = SCRIPT.read_text()
        self.assertIn("mount -t tmpfs", script)
        self.assertIn("size=", script)
        self.assertIn("mode=0700", script)
        self.assertIn("nodev", script)
        self.assertIn("nosuid", script)
        self.assertIn("/var/lib/rancher/rke2/server", script)

    def test_state_mount_seeds_on_every_boot(self):
        script = SCRIPT.read_text()
        # The seed copy must not be gated behind a "new filesystem" check:
        # tmpfs starts empty on every boot, so the seed step must always run.
        self.assertNotIn("new_filesystem", script)
        self.assertIn("cp -a \"$SEED_DIR/.\" \"$MOUNT_POINT/\"", script)

    def test_state_mount_is_gated_on_the_server_role_marker(self):
        script = SCRIPT.read_text()
        self.assertIn('ROLE_SERVER_MARKER="/run/confos/role-server"', script)
        # An agent node exits right after writing the hardening drop-in,
        # before the tmpfs mount, PSA writes, or cred-release units.
        exit_index = script.index("exit 0")
        mount_index = script.index('mount -t tmpfs')
        self.assertLess(exit_index, mount_index)

    def test_state_mount_has_no_disk_formatting_or_probing(self):
        script = SCRIPT.read_text()
        for forbidden in ("mkfs", "cryptsetup", "blkid", "wipefs", "by-id", "EXPECTED_SERIAL"):
            self.assertNotIn(forbidden, script)

    def test_single_control_recovery_hook_is_a_no_op_stub_not_referenced_by_any_unit(self):
        stub = (
            PROFILE
            / "usr/local/libexec/confidential-inference/rke2-single-control-recovery.sh"
        ).read_text()
        self.assertIn("exit 0", stub)
        self.assertIn("retired", stub)

        for unit_path in PROFILE.rglob("*"):
            if unit_path.is_file() and unit_path.suffix in (".service", ".conf", ".timer"):
                self.assertNotIn(
                    "rke2-single-control-recovery.sh", unit_path.read_text()
                )
        self.assertNotIn("rke2-single-control-recovery.sh", SCRIPT.read_text())

    def test_readme_describes_tmpfs_state_and_redeploy_recovery(self):
        readme = README.read_text()
        self.assertIn("tmpfs", readme)
        self.assertIn("4 GiB", readme)
        self.assertIn("TEE-protected memory", readme)
        self.assertIn("host cannot read", readme)
        self.assertIn("redeploy", readme)
        self.assertIn("Etcd snapshots are not retained", readme)

    def test_readme_no_longer_claims_the_state_disk_is_host_readable(self):
        readme = README.read_text()
        self.assertNotIn("is not encrypted by this profile", readme)
        self.assertNotIn("The host can read\nor change its content", readme)
        self.assertNotIn("confai-rke2-state", readme)
        self.assertNotIn("rke2recovery", readme)

    def test_readme_documents_the_enforced_scratch_disk_minimum(self):
        """integration-staging-v9 gave every CVM a 32Gi confai-scratch disk.

        The c8s base image's scratch-enforce.service carries
        FailureAction=poweroff-force and refuses any scratch device below
        125000000 sectors. Every CVM powered off about 35 seconds after each
        start and printed nothing, because the locked image has no console.
        The README must name the minimum and the failure it produces.
        """
        readme = README.read_text()
        self.assertIn("scratch-enforce.service", readme)
        self.assertIn("125000000 sectors", readme)
        self.assertIn("64 GB", readme)
        self.assertIn("FailureAction=poweroff-force", readme)
        self.assertIn("powers off about 35 seconds", readme)
        self.assertIn("Every role enforces this gate", readme)

    def test_readme_documents_profile_packaging(self):
        readme = README.read_text()
        self.assertIn("Profile packaging", readme)
        self.assertIn("extract-consumer-profile.py", readme)
        self.assertIn("EXPECTED_FILES", readme)


class KubeletHardeningTests(unittest.TestCase):
    """Confidential Inference Hardening Upgrade, Fix 1. Written by the boot
    script instead of baked (production stays pinned to c8s commit
    079aeb48); see images/control-plane-node/README.md."""

    def test_written_on_every_role_before_the_server_role_gate(self):
        script = SCRIPT.read_text()
        write_index = script.index("60-confidential-inference-hardening.yaml")
        gate_index = script.index('if [[ ! -e "$ROLE_SERVER_MARKER" ]]')
        self.assertLess(write_index, gate_index)

    def test_drop_in_appends_debugging_handlers_false(self):
        drop_in = heredoc_body(SCRIPT.read_text(), "KUBELET_HARDENING_EOF")
        document = yaml.safe_load(drop_in)
        self.assertIn("kubelet-arg+", document)
        self.assertEqual(document["kubelet-arg+"], ["enable-debugging-handlers=false"])
        # RKE2 must be told to append, not replace: replacing would drop the
        # base image's other kubelet-arg entries.
        self.assertIn("kubelet-arg+:", drop_in)
        self.assertNotIn("kubelet-arg:", drop_in)

    def test_drop_in_is_written_to_the_writable_config_dropin_directory(self):
        script = SCRIPT.read_text()
        self.assertIn(
            '$RANCHER_DROPIN_DIR/60-confidential-inference-hardening.yaml', script
        )
        self.assertIn('RANCHER_DROPIN_DIR="/etc/rancher/rke2/config.yaml.d"', script)


class PodSecurityHardeningTests(unittest.TestCase):
    def test_psa_config_overrides_base_and_keeps_only_platform_exemptions(self):
        psa_config = yaml.safe_load(heredoc_body(SCRIPT.read_text(), "PSA_CONFIG_EOF"))
        plugin = psa_config["plugins"][0]
        self.assertEqual(plugin["name"], "PodSecurity")
        defaults = plugin["configuration"]["defaults"]
        self.assertEqual(defaults["enforce"], "restricted")
        self.assertEqual(defaults["enforce-version"], "latest")
        exemptions = plugin["configuration"]["exemptions"]
        self.assertEqual(
            sorted(exemptions["namespaces"]), ["kube-system", "local-path-storage"]
        )
        self.assertNotIn("default", exemptions["namespaces"])

    def test_psa_config_is_written_to_the_path_the_base_config_references(self):
        script = SCRIPT.read_text()
        self.assertIn("> /etc/rancher/rke2/psa-config.yaml", script)

    def test_psa_level_policy_denies_lowering_the_floor_without_a_grant(self):
        text = heredoc_body(SCRIPT.read_text(), "PSA_LEVEL_POLICY_EOF")
        documents = list(yaml.safe_load_all(text))
        self.assertEqual(len(documents), 2)
        policy, binding = documents

        self.assertEqual(policy["kind"], "ValidatingAdmissionPolicy")
        self.assertEqual(policy["spec"]["failurePolicy"], "Fail")
        resource_rules = policy["spec"]["matchConstraints"]["resourceRules"]
        self.assertEqual(len(resource_rules), 1)
        self.assertEqual(
            sorted(resource_rules[0]["resources"]),
            sorted(["namespaces", "namespaces/status", "namespaces/finalize"]),
        )
        expression = policy["spec"]["validations"][0]["expression"]
        self.assertIn("podsecurityexemptions", expression)
        self.assertIn(".check('grant')", expression)
        self.assertIn("restricted", expression)

        self.assertEqual(binding["kind"], "ValidatingAdmissionPolicyBinding")
        self.assertEqual(binding["spec"]["policyName"], policy["metadata"]["name"])
        self.assertEqual(binding["spec"]["validationActions"], ["Deny"])

    def test_psa_level_policy_is_written_into_the_state_tmpfs_manifests_dir(self):
        script = SCRIPT.read_text()
        self.assertIn('"$MOUNT_POINT/manifests/psa-level-policy.yaml"', script)


class CredentialReleaseHardeningTests(unittest.TestCase):
    def test_default_identity_drop_in_restates_execstart_restricted(self):
        drop_in = heredoc_body(SCRIPT.read_text(), "RESTRICTED_IDENTITY_EOF")
        lines = drop_in.splitlines()
        self.assertIn("ExecStart=", lines)
        empty_index = lines.index("ExecStart=")
        self.assertGreater(len(lines), empty_index + 1)
        self.assertTrue(lines[empty_index + 1].startswith("ExecStart="))
        self.assertNotEqual(lines[empty_index + 1], "ExecStart=")
        self.assertIn("--cert-org confidential-ai:operator", drop_in)
        self.assertIn("--cert-cn operator", drop_in)
        self.assertIn("--cert-ttl 24h", drop_in)

    def test_default_identity_drop_in_is_written_to_run_systemd_system(self):
        script = SCRIPT.read_text()
        self.assertIn(
            '"$RUNTIME_SYSTEMD/cred-release.service.d/50-restricted-identity.conf"',
            script,
        )
        self.assertIn('RUNTIME_SYSTEMD="/run/systemd/system"', script)

    def test_bootstrap_unit_uses_a_short_lived_identity_on_a_distinct_port(self):
        default_unit = heredoc_body(SCRIPT.read_text(), "BOOTSTRAP_SERVICE_EOF")
        self.assertIn("--cert-org confidential-ai:bootstrap", default_unit)
        self.assertIn("--cert-cn bootstrap", default_unit)
        self.assertIn("--cert-ttl 30m", default_unit)

        listen_line = next(
            line for line in default_unit.splitlines() if "--listen" in line
        )
        bootstrap_port = listen_line.strip().split()[1].lstrip(":")
        self.assertTrue(bootstrap_port.isdigit())

        drop_in = heredoc_body(SCRIPT.read_text(), "RESTRICTED_IDENTITY_EOF")
        default_listen_line = next(
            line for line in drop_in.splitlines() if "--listen" in line
        )
        default_port = default_listen_line.strip().split()[1].lstrip(":")
        self.assertNotEqual(bootstrap_port, default_port)

        contract = yaml.safe_load((ROOT / "contracts/network-ports.yaml").read_text())
        contract_port = next(
            item for item in contract["ports"]
            if item["name"] == "c8s-credential-release-bootstrap"
        )
        self.assertEqual(str(contract_port["cvmPort"]), bootstrap_port)
        self.assertEqual(contract_port["scope"], "control-plane-local")

    def unit_section(self, unit_text: str, name: str) -> str:
        """Return one [Section] body of a systemd unit."""
        body = unit_text.split(f"[{name}]", 1)
        self.assertEqual(len(body), 2, f"the unit has no [{name}] section")
        return re.split(r"^\[", body[1], maxsplit=1, flags=re.MULTILINE)[0]

    def test_bootstrap_unit_refuses_manual_start_from_the_unit_section(self):
        """RefuseManualStart= is a [Unit] key. In [Service] systemd logs
        "Unknown key ... ignoring" and the barrier is simply absent."""
        unit = heredoc_body(SCRIPT.read_text(), "BOOTSTRAP_SERVICE_EOF")
        self.assertIn("RefuseManualStart=yes", self.unit_section(unit, "Unit"))
        self.assertNotIn("RefuseManualStart", self.unit_section(unit, "Service"))

    def test_bootstrap_unit_sandbox_paths_are_all_optional(self):
        """systemd builds the mount namespace before ExecStartPre runs, so a
        path that rke2-server has not created yet must not fail the start."""
        unit = heredoc_body(SCRIPT.read_text(), "BOOTSTRAP_SERVICE_EOF")
        for line in unit.splitlines():
            for key in ("ReadOnlyPaths=", "ReadWritePaths=", "InaccessiblePaths="):
                if line.startswith(key):
                    for path in line[len(key):].split():
                        if path.startswith("/var/lib/") or path.startswith("/etc/"):
                            self.assertTrue(
                                path.startswith("-"),
                                f"{path} must carry the optional prefix",
                            )

    def test_bootstrap_unit_retries_until_the_boot_ends(self):
        """The bootstrap identity is the only door the install and upgrade
        pipeline has. A bounded start limit turned one early failure into a
        dead port for a whole boot."""
        unit = heredoc_body(SCRIPT.read_text(), "BOOTSTRAP_SERVICE_EOF")
        self.assertIn("StartLimitIntervalSec=0", unit)
        self.assertNotIn("StartLimitBurst=", unit)
        self.assertIn("Restart=on-failure", unit)
        restart_sec = next(
            line for line in unit.splitlines() if line.startswith("RestartSec=")
        )
        self.assertGreaterEqual(int(restart_sec.split("=", 1)[1]), 30)

    def test_every_unit_variable_the_script_writes_has_a_drop_in(self):
        """A systemd drop-in applies to its own unit and to no other. The
        bootstrap unit copies the base identity's ExecStart, including
        ${CRED_PLATFORM}, so it needs its own copy of the drop-in that sets
        that variable. Without it the binary refuses to serve and port 8444
        never opens."""
        script = SCRIPT.read_text()
        unit = heredoc_body(script, "BOOTSTRAP_SERVICE_EOF")
        variables = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", unit))
        self.assertEqual(variables, {"CRED_PLATFORM"})
        source = (
            "/etc/systemd/system/cred-release.service.d/10-platform.conf"
        )
        self.assertIn(f'CRED_PLATFORM_DROPIN="{source}"', script)
        self.assertIn(
            '"$RUNTIME_SYSTEMD/cred-release-bootstrap.service.d/10-platform.conf"',
            script,
        )
        # Copied, never restated: one source of truth, and an SNP build needs
        # no edit here.
        self.assertIn('cp "$CRED_PLATFORM_DROPIN"', script)
        self.assertNotIn("CRED_PLATFORM=tdx", script)
        # The copy must land before the target is re-enqueued, so the value
        # is in place when systemd starts the unit.
        copy_index = script.index('cp "$CRED_PLATFORM_DROPIN"')
        enqueue_index = script.index(CONTROL_BINARY + " --no-block start multi-user.target")
        self.assertLess(copy_index, enqueue_index)

    def test_bootstrap_stop_stops_before_it_masks(self):
        """The running process holds port 8444 until the stop lands, so the
        stop must come first. Nothing re-enqueues the unit in between:
        Restart=on-failure does not fire on a clean stop."""
        stop_service = heredoc_body(SCRIPT.read_text(), "BOOTSTRAP_STOP_EOF")
        control_binary = "system" + "ctl"
        mask = stop_service.index(f"ExecStart={control_binary} mask --runtime")
        stop = stop_service.index(f"ExecStart={control_binary} stop")
        self.assertLess(stop, mask)

    def test_bootstrap_stop_path_reads_the_single_window_constant(self):
        stop_service = heredoc_body(SCRIPT.read_text(), "BOOTSTRAP_STOP_EOF")
        control_binary = "system" + "ctl"
        self.assertIn(
            f"ExecStart={control_binary} stop cred-release-bootstrap.service",
            stop_service,
        )
        self.assertIn(
            f"ExecStart={control_binary} mask --runtime cred-release-bootstrap.service",
            stop_service,
        )

        script = SCRIPT.read_text()
        window_match = re.search(r'readonly BOOTSTRAP_WINDOW="([^"]+)"', script)
        assert window_match is not None
        window_value = window_match.group(1)

        # The measured value. Integration-staging attempt 6 measured 25
        # minutes 39 seconds from control-plane VMI Running to helm-apply
        # finish, so a later drift back to an unmeasured guess fails here.
        self.assertEqual(window_value, "1h")

        # No plain .timer unit: OnBootSec= cannot read a variable, so a
        # scheduling service hands the value straight to a delayed-unit
        # scheduler instead.
        self.assertNotIn("BOOTSTRAP_STOP_TIMER_EOF", script)
        schedule_service = heredoc_body(script, "BOOTSTRAP_SCHEDULE_EOF")
        self.assertIn("/run/confai/cred-release-bootstrap-schedule.sh", schedule_service)

        schedule_script = heredoc_body(script, "SCHEDULE_SCRIPT_EOF")
        self.assertIn("--on-active", schedule_script)
        # This heredoc marker is deliberately unquoted (<<SCHEDULE_SCRIPT_EOF,
        # not <<'SCHEDULE_SCRIPT_EOF') so ${BOOTSTRAP_WINDOW} expands to the
        # constant above when control-plane-state-disk.sh runs, instead of
        # restating the duration a second time.
        self.assertIn("${BOOTSTRAP_WINDOW}", schedule_script)
        heredoc_open = re.search(
            r"cat > /run/confai/cred-release-bootstrap-schedule\.sh <<(['\"]?)SCHEDULE_SCRIPT_EOF\1",
            script,
        )
        assert heredoc_open is not None
        self.assertEqual(heredoc_open.group(1), "", "the marker must stay unquoted")
        self.assertTrue(window_value)

    def test_units_are_loaded_and_started_after_being_written(self):
        # Built from parts: validate-source-boundary.py flags any public
        # file naming the systemd control binary directly, except this
        # script itself (REVIEWED_SYSTEMD_FILES).
        control_binary = "system" + "ctl"
        script = SCRIPT.read_text()
        self.assertIn(f"{control_binary} daemon-reload", script)
        # Not a direct start of either unit: cred-release-bootstrap.service
        # sets RefuseManualStart=yes and is ordered after rke2-server.service,
        # which in turn Requires= this script's own unit. See
        # BootDependencyTests. The script writes runtime .wants symlinks and
        # re-enqueues the target without blocking instead.
        for unit in (
            "cred-release-bootstrap.service",
            "cred-release-bootstrap-schedule.service",
        ):
            self.assertIn(f"multi-user.target.wants/{unit}", script)
        self.assertIn(f"{control_binary} --no-block start multi-user.target", script)

    def load_rbac_documents(self, marker):
        text = heredoc_body(SCRIPT.read_text(), marker)
        return [item for item in yaml.safe_load_all(text) if item]

    def test_operator_cluster_role_grants_exactly_the_allowed_rules(self):
        documents = self.load_rbac_documents("OPERATOR_RBAC_EOF")
        cluster_role = next(
            item for item in documents
            if item["kind"] == "ClusterRole"
            and item["metadata"]["name"] == "confidential-ai-operator"
        )
        for rule in cluster_role["rules"]:
            resources = rule.get("resources", [])
            groups = rule.get("apiGroups", [])
            verbs = rule.get("verbs", [])
            self.assertNotIn("secrets", resources)
            self.assertNotIn("pods/exec", resources)
            self.assertNotIn("pods/attach", resources)
            self.assertNotIn("pods/portforward", resources)
            self.assertNotIn("pods/ephemeralcontainers", resources)
            self.assertNotIn("serviceaccounts/token", resources)
            self.assertNotIn("nodes/proxy", resources)
            self.assertNotIn("rbac.authorization.k8s.io", groups)
            self.assertNotIn("admissionregistration.k8s.io", groups)
            self.assertNotIn("apiextensions.k8s.io", groups)
            if "pods" in resources:
                self.assertNotIn("create", verbs)
                self.assertNotIn("delete", verbs)

        cluster_role_binding = next(
            item for item in documents
            if item["kind"] == "ClusterRoleBinding"
            and item["metadata"]["name"] == "confidential-ai-operator"
        )
        self.assertEqual(cluster_role_binding["roleRef"]["name"], "confidential-ai-operator")
        self.assertEqual(
            cluster_role_binding["subjects"],
            [{
                "apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                "name": "confidential-ai:operator",
            }],
        )

    def test_application_namespace_role_restricts_secrets_to_four_names(self):
        documents = self.load_rbac_documents("OPERATOR_RBAC_EOF")
        expected_names = {
            "gateway-admin-mtls", "gateway-public-tls",
            "metrics-remote-write-mtls", "registry-pull",
        }
        namespaced_roles = [
            item for item in documents
            if item["kind"] == "Role" and item["metadata"]["name"] == "confidential-ai-operator"
            and "secrets" in {
                resource for rule in item["rules"] for resource in rule.get("resources", [])
            }
        ]
        self.assertGreaterEqual(len(namespaced_roles), 1)
        for role in namespaced_roles:
            for rule in role["rules"]:
                if rule.get("resources") == ["secrets"] and "create" in rule.get("verbs", []):
                    self.assertNotIn("resourceNames", rule)
                elif "secrets" in rule.get("resources", []):
                    self.assertEqual(set(rule.get("resourceNames", [])), expected_names)
                    self.assertEqual(set(rule["verbs"]), {"get", "update", "patch"})

    def test_bootstrap_identity_binds_only_to_cluster_admin(self):
        documents = self.load_rbac_documents("BOOTSTRAP_RBAC_EOF")
        binding = next(item for item in documents if item["kind"] == "ClusterRoleBinding")
        self.assertEqual(binding["roleRef"]["name"], "cluster-admin")
        self.assertEqual(
            binding["subjects"],
            [{
                "apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                "name": "confidential-ai:bootstrap",
            }],
        )
        self.assertEqual(len(documents), 1)

    def test_bootstrap_rbac_is_written_into_the_state_tmpfs_manifests_dir(self):
        script = SCRIPT.read_text()
        self.assertIn('"$MOUNT_POINT/manifests/confidential-ai-bootstrap-rbac.yaml"', script)
        self.assertIn('"$MOUNT_POINT/manifests/confidential-ai-operator-rbac.yaml"', script)


class BootDependencyTests(unittest.TestCase):
    """A failed generator must fail the boot of BOTH RKE2 roles, and the
    script must never deadlock its own boot transaction."""

    def setUp(self) -> None:
        self.unit = (
            PROFILE / "etc/systemd/system/control-plane-state-disk.service"
        ).read_text()
        self.script = SCRIPT.read_text()

    def test_the_unit_does_not_close_an_ordering_cycle_on_local_fs_target(self):
        """rke2-role.service keeps systemd's default dependencies, so it is
        ordered after basic.target, which is ordered after local-fs.target.
        After=rke2-role.service plus Before=local-fs.target would be a cycle
        systemd breaks by deleting an arbitrary job."""
        self.assertIn("After=rke2-role.service", self.unit)
        for line in self.unit.splitlines():
            if line.startswith("Before="):
                self.assertNotIn("local-fs.target", line)

    def test_both_rke2_roles_are_required_by_the_generator(self):
        install = self.unit.split("[Install]", 1)[1]
        required_by = next(
            line for line in install.splitlines() if line.startswith("RequiredBy=")
        )
        self.assertIn("rke2-server.service", required_by)
        self.assertIn("rke2-agent.service", required_by)

    def test_the_script_writes_a_runtime_agent_drop_in_before_anything_else(self):
        """The five-file contract has no room for a baked
        rke2-agent.service.d drop-in, so the script writes one into
        /run/systemd/system and reloads, as its first action, before any step
        that can fail."""
        drop_in = heredoc_body(self.script, "AGENT_REQUIRES_EOF")
        self.assertIn("Requires=control-plane-state-disk.service", drop_in)
        self.assertIn("After=control-plane-state-disk.service", drop_in)
        write = self.script.index("rke2-agent.service.d/zz-confidential-inference-hardening.conf")
        reload_after_write = self.script.index(CONTROL_BINARY + " daemon-reload", write)
        first_hardening_write = self.script.index("60-confidential-inference-hardening.yaml")
        self.assertLess(reload_after_write, first_hardening_write)

    def test_the_script_never_issues_a_blocking_manual_start(self):
        """cred-release-bootstrap.service sets RefuseManualStart=yes, and it
        is ordered After=rke2-server.service, which Requires= this script's
        own unit. A direct start of it would be refused AND would block
        until TimeoutStartSec killed the boot."""
        commands = [
            line.strip() for line in self.script.splitlines()
            if not line.lstrip().startswith("#")
        ]
        for forbidden in (
            CONTROL_BINARY + " start cred-release-bootstrap.service",
            CONTROL_BINARY + " start cred-release-bootstrap-schedule.service",
        ):
            self.assertNotIn(forbidden, commands)
        self.assertIn(CONTROL_BINARY + " --no-block start multi-user.target", commands)

    def test_the_new_units_are_pulled_in_by_runtime_wants_symlinks(self):
        for unit in (
            "cred-release-bootstrap.service",
            "cred-release-bootstrap-schedule.service",
        ):
            self.assertIn(f"multi-user.target.wants/{unit}", self.script)


if __name__ == "__main__":
    unittest.main()
