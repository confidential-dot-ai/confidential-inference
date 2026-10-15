"""Test native platform composition with the selected C8s matcher."""

import copy
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
NATIVE = runpy.run_path(str(ROOT / "scripts/native_c8s_allowlist.py"))


class NativeRouterPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c8s = yaml.safe_load((ROOT / "release/spec.yaml").read_text())["c8s"]
        cls.record = json.loads((ROOT / "release/inputs/c8s-seeds" /
            (cls.c8s["sourceCommit"] + ".json")).read_text())
        cls.configs = json.loads((ROOT / "release/inputs/image-config.json").read_text())
        cls.entries = NATIVE["native_entries"](cls.c8s, cls.configs, cls.record)
        cls.temp = tempfile.TemporaryDirectory(prefix="native-router-matcher-")
        cls.binary = Path(cls.temp.name) / "match"
        source = Path(cls.temp.name) / "main.go"
        source.write_text('''package main
import("encoding/json"; "os"; "github.com/confidential-dot-ai/c8s/pkg/allowlist")
func main() {
 var input struct { Policy json.RawMessage; Running []allowlist.RunningContainer }
 if err:=json.NewDecoder(os.Stdin).Decode(&input);err!=nil {panic(err)}
 policy,err:=allowlist.ParseJSON(input.Policy);if err!=nil {panic(err)}
 name,_,err:=policy.MatchWorkload(input.Running)
 result:=map[string]string{"name":name};if err!=nil {result["error"]=err.Error()}
 if err:=json.NewEncoder(os.Stdout).Encode(result);err!=nil {panic(err)}
}
''')
        subprocess.run(["go", "build", "-o", str(cls.binary), str(source)],
            cwd=ROOT / "tools/c8s-allowlist-canonical", check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def match(self, rules):
        running = [{"Digest": item["digest"],
                    "Argv": item["command"]["argv"] + item["args"]["argv"]} for item in rules]
        policy = copy.deepcopy(self.record["allowlist"])
        policy["workloads"].update(self.entries)
        return json.loads(subprocess.run([str(self.binary)], input=json.dumps(
            {"Policy": policy, "Running": running}), text=True, capture_output=True,
            check=True).stdout)

    def test_late_authored_router_and_completed_acme_match_uniquely(self):
        entry = self.entries["c8s-router"]
        self.assertEqual(self.match(entry["containers"]), {"name": "c8s-router"})
        self.assertEqual(self.match(entry["containers"] + entry["initContainers"]),
                         {"name": "c8s-router"})
        self.assertEqual(len(entry["containers"]), 3)
        self.assertEqual(len(entry["initContainers"]), 1)
        self.assertNotIn("secrets", entry)

    def test_altered_or_missing_authored_process_fails_closed(self):
        entry = self.entries["c8s-router"]
        changed = copy.deepcopy(entry["containers"])
        changed[1]["command"]["argv"].append("--unreviewed")
        self.assertIn("error", self.match(changed))
        self.assertIn("error", self.match(entry["containers"][:-1]))
        foreign = copy.deepcopy(entry["containers"][1])
        foreign["command"]["argv"] = ["/c8s", "serve"]
        self.assertIn("error", self.match(entry["containers"] + [foreign]))

    def test_unpinned_foreign_duplicate_or_other_source_is_rejected(self):
        for change in ("duplicate", "foreign", "unpinned", "source"):
            record = copy.deepcopy(self.record)
            containers = record["nativeRouter"]["spec"]["template"]["spec"]["containers"]
            if change == "duplicate":
                containers.append(copy.deepcopy(containers[0]))
            elif change == "foreign":
                containers[0]["name"] = "foreign"
            elif change == "unpinned":
                containers[0]["image"] = "nginx:latest"
            else:
                record["sourceCommit"] = "0" * 40
            with self.subTest(change=change), self.assertRaises(NATIVE["NativeRuleError"]):
                NATIVE["native_entries"](self.c8s, self.configs, record)


if __name__ == "__main__":
    unittest.main()
