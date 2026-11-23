"""Tests of the recipes (recipes/, scripts/recipe-values.py) and of the
confidential-sglang image pin (scripts/confidential_sglang_release.py).

They use no network and no cluster. The helm tests need helm on PATH.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import confidential_sglang_release as CSR  # noqa: E402


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RV = load("recipe_values", "scripts/recipe-values.py")
MAN = load("build_release_manifest_recipes", "scripts/build-release-manifest.py")
FIXTURES = ROOT / "tests/release-v1/fixtures/confidential-sglang"
RECORD = "images-0123456789ab"
QWEN = ROOT / "recipes/qwen35-0.8b-1xb200/recipe.yaml"
DSV41 = ROOT / "recipes/deepseek-v41-flash-262k-4xb200/recipe.yaml"
LAYOUT = "dsv41-262k"
CHART = ROOT / "helm/confidential-inference"


def fixture_pin() -> dict:
    return CSR.release_pin({"record": RECORD}, FIXTURES)


def fixture_layout() -> dict:
    return CSR.read_layout(RECORD, LAYOUT, FIXTURES)


def fixture_record() -> dict:
    return json.loads((FIXTURES / f"{RECORD}.json").read_text())


def release_images() -> dict[str, str]:
    """Chart image keys of a release: the spec's external images plus the fixture record."""
    pin = CSR.release_pin({"record": RECORD}, FIXTURES)
    images = {key: value for key, value in MAN.read_spec()["images"].items() if "@" in value}
    images["sglangConfidential"] = "ghcr.io/confidential-dot-ai/confidential-inference/sglang-confidential@sha256:" + "1" * 64
    images["gateway"] = "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "2" * 64
    return {**images, **CSR.chart_images(pin)}


class ConfidentialSglangPinTests(unittest.TestCase):
    def test_the_build_refuses_the_placeholder(self):
        spec = MAN.read_spec()
        with self.assertRaisesRegex(MAN.ManifestError, "placeholder"):
            MAN.confidential_sglang({**spec, "confidentialSglang": {"record": CSR.PLACEHOLDER}})

    def test_the_spec_pins_a_record_that_is_in_the_inputs(self):
        record = MAN.read_spec()["confidentialSglang"]["record"]
        self.assertNotEqual(record, CSR.PLACEHOLDER)
        CSR.read_record(record)

    def test_the_pin_is_one_spec_line(self):
        lines = [line for line in (ROOT / "release/spec.yaml").read_text().splitlines()
                 if CSR.SPEC_LINE.fullmatch(line)]
        self.assertEqual(len(lines), 1)

    def test_a_record_pins_both_images_with_their_two_build_digests(self):
        pin = CSR.release_pin({"record": RECORD}, FIXTURES)
        self.assertEqual(pin["sourceCommit"], "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(pin["recordSha256"], CSR.sha256((FIXTURES / f"{RECORD}.json").read_bytes()))
        self.assertEqual(CSR.chart_images(pin), {
            "confidentialSglangEngine": "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "e" * 64,
            "confidentialSglangRouter": "ghcr.io/confidential-dot-ai/confidential-sglang/router@sha256:" + "f" * 64,
        })

    def test_an_invalid_record_is_refused(self):
        def changed(edit):
            record = fixture_record()
            edit(record)
            return record
        cases = {
            "names source commit": (changed(lambda r: r.update(sourceCommit="1" * 40)), RECORD),
            "two build digests": (changed(lambda r: r["images"][0].update(
                builds=["sha256:" + "e" * 64, "sha256:" + "d" * 64])), RECORD),
            "holds exactly": (changed(lambda r: r.update(extra=1)), RECORD),
            "untagged": (changed(lambda r: r["images"][1].update(image="docker.io/library/router")), RECORD),
            "images are exactly": (changed(lambda r: r["images"].pop()), RECORD),
            "run.id": (changed(lambda r: r["run"].update(id="1")), RECORD),
            "run.repository": (changed(lambda r: r["run"].update(repository="someone/else")), RECORD),
            # The archived confidential-sglang-ci, even with a consistent URL and workflow.
            "run.repository is not": (changed(lambda r: r["run"].update(
                repository="confidential-dot-ai/confidential-sglang-ci",
                url="https://github.com/confidential-dot-ai/confidential-sglang-ci/actions/runs/19000000001/attempts/1",
                workflow="confidential-dot-ai/confidential-sglang-ci/.github/workflows/images.yml@refs/heads/main")),
                RECORD),
            "on main": (changed(lambda r: r["run"].update(workflow="x/y/.github/workflows/images.yml@refs/heads/dev")), RECORD),
        }
        for message, (record, name) in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(CSR.RecordError, message):
                CSR.validate_record(record, name)
        with self.assertRaisesRegex(CSR.RecordError, "images-<12 hex>"):
            CSR.validate_name("images-0123")

    def test_the_spec_cannot_pin_the_images_directly(self):
        spec = MAN.read_spec()
        images = {**spec["images"], "confidentialSglangEngine": "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "e" * 64}
        with self.assertRaisesRegex(MAN.ManifestError, "come from confidentialSglang.record"):
            MAN.validate_spec({**spec, "images": images})

    def test_pin_writes_the_record_and_changes_one_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            spec = Path(temporary) / "spec.yaml"
            shutil.copy(ROOT / "release/spec.yaml", spec)
            inputs = Path(temporary) / "inputs"
            data = (FIXTURES / f"{RECORD}.json").read_bytes()
            layout = (FIXTURES / "layouts" / RECORD / f"{LAYOUT}.json").read_bytes()
            CSR.pin(RECORD, spec, inputs, fetch=lambda name, _directory: data,
                    extract=lambda _reference: {LAYOUT: layout})
            old = (ROOT / "release/spec.yaml").read_text().splitlines()
            new = spec.read_text().splitlines()
            changed = [(a, b) for a, b in zip(old, new) if a != b]
            self.assertEqual(len(changed), 1)
            self.assertEqual(changed[0][1], f"  record: {RECORD}")
            self.assertEqual((inputs / f"{RECORD}.json").read_bytes(), data)
            # The engine image's layouts, bound by SHA-256 in the manifest.
            self.assertEqual((inputs / "layouts" / RECORD / f"{LAYOUT}.json").read_bytes(), layout)
            self.assertEqual(CSR.release_pin({"record": RECORD}, inputs)["layouts"], {LAYOUT: CSR.sha256(layout)})
            with self.assertRaisesRegex(CSR.RecordError, "names source commit"):
                CSR.pin("images-111111111111", spec, inputs, fetch=lambda name, _directory: data)
            # A layout built from another commit than the record's is refused.
            other = layout.replace(b"0123456789abcdef0123456789abcdef01234567", b"1" * 40)
            with self.assertRaisesRegex(CSR.RecordError, "not the record's source commit"):
                CSR.pin(RECORD, spec, inputs, fetch=lambda name, _directory: data,
                        extract=lambda _reference: {LAYOUT: other})

    def test_render_reads_a_confidential_sglang_image_config_from_the_registry(self):
        render = load("render_allowlist_recipes", "scripts/render-allowlist.py")
        image = "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "e" * 64
        config = {"env": ["HOME=/tmp"], "entrypoint": [], "cmd": []}
        with mock.patch.dict(render.ALLOWLIST_GENERATOR, {"image_config": lambda _image: config}):
            self.assertEqual(render.image_configs([image])[image], config)
        with self.assertRaisesRegex(render.ManifestError, "no record"):
            render.image_configs(["docker.io/library/other@sha256:" + "e" * 64])


class RecipeTests(unittest.TestCase):
    def recipe(self) -> dict:
        return yaml.safe_load(QWEN.read_text())

    def refused(self, edit, message: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "qwen35-0.8b-1xb200"
            shutil.copytree(QWEN.parent, directory)
            recipe = self.recipe()
            edit(recipe, directory)
            (directory / "recipe.yaml").write_text(yaml.safe_dump(recipe))
            with self.assertRaisesRegex(RV.RecipeError, message):
                RV.values(RV.load(directory / "recipe.yaml"), release_images())

    def test_the_qwen_recipe_renders_its_chart_values(self):
        values = RV.values(RV.load(QWEN), release_images())
        inference = values["inference"]
        self.assertEqual({key: inference[key] for key in (
            "mode", "layout", "engineImage", "gpusPerReplica", "gpuArchitectures", "attestedGpuCount",
            "contextLength", "toolCallParser", "reasoningParser", "moeRunnerBackend", "workerExtraArgs",
            "flashinferDisableJit")}, {
            "mode": "model", "layout": "worker", "engineImage": "confidentialSglangEngine", "gpusPerReplica": 1,
            "gpuArchitectures": ["BLACKWELL"], "attestedGpuCount": 1, "contextLength": 262144,
            "toolCallParser": "qwen3_coder", "reasoningParser": "qwen3", "moeRunnerBackend": "auto",
            "workerExtraArgs": [], "flashinferDisableJit": True})
        self.assertEqual(inference["model"]["name"], "Qwen/Qwen3.5-0.8B")
        self.assertEqual(inference["model"]["revision"], "2fc06364715b967f1860aea9cf38778875588b17")
        self.assertEqual(inference["model"]["mountVerification"]["expectedFileList"], [
            {"path": ".model-lock-local-manifest.json",
             "sha256": "625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"},
            {"path": "config.json", "sha256": "b90b86f35c8e6925ef74ee04d0e758f0a845c83a42089ad82bbaa948de9b4204"},
            {"path": "tokenizer_config.json",
             "sha256": "49e2b6e395f959f077f1e992b338919c0d4a9732fc6e613995e06557f843500c"},
        ])
        self.assertEqual(inference["model"]["download"]["manifest"], (QWEN.parent / "model-manifest.json").read_text())
        self.assertEqual(values["router"], {"image": "confidentialSglangRouter"})
        # No environment value: no replica count, model server, node, or router API server.
        self.assertNotIn("replicas", inference)
        self.assertNotIn("hosts", inference["model"]["download"])
        self.assertNotIn("enabled", inference["model"]["download"])
        self.assertNotIn("scheduling", values)
        # The qwen recipe lists no unsupported parameter: the gateway settings stay as they were.
        self.assertNotIn("gateway", values)

    def test_the_values_render_the_worker_and_router_of_the_recipe(self):
        if shutil.which("helm") is None:
            self.skipTest("helm is not on PATH")
        images = release_images()
        with tempfile.TemporaryDirectory() as temporary:
            values = Path(temporary) / "recipe-values.yaml"
            values.write_text(RV.dump(RV.values(RV.load(QWEN), images)))
            release = Path(temporary) / "release-values.yaml"
            release.write_text(yaml.safe_dump({"images": images}))
            result = subprocess.run(["helm", "template", "recipe", str(CHART), "--values", str(values),
                                     "--values", str(release)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        documents = [item for item in yaml.safe_load_all(result.stdout) if item]
        workers = [item for item in documents if item["kind"] == "StatefulSet"
                   and item["metadata"]["name"].startswith("inference-worker")]
        self.assertTrue(workers)
        container = workers[0]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["image"], images["confidentialSglangEngine"])
        args = container["args"]
        server = args[args.index("sglang.launch_server") + 1:]
        # confidential-sglang recipes/qwen35-0.8b/container/serve.sh, plus the
        # chart's cold-path warmup, the recipe's context length and the chart's model path.
        self.assertEqual([arg for arg in server if not arg.startswith("--model-path=")], [
            "--served-model-name=Qwen/Qwen3.5-0.8B", "--revision=2fc06364715b967f1860aea9cf38778875588b17",
            "--tool-call-parser=qwen3_coder", "--reasoning-parser=qwen3", "--tp=1", "--moe-runner-backend=auto",
            "--warmups=confidential_cold_path", "--context-length=262144", "--mem-fraction-static=0.90", "--chunked-prefill-size=4096",
            "--swa-full-tokens-ratio=0.1", "--enable-metrics", "--enable-cache-report", "--host=0.0.0.0",
            "--port=30000"])
        env = {item["name"]: item.get("value") for item in container["env"]}
        self.assertEqual(env["FLASHINFER_DISABLE_JIT"], "1")
        router = next(item for item in documents if item["kind"] == "Deployment"
                      and item["metadata"]["name"] == "sglang-router")
        router_container = router["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(router_container["image"], images["confidentialSglangRouter"])
        self.assertIn("--policy=cache_aware", router_container["args"])

    def test_an_invalid_recipe_is_refused(self):
        def set_path(*path, value):
            def edit(recipe, _directory):
                target = recipe
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return edit
        cases = [
            (set_path("worker", "extraArgs", value=["--mem-fraction-static=0.5"]), "which the chart sets"),
            (set_path("worker", "extraArgs", value=["rm -rf"]), "extraArgs item is invalid"),
            (set_path("routing", "policy", value="round_robin"), "routing.policy"),
            (set_path("routing", "kind", value="none"), "routing.kind"),
            (set_path("engine", "image", value="gateway"), "engine.image"),
            (set_path("model", "manifestSha256", value="0" * 64), "differs from model.manifestSha256"),
            (set_path("model", "revision", value="1" * 40), "another revision"),
            (set_path("model", "checkFiles", value=["missing.json"]), "no SHA-256 for missing.json"),
            (set_path("replica", "gpuArchitectures", value=["AMPERE"]), "gpuArchitectures"),
            (set_path("schema", value="confidential.ai/recipe/v1"), "recipe schema"),
            (set_path("replica", "workers", value=2), "replica.workers was removed"),
            (set_path("replica", "layout", value="pd"), "replica.layout"),
            (set_path("replica", "plan", value=LAYOUT), "unknown fields"),
            (set_path("name", value="other"), "differs from its directory"),
            (set_path("extra", value=1), "unknown fields"),
            (set_path("behavior", "apis", "embeddings", value={}), "behavior.apis keys"),
            (set_path("behavior", "warmup", value=[]), "unknown fields"),
            (set_path("behavior", "unsupportedParameters", value=[]), "list of 1 to 64"),
            (set_path("behavior", "unsupportedParameters", value={"n": [1]}), "list of 1 to 64"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": "N"}]), r"\[0\]\.name is invalid"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": True}]), r"\[0\]\.name is invalid"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": "n", "when": 1}]), "unknown fields"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": "n", "allowed": [None]}]),
             "booleans, numbers or strings"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": "n", "allowed": [[1]]}]),
             "booleans, numbers or strings"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": "n", "allowed": []}]),
             "booleans, numbers or strings"),
            (set_path("behavior", "unsupportedParameters", value=[{"name": "n"}, {"name": "n"}]),
             "names a parameter twice"),
            (set_path("worker", "extraArgs", value=["--warmups=other"]), "which the chart sets"),
            (set_path("worker", "extraArgs", value=["--warmup=other"]), "sets --warmups, which the chart sets"),
        ]
        for edit, message in cases:
            with self.subTest(message=message):
                self.refused(edit, message)

    def test_a_recipe_directory_holds_only_its_files(self):
        self.refused(lambda _recipe, directory: (directory / "notes.txt").write_text("x"), "holds exactly")

    def test_a_release_without_the_image_refuses_the_recipe(self):
        images = release_images()
        images.pop("confidentialSglangRouter")
        with self.assertRaisesRegex(RV.RecipeError, "routing.image"):
            RV.values(RV.load(QWEN), images)

    def test_the_release_ships_every_recipe(self):
        with mock.patch.object(CSR, "INPUTS", FIXTURES):
            data, binding = MAN.recipes_file(release_images(), fixture_pin())
        self.assertEqual(binding["file"], "recipes.json")
        self.assertEqual(binding["sha256"], MAN.sha256(data))
        shipped = json.loads(data)
        self.assertEqual(shipped["schema"], "confidential.ai/recipes/v1")
        names = sorted(path.name for path in (ROOT / "recipes").iterdir() if path.is_dir())
        self.assertEqual(sorted(shipped["recipes"]), names)
        self.assertEqual(shipped["recipes"]["qwen35-0.8b-1xb200"]["recipe.yaml"], QWEN.read_text())
        self.assertEqual(binding["recipes"]["qwen35-0.8b-1xb200"], MAN.sha256(QWEN.read_bytes()))
        # The same tree gives the same bytes.
        with mock.patch.object(CSR, "INPUTS", FIXTURES):
            self.assertEqual(MAN.recipes_file(release_images(), fixture_pin())[0], data)
        # A pin without the pair recipe's layout fails the release build.
        pin = {key: value for key, value in fixture_pin().items() if key != "layouts"}
        with mock.patch.object(CSR, "INPUTS", FIXTURES), self.assertRaisesRegex(MAN.ManifestError, "binds no layout"):
            MAN.recipes_file(release_images(), pin)
        self.assertEqual(shipped["recipes"]["deepseek-v41-flash-262k-4xb200"]["recipe.yaml"], DSV41.read_text())


class PairRecipeTests(unittest.TestCase):
    """The DeepSeek-V4.1 pair recipe: one replica is the engine image's launch plan dsv41-262k."""

    def values(self, recipe: dict | None = None, layout: dict | None = None) -> dict:
        loaded = RV.load(DSV41)
        if recipe is not None:
            loaded = {**recipe, "_modelManifest": loaded["_modelManifest"]}
        return RV.values(loaded, release_images(), layout or fixture_layout())

    def test_the_recipe_names_the_layout_and_copies_no_flag(self):
        recipe = yaml.safe_load(DSV41.read_text())
        self.assertEqual(recipe["replica"], {"layout": "pair", "plan": LAYOUT, "gpus": 4,
                                             "gpuArchitectures": ["BLACKWELL"], "attestedGpuCount": 4})
        self.assertNotIn("extraArgs", recipe["worker"])
        self.assertEqual(recipe["model"]["repository"], "deepseek-ai/DeepSeek-V4.1-Flash-1017")
        self.assertEqual(recipe["model"]["revision"], "1bae0e1088993b9b82de08f59de5be5a34e42170")
        self.assertEqual(recipe["model"]["contextLength"], 262144)
        self.assertEqual(sorted(recipe["behavior"]["apis"]), ["chat", "completions", "messages", "responses"])

    def test_the_gateway_refuses_the_parameters_the_pair_does_not_support(self):
        # n > 1 holds a decode slot until it times out; the others the pair refuses
        # only after it tokenizes the prompt.
        self.assertEqual(self.values()["gateway"], {"unsupportedParameters": [
            {"name": "n", "allowed": [1]},
            {"name": "best_of", "allowed": [1]},
            {"name": "min_p", "allowed": [0]},
            {"name": "logprobs", "allowed": [False]},
            {"name": "top_logprobs", "allowed": [0]},
        ]})
        # Helm reads YAML 1.1: the values file must keep n a string.
        self.assertIn('- name: "n"', RV.dump(self.values()))

    def test_the_pair_values_come_from_the_layout(self):
        inference = self.values()["inference"]
        self.assertEqual((inference["layout"], inference["gpusPerReplica"], inference["attestedGpuCount"]),
                         ("pair", 4, 4))
        self.assertNotIn("replicas", inference)
        pair = inference["pair"]
        layout = fixture_layout()
        self.assertEqual((pair["plan"], pair["layoutSha256"]), (LAYOUT, layout["_sha256"]))
        prefill, decode = pair["prefill"], pair["decode"]
        self.assertEqual((prefill["gpus"], prefill["port"], prefill["bootstrapPort"]), (2, 8041, 8999))
        self.assertEqual((decode["gpus"], decode["port"], decode["maxRunningRequests"]), (2, 8042, 128))
        for role, worker in (("prefill", prefill), ("decode", decode)):
            plan = next(item for item in layout["plan"]["workers"] if item["name"] == role)["command"][3:]
            # The plan's flags in order, less the four the chart sets.
            kept = RV.join_flags([item for item in RV.split_flags(plan, role) if item[0] not in RV.PAIR_CHART_FLAGS])
            self.assertEqual(worker["args"], kept)
            for flag in ("--model-path", "--served-model-name", "--host", "--warmups"):
                self.assertNotIn(flag, worker["args"])
            self.assertIn("--speculative-algorithm", worker["args"])
            self.assertNotIn("CUDA_VISIBLE_DEVICES", worker["env"])
        self.assertEqual((pair["router"]["port"], pair["router"]["metricsPort"]), (8040, 29001))
        self.assertEqual(pair["router"]["args"], ["--reject-video", "--disable-circuit-breaker", "--retry-max-retries",
                                                  "2", "--max-concurrent-requests", "192", "--queue-size", "256",
                                                  "--queue-timeout-secs", "30"])

    def test_the_recipe_must_agree_with_its_layout(self):
        def changed(edit):
            recipe = yaml.safe_load(DSV41.read_text())
            edit(recipe)
            return recipe
        cases = {
            "--tool-call-parser": changed(lambda r: r["worker"].update(toolCallParser="deepseekv4")),
            "--context-length": changed(lambda r: r["model"].update(contextLength=131072)),
            "--speculative-algorithm": changed(lambda r: r["worker"].update(speculativeAlgorithm="")),
            "uses 4 GPUs": changed(lambda r: r["replica"].update(gpus=8, attestedGpuCount=8)),
        }
        for message, recipe in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(RV.RecipeError, message):
                self.values(recipe)

    def test_a_layout_the_chart_cannot_run_is_refused(self):
        def changed(edit):
            layout = copy.deepcopy(fixture_layout())
            edit(layout["plan"])
            return layout

        def set_flag(role, flag, value):
            def edit(plan):
                command = plan["workers"][role]["command"]
                command[command.index(flag) + 1] = value
            return edit
        cases = {
            "runs warmups other": changed(lambda plan: plan["workers"][0]["command"].extend(["--warmups", "other"])),
            "sglang-pair gives": changed(lambda plan: plan["workers"][1]["env"].update(CUDA_VISIBLE_DEVICES="0,1")),
            "one prefill and one decode": changed(lambda plan: plan["workers"].reverse()),
            "--disaggregation-mode is not decode": changed(set_flag(1, "--disaggregation-mode", "prefill")),
            "sglang-pair control": changed(lambda plan: plan["workers"][0]["env"].update(SGLANG_PAIR_ROLE="x")),
            "which the pair refuses": changed(lambda plan: plan["workers"][1]["command"].append("--log-requests")),
            "--prefill is not": changed(lambda plan: plan["router"]["command"].__setitem__(
                plan["router"]["command"].index("8999"), "9000")),
        }
        for message, layout in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(RV.RecipeError, message):
                self.values(layout=layout)

    def test_with_a_release_the_layout_must_be_the_bound_one(self):
        recipe = RV.load(DSV41)
        pin = fixture_pin()
        with mock.patch.object(CSR, "INPUTS", FIXTURES):
            RV.recipe_values(recipe, release_images(), {"confidentialSglang": pin})
            other = {**pin, "layouts": {LAYOUT: "sha256:" + "0" * 64}}
            with self.assertRaisesRegex(RV.RecipeError, "differs from the release"):
                RV.recipe_values(recipe, release_images(), {"confidentialSglang": other})
            with self.assertRaisesRegex(RV.RecipeError, "binds no layout"):
                RV.recipe_values(recipe, release_images(), {"confidentialSglang": {**pin, "layouts": {}}})

    def test_the_pinned_engine_image_has_the_layout(self):
        """release/spec.yaml's record: its committed layouts include dsv41-262k, built from its commit."""
        record = MAN.read_spec()["confidentialSglang"]["record"]
        layout = CSR.read_layout(record, LAYOUT)
        self.assertEqual(layout["revision"], CSR.read_record(record)[1]["sourceCommit"])
        self.assertIn(LAYOUT, CSR.release_pin({"record": record})["layouts"])
        RV.recipe_values(RV.load(DSV41), RV.release_image_keys(None))


class LayoutImageTests(unittest.TestCase):
    """confidential_sglang_release.image_layouts reads the layouts from the image layers, top first."""

    @staticmethod
    def layer(files: dict[str, bytes]) -> bytes:
        import io
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def crane(self, layers: list[bytes]):
        reference = "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "e" * 64
        digests = [f"sha256:{index:064x}" for index in range(len(layers))]
        manifest = {"layers": [{"digest": digest, "size": len(data), "mediaType":
                                "application/vnd.oci.image.layer.v1.tar+gzip"} for digest, data in zip(digests, layers)]}
        calls = []

        def run(command, **_kwargs):
            calls.append(command[1])
            if command[1] == "manifest":
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(manifest).encode(), stderr=b"")
            digest = command[2].split("@", 1)[1]
            return subprocess.CompletedProcess(command, 0, stdout=layers[digests.index(digest)], stderr=b"")
        return reference, run, calls

    def test_the_layers_merge_and_the_upper_file_wins(self):
        old = self.layer({"opt/sglang/layouts/a.json": b"old", "opt/sglang/layouts/c.json": b"c"})
        new = self.layer({"opt/sglang/layouts/a.json": b"new", "opt/sglang/layouts/b.json": b"b"})
        top = self.layer({"opt/sglang/SOURCE_RECORD.json": b"{}"})
        reference, run, calls = self.crane([old, new, top])
        # c.json of the lower layer stays: an upper layer that replaces a.json hides nothing else.
        self.assertEqual(CSR.image_layouts(reference, run), {"a": b"new", "b": b"b", "c": b"c"})
        self.assertEqual(calls, ["manifest", "blob", "blob", "blob"])

    def test_the_reader_stops_at_the_first_large_layer(self):
        below = self.layer({"opt/sglang/layouts/hidden.json": b"x"})
        large = self.layer({"usr/lib/big": bytes(range(256)) * 64 + __import__("os").urandom(8192)})
        layouts = self.layer({"opt/sglang/layouts/a.json": b"a"})
        reference, run, calls = self.crane([below, large, layouts])
        with mock.patch.object(CSR, "MAX_LAYER_BYTES", len(layouts) + 1):
            self.assertGreater(len(large), CSR.MAX_LAYER_BYTES)
            self.assertEqual(CSR.image_layouts(reference, run), {"a": b"a"})
            self.assertEqual(calls, ["manifest", "blob"])
            reference, run, _ = self.crane([layouts, large])
            with self.assertRaisesRegex(CSR.RecordError, "has no opt/sglang/layouts/"):
                CSR.image_layouts(reference, run)

    def test_a_removed_layout_or_no_layout_is_refused(self):
        base = self.layer({"opt/sglang/layouts/a.json": b"a"})
        removed = self.layer({"opt/sglang/layouts/.wh.a.json": b""})
        reference, run, _ = self.crane([base, removed])
        with self.assertRaisesRegex(CSR.RecordError, "removes opt/sglang/layouts/a.json"):
            CSR.image_layouts(reference, run)
        reference, run, _ = self.crane([self.layer({"usr/bin/x": b"x"})])
        with self.assertRaisesRegex(CSR.RecordError, "has no opt/sglang/layouts/"):
            CSR.image_layouts(reference, run)
        with self.assertRaisesRegex(CSR.RecordError, "not pinned by digest"):
            CSR.image_layouts("ghcr.io/x/engine:latest", run)

    def test_check_image_compares_the_committed_layouts_with_the_image(self):
        committed = (FIXTURES / "layouts" / RECORD / f"{LAYOUT}.json").read_bytes()
        CSR.check_image(RECORD, FIXTURES, extract=lambda _reference: {LAYOUT: committed})
        with self.assertRaisesRegex(CSR.RecordError, "differ from the layouts of its engine image"):
            CSR.check_image(RECORD, FIXTURES, extract=lambda _reference: {LAYOUT: committed + b" "})


if __name__ == "__main__":
    unittest.main()
