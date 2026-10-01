from __future__ import annotations

import importlib.util
import sys
import unittest
import tempfile
import threading
import http.client
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "images" / "sglang" / "gpu_metrics.py"
SPEC = importlib.util.spec_from_file_location("gpu_metrics", SCRIPT)
assert SPEC and SPEC.loader
gpu_metrics = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gpu_metrics
SPEC.loader.exec_module(gpu_metrics)


class GpuMetricsTests(unittest.TestCase):
    def test_parses_bounded_nvidia_samples(self) -> None:
        samples = gpu_metrics.parse_nvidia_smi(
            "0, 25, 1024, 2048, 41, 2, 0\n"
            "1, 0, 512, 2048, 39, N/A, N/A\n"
        )
        self.assertEqual([0, 1], [sample.index for sample in samples])
        self.assertEqual(0.25, samples[0].utilization_ratio)
        self.assertEqual(1024 * 1024 * 1024, samples[0].memory_used_bytes)
        self.assertEqual(2, samples[0].corrected_ecc_errors)
        self.assertIsNone(samples[1].uncorrected_ecc_errors)

    def test_renders_only_safe_worker_and_gpu_labels(self) -> None:
        sample = gpu_metrics.parse_nvidia_smi("0, 50, 1024, 2048, 40, 1, 0\n")
        text = gpu_metrics.render_metrics("sglang-0", sample).decode()
        self.assertIn('worker="sglang-0",gpu="0"', text)
        self.assertIn("confidential_inference_gpu_utilization_ratio", text)
        self.assertIn("confidential_inference_gpu_memory_used_bytes", text)
        self.assertIn("confidential_inference_gpu_temperature_celsius", text)
        self.assertIn("confidential_inference_gpu_ecc_uncorrected_errors_total", text)
        self.assertNotIn("uuid", text.lower())

    def test_failure_response_has_no_stale_gpu_values(self) -> None:
        text = gpu_metrics.render_metrics("sglang-1", [], success=False).decode()
        self.assertIn(
            'confidential_inference_gpu_metrics_scrape_success{worker="sglang-1"} 0',
            text,
        )
        self.assertNotIn('gpu="', text)

    def test_rejects_invalid_samples(self) -> None:
        invalid = (
            "",
            "0, 101, 1, 2, 40, 0, 0\n",
            "0, 1, 3, 2, 40, 0, 0\n",
            "0, 1, 1, 2, 40, 0\n",
            "0, 1, 1, 2, 40, 0, 0\n0, 1, 1, 2, 40, 0, 0\n",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(gpu_metrics.GpuMetricsError):
                    gpu_metrics.parse_nvidia_smi(value)

    def test_rejects_unsafe_worker_label(self) -> None:
        with self.assertRaises(gpu_metrics.GpuMetricsError):
            gpu_metrics.render_metrics('worker"} 1\nsecret{', [])

    def resource_fixture(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        membership = root / "membership"
        membership.write_text("0::/\n")
        (root / "cpu.stat").write_text("usage_usec 3250000\nuser_usec 3000000\nsystem_usec 250000\n")
        (root / "memory.current").write_text("45000\n")
        (root / "memory.stat").write_text("anon 30000\ninactive_file 11000\n")
        return root, membership

    def test_reads_container_counters_and_subtracts_inactive_file_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, membership = self.resource_fixture(directory)
            sample = gpu_metrics.query_container_resources(root, membership)
            self.assertEqual(3250000, sample.cpu_usage_usec)
            self.assertEqual(34000, sample.memory_working_set_bytes)
            text = gpu_metrics.render_metrics("sglang-0", [], success=False, resources=sample).decode()
            self.assertIn('confidential_inference_container_cpu_seconds_total{worker="sglang-0"} 3.250000', text)
            self.assertIn('confidential_inference_container_memory_working_set_bytes{worker="sglang-0"} 34000', text)

    def test_refuses_non_root_membership_and_parent_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, membership = self.resource_fixture(directory)
            for value in ("0::/host/another-container\n", "0::/../sibling\n", "1:cpu:/\n"):
                membership.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    gpu_metrics.query_container_resources(root, membership)

    def test_reclaim_race_does_not_emit_negative_memory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, membership = self.resource_fixture(directory)
            (root / "memory.current").write_text("10000\n")
            self.assertEqual(0, gpu_metrics.query_container_resources(root, membership).memory_working_set_bytes)

    def test_invalid_or_missing_resource_counters_are_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, membership = self.resource_fixture(directory)
            for text in ("usage_usec -1\n", "usage_usec 1\nusage_usec 2\n", "user_usec 100\n"):
                (root / "cpu.stat").write_text(text)
                with self.subTest(text=text), self.assertRaises((ValueError, KeyError)):
                    gpu_metrics.query_container_resources(root, membership)
        text = gpu_metrics.render_metrics("sglang-0", []).decode()
        self.assertIn('confidential_inference_container_metrics_scrape_success{worker="sglang-0"} 0', text)
        self.assertNotIn("confidential_inference_container_cpu_seconds_total", text)
        self.assertNotIn("confidential_inference_container_memory_working_set_bytes", text)

    def test_http_resource_metrics_survive_an_independent_gpu_query_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, membership = self.resource_fixture(directory)
            sample = gpu_metrics.query_container_resources(root, membership)
        server = gpu_metrics.http.server.ThreadingHTTPServer(("127.0.0.1", 0), gpu_metrics.handler("sglang-1"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with patch.object(gpu_metrics, "query_nvidia_smi", side_effect=OSError()), patch.object(
                gpu_metrics, "query_container_resources", return_value=sample):
            thread.start()
            connection = http.client.HTTPConnection(*server.server_address, timeout=5)
            try:
                connection.request("GET", "/metrics")
                response = connection.getresponse()
                text = response.read().decode()
                self.assertEqual(200, response.status)
                self.assertIn('confidential_inference_gpu_metrics_scrape_success{worker="sglang-1"} 0', text)
                self.assertIn('confidential_inference_container_metrics_scrape_success{worker="sglang-1"} 1', text)
                self.assertIn("confidential_inference_container_cpu_seconds_total", text)
                self.assertNotIn('gpu="', text)
            finally:
                connection.close()
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()


if __name__ == "__main__":
    unittest.main()
