from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
