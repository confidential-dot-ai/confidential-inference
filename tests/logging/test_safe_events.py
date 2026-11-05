"""Check all current event schemas, queue validation, and release inputs."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from corpus import ROOT, SECRET, negatives, positives
from safe_events import CONTRACT, validate, envelope
from private_log_sink import LogSink, NonblockingStdout


class ContractTests(unittest.TestCase):
    def test_all_existing_event_types_accept_only_their_approved_fields(self):
        self.assertGreater(len(positives()), 50)
        for record in positives():
            self.assertIsNotNone(record)
            self.assertEqual(record, validate(record))
        for record in negatives():
            self.assertIsNone(validate(record), repr(record)[:150])

    def test_contract_copies_are_identical(self):
        subprocess.run([sys.executable, str(ROOT / 'scripts/sync-safe-events.py'), '--check'], check=True)

    def test_rejected_records_never_enter_the_queue_or_stdout(self):
        sink = LogSink('http://127.0.0.1:1/v1/logs', 'sglang-router', timeout=.01)
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        try:
            writer = NonblockingStdout(write_fd)
            for record in negatives():
                sink.submit(record)
                self.assertFalse(writer.write(record))
            result = sink.close()
            self.assertEqual(len(negatives()), result['dropped'])
            self.assertEqual(0, result['exported'])
            self.assertEqual(0, sink.queue.qsize())
            with self.assertRaises(BlockingIOError):
                os.read(read_fd, 4096)
        finally:
            os.close(read_fd)
            os.close(write_fd)
            sink.close()

    def test_router_sink_exception_does_not_format_its_arguments(self):
        spec = importlib.util.spec_from_file_location('router_failure_fixture', ROOT / 'images/sglang-router/private_router.py')
        router = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(router)
        class Broken:
            def write(self, record):
                raise ValueError(SECRET)
        router.LOG_STDOUT = Broken()
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            router.emit('router_failed', role='router')
        self.assertEqual('', output.getvalue() + errors.getvalue())

    def test_no_gateway_site_can_use_the_old_tracing_writer(self):
        for path in (ROOT / 'services/gateway/src').glob('*.rs'):
            text = path.read_text().split('#[cfg(test)]')[0]
            if path.name != 'safe_logging.rs':
                self.assertNotRegex(text, r'tracing::(?:info|warn|error|debug|trace)!', str(path))

class BuildInputTests(unittest.TestCase):
    def test_shared_contract_changes_rebuild_both_python_consumers(self):
        import runpy
        select = runpy.run_path(str(ROOT / 'scripts/affected-release-images.py'))['affected_images']
        for name in ['private_log_sink.py','safe_events.py','safe_events.json']:
            images = {image.image for image in select(['images/sglang-router/' + name])}
            self.assertTrue({'sglang','sglang-router'} <= images, name)
        self.assertIn('sglang',{image.image for image in select(['images/sglang-router/private_process.py'])})


if __name__ == '__main__':
    unittest.main()
