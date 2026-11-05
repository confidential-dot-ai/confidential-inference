#!/usr/bin/env python3
"""Run legacy worker commands through the application event boundary.

Native and dependency output is discarded. Only records that pass the shared
contract can reach local logs or the OTLP queue. Signals reach the child.
"""
import json
import os
import resource
import signal
import subprocess
import sys
import threading

from safe_events import envelope, validate
from private_log_sink import LogSink, NonblockingStdout, consume_child_output


def main(command=None):
    command = sys.argv[1:] if command is None else command
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    writer = NonblockingStdout()
    sink = LogSink.from_environment()

    def emit(event, **fields):
        record = envelope({'event': event, 'role': 'worker', **fields})
        if record is None:
            return
        try:
            writer.write(record)
        except Exception:
            pass
        if sink:
            try:
                sink.submit(record)
            except Exception:
                pass

    shutdown_seconds = int(os.environ.get("CI_PROCESS_SHUTDOWN_SECONDS", "900"))
    if not 1 <= shutdown_seconds <= 86400:
        return 2
    child = None
    timer = None
    try:
        blocked = {'--log-requests', '--log-requests-target', '--crash-dump-folder',
                   '--debug-tensor-dump-output-folder', '--log-dir'}
        for arg in command:
            flag = arg.split('=', 1)[0].replace('_', '-')
            if flag.startswith('--') and any(value.startswith(flag) for value in blocked):
                emit('worker_config_rejected')
                return 2
        environment = os.environ.copy()
        for name in tuple(environment):
            if any(part in name for part in ('DUMP', 'TRACE', 'PROFILER', 'LOG_REQUEST', 'DEBUG_INFO', 'REPRO', 'SAVE_ARGS', 'LOGGING_CONFIG')) or name in {'PYTHONFAULTHANDLER', 'TORCH_LOGS', 'TORCH_LOGS_OUT'}:
                del environment[name]
        child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)

        def kill():
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        def forward(signum, _frame):
            nonlocal timer
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass
            if timer is None:
                timer = threading.Timer(shutdown_seconds, kill)
                timer.daemon = True
                timer.start()

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
            signal.signal(sig, forward)
        emit('worker_process_started')
        def accept(raw):
            record = validate(json.loads(raw))
            if record is None or record['component'] != 'worker':
                return False
            try:
                writer.write(record)
            except Exception:
                pass
            if sink:
                try:
                    sink.submit(record)
                except Exception:
                    pass
            return True
        code, rejected = consume_child_output(child, accept)
        if rejected:
            emit('worker_process_output_dropped', count=rejected)
        emit('worker_process_exit', code=code)
        return code if code >= 0 else 128 - code
    except Exception:
        emit('worker_process_failed')
        return 1
    finally:
        if timer:
            timer.cancel()
        if child:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if sink:
            result = sink.close(timeout=1)
            sink = None
            if result['dropped'] or result['pending'] or result['failures']:
                emit('worker_diagnostic_delivery_failed', **result)


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        result = 1  # No traceback, argument, environment or exception fallback.
    raise SystemExit(result)
