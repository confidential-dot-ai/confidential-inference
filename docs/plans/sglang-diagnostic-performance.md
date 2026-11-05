# SGLang diagnostic performance follow-up

Status: Open. The operator accepted the measured gap on 2026-11-05 and asked
for release to proceed on B300 Node 3. Keep the recovery and privacy controls.
The operator will make the separate DNS change. This plan does not permit it.

## Measurements

The saved production reference uses eight B200 GPUs and release v0.16.2.
The test uses eight B300 GPUs and the changed paired workers. The workload
runs for ten minutes: three minutes at concurrency 8, three at 16, and four
at 32. Both use the same request generators and output limits. The reference
uses the full HTTPS gateway. The test uses the internal HTTP router.
These differences limit claims about the cause of the gap.

| Measure | Concurrency 8: production / test | Concurrency 16 | Concurrency 32 |
| --- | --- | --- | --- |
| Output tokens per second | 512.09 / 401.23 | 765.38 / 741.22 | 1193.05 / 1190.77 |
| Completion seconds, p95 | 23.51 / 26.39 | 31.93 / 34.46 | 44.41 / 46.71 |
| Stream HTTP first-byte seconds, p95 | 1.125 / 1.252 | 1.278 / 1.259 | 1.403 / 1.367 |

All 2,097 test requests returned HTTP 200 and passed response checks. All
requests drained. There were no health failures. HTTP first byte does not
measure the first generated token. An earlier comparison on the same B300
hardware over TCP also found about 15–17% higher single-request latency with
the changed worker. Preserve both results; neither isolates a cause.

## Hypotheses

Progress checks wrap scheduler stages on the scheduler thread. They read
clocks and update state on each stage. CUDA completion markers and queries
run at most every 100 ms. Progress files are written about twice per second,
and immediately when batch execution starts after a non-busy state. File
writes are synchronous. This work can add a fixed cost to each scheduler step.
Larger batches can share that cost across more requests.

The 256-entry PyTorch NCCL recorder also runs during healthy communication.
GPU timing and C++ stack capture are disabled. Its remaining cost is not yet
measured separately. Diagnostic export is mainly triggered by failure and is
less likely to explain normal step latency. Cache state, warm-up, batching,
routing, CPU allocation and GPU settings can also affect the comparison.
These are hypotheses, not findings.

## Work

1. Fix hardware, transport, routing, workload and explicit warm-up conditions.
2. Compare the original and changed workers on the same B300 pair.
3. In test images only, measure progress checks and NCCL recording separately.
   Change one feature at a time. Restore checks after each short test.
4. Measure scheduler CPU time, step latency, completion latency and throughput
   at low and high concurrency. Compare request types and output lengths.
5. Reduce measured overhead. Consider less work on the scheduler thread and
   a cheaper progress publication path. Preserve final-batch GPU tracking,
   stale-rank detection, bounded shutdown and customer-safe diagnostics.
6. Repeat privacy, crash, hang, TCP and NVLink checks after a code change.
   Use the approved image and signed release pipeline for deployment.

Do not remove recovery or diagnostic coverage based only on a hypothesis.
Do not claim the original GPU kernel stall is fixed. The measured performance
gap is accepted for this release; further measurements must still be recorded.
