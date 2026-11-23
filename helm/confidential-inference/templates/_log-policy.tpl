{{- /*
The log policy: the only records that leave the cluster. The node log agent
(templates/node-log-agent.yaml) applies it to every container's output, and
the telemetry collector (templates/telemetry-collector.yaml) applies it again
to what the agents send. docs/telemetry-egress.md explains it.

Each source is one container kind, told apart by namespace, pod and
container name from the log file path (no Kubernetes API access):

- gateway: the gateway's JSON lines. Only the `message` leaves, and only when
  it is one of gatewayMessages, or the audit record (auditRecord), which
  leaves as its own fields. services/gateway/tests/log_privacy.rs fails when
  a gateway message is not on this list.
- sglang-router, inference-worker, inference-pair: JSON events of fixed names. Only the listed
  fields leave, each checked: a string field against its pattern, an
  integer field as a number. images/sglang-router/README.md and
  images/sglang-confidential/README.md give the events.
- text sources (c8s, telemetry-collector, node-log-agent): the level and the
  message of a JSON or slog text line, with Bearer tokens, addresses and user
  agents replaced and the message cut to 256 characters. These components
  never read request content.

Every other record, and every other field, is dropped and counted
(node_log_agent.records{kept="false"}).
*/ -}}
{{- define "confidential-inference.logPolicy" -}}
gatewayMessages:
  - "gateway configuration validated"
  - "no admin API key file; admin requests need the v1 signature"
  - "the metrics listener stopped"
  - "the gateway is ready"
  - "the gateway started endpoint drain"
  - "the gateway started graceful shutdown"
  - "the gateway panicked; the panic message is not logged"
  - "no routing key secret: the router routes requests at random"
  - "refused the pulled key snapshot"
  - "the key snapshot pull failed"
  - "applied a key registry snapshot"
  - "refused a key registry snapshot: the pepper does not match"
  - "usage model identity did not match its approved binding"
  - "the usage queue is full; dropped the oldest event"
  - "the admin refused a usage event; dropped it"
  - "usage delivery delayed"
  - "usage events were not delivered before shutdown"
auditRecord: '^[{]"event":"gateway_request_completed","key_ref":("kp_[0-9a-f]{24}"|null),"request_id":"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}","route":"/v1/(models|chat/completions|completions|responses)","status":[1-5][0-9][0-9][}]$'
auditFields:
  request_id: {string: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'}
  route: {string: '^/v1/(models|chat/completions|completions|responses)$'}
  status: {int: true}
  key_ref: {string: '^kp_[0-9a-f]{24}$'}
structured:
  sglang-router:
    events: [worker_response_read_failed, worker_proxy_failed, pair_selection_failed, request_serialization_failed,
             worker_error_body_invalid_json, worker_request_prepare_failed, paired_decode_cancelled, worker_http_error,
             worker_request_failed, response_serialization_failed, router_config_rejected, router_exit, router_failed,
             router_started]
    fields:
      timestamp: {string: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$'}
      source_revision: {string: '^([0-9a-f]{40}|unknown)$'}
      role: {string: '^(router|prefill|decode)$'}
      status: {int: true}
      code: {int: true}
  inference-worker:
    events: [worker_ready, request_failed, gpu_oom, cuda_error, nccl_error, worker_error, worker_exit, jit_compile]
    fields:
      model_revision: {string: '^[0-9a-f]{40}$'}
      gpus: {int: true}
      load_seconds: {int: true}
      error_class: {string: '^(invalid_request|not_found|request_too_large|overloaded|unavailable|timeout|client_error|connection_error|aborted|internal_assertion|unclassified)$'}
      http_status: {int: true}
      phase: {string: '^(http|tokenize|schedule|model|unknown)$'}
      input_tokens_bucket: {string: '^(unknown|lt_1k|1k_8k|8k_32k|32k_128k|128k_512k|ge_512k)$'}
      duration_ms: {int: true}
      # A type name of code: dotted identifiers ending in Error, Exception, ...
      exception: {string: '^([A-Za-z_][A-Za-z0-9_]{0,40}[.]){0,6}[A-Za-z_][A-Za-z0-9_]{0,40}(Error|Exception|Interrupt|Exit|Warning|Iteration|Failure|Timeout)$'}
      # A frame of SGLang code: sglang/<path>.py:<line>.
      location: {string: '^sglang(_simulator)?/[A-Za-z0-9_/.-]{1,150}[.]py:[0-9]{1,7}$'}
      code: {string: '^(cudaError[A-Za-z]{1,40}|nccl[A-Za-z]{1,40}|timeout|unknown)$'}
      exit_code: {int: true}
      signal: {string: '^SIG[A-Z0-9]{1,12}$'}
      # jit_compile: a kernel compiled after worker_ready. The cache is a
      # fixed name, never a path; files is a count.
      cache: {string: '^(flashinfer|triton|inductor|deep_gemm|sglang_jit|cuda|tilelang|cute_dsl|tvm_ffi|other)$'}
      files: {int: true}
      # The Triton kernels that compiled: their function names in code (file
      # stems of the Triton cache), at most 8, comma-joined; empty otherwise.
      kernels: {string: '^([A-Za-z_][A-Za-z0-9_]{0,63}(,[A-Za-z_][A-Za-z0-9_]{0,63}){0,7})?$'}
  # sglang-pair (inference.layout pair): the supervisor's error records,
  # confidential-sglang confidential/helpers/pair_supervisor.py EVENTS. The
  # supervisor discards the workers' and the model gate's own output and
  # writes only records that pass its schema (reviewed_event); the workers
  # send it error events and, on a failure, stack and NCCL snapshots
  # (sglang/srt/utils/pair_progress.py). Every field is a fixed name, a
  # code path of the image, or a number. Left out on purpose: count and
  # bytes (an NCCL collective's tensor size, a KV transfer's size) and
  # input_tokens / output_tokens (a batch's token totals): with one request
  # in a batch, each gives that request's prompt or output length.
  inference-pair:
    events: [rank_failed, watchdog_timeout, communicator_abort_timeout, child_exit, progress_stale,
             startup_timeout, shutdown_timeout, supervisor_failed, cuda_error, nccl_error, diagnostic_failed,
             kv_transfer_failed, status_request_failed, rank_progress_failed, stack_frame, stack_dump_complete,
             stack_dump_unavailable, communicator_abort_started, communicator_abort_finished,
             communicator_abort_failed, fatal_exit_deadline, nccl_collective, nccl_snapshot,
             nccl_snapshot_unavailable, scheduler_snapshot, scheduler_snapshot_unavailable,
             gpu_event_query_failed, diagnostic_delivery_failed,
             # Readiness and late compiles, and the model gate's own events
             # (confidential-sglang #31: fetch-model, wait-for-model).
             worker_ready, jit_compile, model_fetch_started, model_fetch_retry, model_fetch_complete,
             model_fetch_failed, model_verified, model_check_failed]
    fields:
      # The supervisor's own: when, which supervisor run (random per start),
      # which source build.
      timestamp_ns: {int: true}
      run_id: {string: '^[0-9a-f]{32}$'}
      source_revision: {string: '^([0-9a-f]{40}|unknown)$'}
      # Which worker: the pair itself, prefill or decode, and the rank.
      role: {string: '^(pair|prefill|decode)$'}
      rank: {int: true}
      # A fixed numeric code of the event (child exit status, failure kind).
      code: {int: true}
      # Times: of the failure, since the last progress, of a pending GPU
      # step, of the scheduler's stage and last step, an NCCL timeout.
      duration_ms: {int: true}
      age_ms: {int: true}
      gpu_pending_ms: {int: true}
      step_age_ms: {int: true}
      last_step_ms: {int: true}
      timeout_ms: {int: true}
      # A stack frame: a thread and frame index, a file of the image's code
      # (sglang, torch, uvicorn, zmq or the Python library; never a frame's
      # text) and its line.
      thread: {int: true}
      frame: {int: true}
      location: {string: '^(sglang|torch|uvicorn|zmq|python)/[A-Za-z0-9_/.-]{1,200}[.]py$'}
      line: {int: true}
      # A scheduler snapshot: its stage (a fixed code) and how many requests
      # its batch holds.
      stage_code: {int: true}
      batch_size: {int: true}
      queue_depth: {int: true}
      # An NCCL collective: its kind, state, sequence number, process group
      # number and times.
      op: {string: '^(all_reduce|broadcast|reduce|all_gather|reduce_scatter|all_to_all|send|recv|barrier)$'}
      state: {string: '^(scheduled|started|completed)$'}
      sequence: {int: true}
      group_id: {int: true}
      created_ns: {int: true}
      started_ns: {int: true}
      completed_ns: {int: true}
      # Delivery counters of the snapshot and of the diagnostics.
      rejected: {int: true}
      exported: {int: true}
      dropped: {int: true}
      pending: {int: true}
      failures: {int: true}
      # worker_ready: the worker's GPUs and seconds since the supervisor started.
      gpus: {int: true}
      load_seconds: {int: true}
      # jit_compile after worker_ready: the Triton kernel's function name in
      # code and its compile time (duration_ms above).
      kernel: {string: '^[A-Za-z_][A-Za-z0-9_]{0,63}$'}
      # The model gate: a file of the pinned model manifest (never a name read
      # from disk), the model server's host name (an allowlist exit), the
      # attempt, a fixed error class and HTTP status, sizes and SHA-256 digests
      # of model bytes, and file and byte counts.
      # A segment may start with a dot (.gitattributes) but is never . or ..;
      # the source caps each segment at 128 characters (RE2 refuses a nested
      # repeat count here).
      file: {string: '^([A-Za-z0-9_-][A-Za-z0-9_.-]*|[.][A-Za-z0-9_-][A-Za-z0-9_.-]*)(/([A-Za-z0-9_-][A-Za-z0-9_.-]*|[.][A-Za-z0-9_-][A-Za-z0-9_.-]*)){0,8}$'}
      host: {string: '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'}
      attempt: {int: true}
      error_class: {string: '^(http_error|connection|timeout|size_mismatch|digest_mismatch|io|manifest_digest|manifest_invalid|unsafe_path|unavailable|writable|missing|extra|unexpected_file|index_invalid|root)$'}
      http_status: {int: true}
      expected_size: {int: true}
      got_size: {int: true}
      expected_sha256: {string: '^[0-9a-f]{64}$'}
      got_sha256: {string: '^[0-9a-f]{64}$'}
      files: {int: true}
      size_bytes: {int: true}
      downloaded: {int: true}
      kept: {int: true}
textSources: [c8s, telemetry-collector, node-log-agent]
# The containers C8s injects into a member pod (C8s v0.101.5
# pkg/workloadclaims). The front door's namespace (c8s.frontDoorNamespace) and
# c8s-system are C8s sources too.
c8sContainers: [c8s-cert, c8s-cert-wait, c8s-secret, c8s-volume, c8s-mesh, cds-attest]
# The keys that every kept record carries, set by the agent and the collector.
identity: [service, namespace, pod, container, node, environment, deployment, framework_release]
{{- end -}}

{{- /* The keys a kept record of one source may carry: the policy and identity keys. */ -}}
{{- define "confidential-inference.logPolicy.keys" -}}
{{- $p := .policy -}}
{{- $keys := list -}}
{{- if eq .source "gateway" -}}
{{- $keys = concat (list "event" "level") (keys $p.auditFields) -}}
{{- else if hasKey $p.structured .source -}}
{{- $keys = concat (list "event") (keys (get $p.structured .source).fields) -}}
{{- else -}}
{{- $keys = list "level" "msg" -}}
{{- end -}}
{{- concat $keys $p.identity | uniq | sortAlpha | toJson -}}
{{- end -}}

{{- /* OTTL statements that check the fields of a parsed record at `.path`
for one source: a string field must match its pattern, an integer field must
be a number (it becomes an integer). A field that fails is deleted. `.when`
is the source condition. */ -}}
{{- define "confidential-inference.logPolicy.fieldChecks" -}}
{{- $path := .path -}}
{{- $when := .when -}}
{{- range $name, $rule := .fields }}
{{- $value := printf "%s[%s]" $path (toJson $name) }}
{{- if $rule.int }}
- {{ printf "delete_key(%s, %s) where %s and %s != nil and not IsInt(%s) and not IsDouble(%s)" $path (toJson $name) $when $value $value $value | toJson }}
- {{ printf "set(%s, Int(%s)) where %s and IsDouble(%s)" $value $value $when $value | toJson }}
{{- else }}
- {{ printf "delete_key(%s, %s) where %s and %s != nil and not IsString(%s)" $path (toJson $name) $when $value $value | toJson }}
- {{ printf "delete_key(%s, %s) where %s and IsString(%s) and not IsMatch(%s, %s)" $path (toJson $name) $when $value $value (toJson $rule.string) | toJson }}
{{- end }}
{{- end }}
{{- end -}}
