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
- sglang-router, inference-worker: JSON events of fixed names. Only the listed
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
  - "the metrics listener stopped"
  - "the gateway is ready"
  - "the gateway started endpoint drain"
  - "the gateway started graceful shutdown"
  - "the gateway panicked; the panic message is not logged"
  - "no routing key secret: the router routes requests at random"
  - "the gateway serves its usage reporter key"
  - "usage model identity did not match its approved binding"
  - "a usage event was refused by Confidential Cloud"
  - "a usage report was refused by Confidential Cloud; dropped it"
  - "the reporter key is not bound in Confidential Cloud; bind the key the gateway serves"
  - "usage delivery delayed"
  - "usage events were not reported before shutdown"
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
    events: [worker_ready, request_failed, gpu_oom, cuda_error, nccl_error, worker_error, worker_exit]
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
