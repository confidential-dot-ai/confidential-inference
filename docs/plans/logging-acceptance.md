# Logging acceptance checklist

Use this checklist for each staging deployment and each candidate
deployment of a framework release that includes the node log agent. Run
every check on the deployment itself. Staging and production log the same
way, so a check that passes on staging also tests production.

Terms:

- **Agent**: the node log agent, the DaemonSet `node-log-agent`
  (`helm/confidential-inference/templates/node-log-agent.yaml`).
- **Collector**: the Deployment `telemetry-collector`, the only pod with an
  exit and the relay credentials.
- **Log policy**: `helm/confidential-inference/templates/_log-policy.tpl`.
- **Marker**: a unique random string, for example
  `canary-<16 random hex digits>`. Make a new one for each run. Do not use
  it anywhere else.

Design and field list: [docs/telemetry-egress.md](../telemetry-egress.md).

Before you start, record the deployment name (`deployment`, for example
`staging-0123456789ab`), the environment, and the framework release.
Every Loki query below selects the deployment with
`{k8s_cluster_name="<deployment>"}`. If the relay maps the labels with
other names, use those names and write them in the record.

## Checks that the tests in the repository cover

These tests run without a cluster. They must pass on the release commit.

| Criterion | Test |
|---|---|
| 2, 3: no marker, client address, user agent or Bearer token leaves the agent and the collector | `tests/telemetry/test_node_log_agent.py` (needs Docker) |
| 2: the collector drops unreviewed bodies and fields | `tests/telemetry/test_collector.py` (needs Docker) |
| 2: the worker supervisor emits no marker from prompts, exception messages, code lines or access-log paths; tracebacks become a type and an SGLang location; unknown errors are `unclassified` | `tests/images/sglang-confidential/test_server_output.py` |
| 2: the router launcher emits only contract keys | `tests/images/sglang-router/test_private_router.py` |
| 2: every gateway line is JSON, with a listed message or the audit record | `cargo test -p confidential-gateway --test log_privacy` |
| 6: the agent has a read-only `/var/log/pods` mount, no other host path, no secret, no service account token, no exit | `tests/helm/test_render.py` (`check_node_log_agent`) |
| 6: the agent's allowlist entry pins its argv and mounts, admits only `NODE_NAME` as an open variable, and has no secrets grant and no egress | `tests/release-v1/fixtures/staging-allowlist.json` (entry `node-log-agent`), `tests/release-v1` |
| 7: the agent and collector log pipelines of two deployments differ only in the identity values | `tests/helm/test_render.py` (`check_node_log_agent`) |

## Checks on the deployment

Write the result of each check (pass or fail, the query, the count, the
time) in the deployment record.

### 1. Every source is in Loki, with its labels

Wait 5 minutes after all pods are Ready. Then run, for each source:

```logql
sum by (service_name) (count_over_time({k8s_cluster_name="<deployment>"}[10m]))
```

Pass when each of these sources has at least one record: `gateway`,
`sglang-router`, `inference-worker` (one or more records for each worker
pod: `inference-worker-0`, `inference-worker-1`), `c8s`,
`node-log-agent`, `telemetry-collector`.

For one record of each source, check that the body has `environment`,
`deployment`, `framework_release`, `namespace`, `service` and `node`, with
the values of this deployment, and that `node` is the node of that pod.

Each worker must have a `worker_ready` record with the release's model
revision.

### 2. Canary: the marker leaves nowhere

Send 1,000 requests through the public endpoint. Put the marker in:

- the user prompt of every request;
- the system prompt of every request;
- the tool arguments of 100 requests (a tool definition and a tool call
  message that hold the marker);
- 100 requests that fail: 50 with a body that is not valid JSON and that
  holds the marker, 50 with a prompt longer than the model context.

Then wait 5 minutes and run:

```logql
count_over_time({k8s_cluster_name="<deployment>"} |= "<marker>" [1h])
```

Pass when the result is empty (0). Also search the metrics for the marker in
any label value: export the label values of every series of the deployment
(`cluster="<telemetry.deployment>"`) for the test hour from the metrics
store, and search them for the marker. Pass when no label value holds it.

### 3. No client address, user agent or token

Run:

```logql
count_over_time({k8s_cluster_name="<deployment>"} |~ "(?i)(bearer [a-z0-9]|mozilla/|curl/|python-requests|user-agent)" [1h])
count_over_time({k8s_cluster_name="<deployment>"} |= "<your public client IP>" [1h])
```

Pass when both are empty. Send the canary requests of check 2 from a known
client address and with a known `User-Agent`, so the second query has a
value to look for.

### 4. Faults are visible within 60 seconds

For each fault, note the time, then query the deployment for 60 seconds
after it.

| Fault | How | Pass when |
|---|---|---|
| A worker dies | Delete one worker pod with `kubectl delete pod --grace-period=0 --force`, or stop its server process | A `worker_exit` record of that pod (`signal` `SIGKILL` or an `exit_code`) |
| An oversized request | Send a prompt longer than the model context | A `request_failed` record with `http_status` 400 and an `error_class` (`invalid_request`). Also a `gateway_request_completed` with status 400 |
| An unlisted pod | Apply a pod that no allowlist entry admits | See the note below |
| An unknown error | Make SGLang raise an error it does not classify (for example a request that the engine rejects with an internal error) | A `worker_error` or `request_failed` record with `error_class` `unclassified` and a `location` |

Note on the unlisted pod: C8s refuses the pod in its NRI admission plugin, a
host unit that logs to the journal (out of scope, see
docs/telemetry-egress.md section 8). The refusal is a kubelet event, not a
pod log line. Record whether any C8s pod record shows the refusal. If none
does, record the check as "not covered: journal follow-up", not as a pass.

### 5. 64 concurrent requests for 30 minutes

Run a load of 64 concurrent requests for 30 minutes and count the requests
that the load tool sent. Then run:

```logql
sum(count_over_time({k8s_cluster_name="<deployment>", service_name="gateway"} |= "gateway_request_completed" [35m]))
```

Pass when the count equals the number of requests sent (counting the
requests of the load tool only; run nothing else during the test).

Agent memory: in the metrics, read
`otelcol_process_memory_rss{service_name="node-log-agent"}` (with the
`node` label) for each agent over the 30 minutes. Pass when the value at the
end is at most 20% above the value after 5 minutes, and below the agent's
memory limit (`telemetry.nodeAgent.resources.memory`).

Also read `node_log_agent_records{kept="false"}`: it must grow only for the
expected sources (`unlisted`, and the text lines of the workers' supervisor
and fetch-model), not for `gateway` during the load.

### 6. The live allowlist

Run `c8s allowlist get node-log-agent` against the Trust Authority of the deployment.
Pass when the entry:

- has one container of the pinned collector image digest, `command` and
  `args` `exact`;
- has `mounts` `exact` with only a `host` rule for `/var/log/pods` with
  `readOnly: true` and an `emptyDir` rule;
- has `env` `match`, with `NODE_NAME` `present` and every other variable
  `exact`;
- has no `secrets` grant and no `egress`.

Compare the entry with the entry `node-log-agent` that
`scripts/render-allowlist.py` wrote for the deployment: they must be equal.

### 7. Staging and production differ only in labels

Render the allowlist of the staging deployment and the production
deployment of the same release. Take the `args` of the entries
`node-log-agent` and `telemetry-collector`. Replace the environment name,
the deployment name and `telemetry.deployment` with placeholders. Pass when
the agent `args` are equal, and the collector `processors.transform/logs`
are equal. (The relay address and credentials of the collector can differ.)
