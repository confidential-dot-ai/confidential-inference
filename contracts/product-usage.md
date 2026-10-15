# Product usage minute snapshots

The gateway reports numeric usage in one-minute UTC buckets. It does not keep request history. A bucket identifies the key realm, exact registry key ID, approved requested and served model, model revision, environment, cluster, and producer. Usage belongs to the request completion minute.

Each producer sends cumulative snapshots. The receiver replaces a bucket only with a higher revision. An identical retry changes nothing. An older revision is stale. Different content at the same revision is a conflict. Totals and revisions must persist together. A new empty volume needs a new producer identity.

Counts distinguish completed, failed, cancelled, and interrupted requests. Usage completeness is independent of outcome. Known-token counts distinguish missing observations from measured zeros. Cached input and reasoning tokens are not added again to input plus output totals. The request count equals the sum of outcome counts and the sum of usage completeness counts.

The gateway persists changed buckets every second. V1 accepts loss of unflushed observations after a crash. It sends committed snapshots every ten seconds. A batch has at most 256 records and at most 262,144 encoded bytes, including the envelope. Exactly one delivery request is in flight. Retries use increasing delays up to 120 seconds. Redirects are disabled. TLS verifies the receiver. An optional client identity supports mTLS ingress.

The envelope is `{"buckets":[...]}`. Each record has `bucket_id`, `producer_id`, `environment`, `cluster_id`, `key_realm`, `key_id`, `requested_model`, `served_model`, `model_revision`, `bucket_start_ms`, `revision`, and `counts`. The bucket ID is the lowercase SHA-256 of the compact JSON array of those eight identity strings, in that order, followed by `bucket_start_ms`. The hash does not include revision or counts.

The acknowledgment is `{"results":[{"bucket_id":"...","revision":1,"status":"accepted"}]}`. Results preserve request order. Accepted, unknown-key, and stale records are acknowledged. Unknown keys remain in the usage store for reconciliation. Conflicting or invalid snapshots are quarantined locally. Transient receiver errors retain pending snapshots for retry. Acknowledgments are committed locally in one transaction per batch.

The private CDS configuration supplies scope, a producer identity, model bindings, the HTTPS receiver URL, a producer token, optional TLS material and address override, a bucket limit, a total database byte budget, and acknowledged retention. It is never a public ConfigMap or a Kubernetes Secret. No credential enters a bucket or an error log.

The local database uses DELETE journaling and FULL synchronization. SQLite page capacity reserves room for the rollback journal within the configured byte budget. A row limit bounds in-memory aggregates. One potential new bucket is reserved per active request. Exhausted capacity rejects new inference before upstream dispatch. This behavior is for staging validation; production enablement requires its own capacity and availability decision.

The private `/usage-status` endpoint reports queue counts, limits, reconciliation counts, and flush and delivery times. It contains no key IDs, model names, or credentials. Pending data must be drained before retiring its encrypted volume. Acknowledged retention defines the supported receiver replay window.

Streaming usage is requested internally even when callers omit it. Injected final usage frames are removed when the caller did not request them. Collection handles split bytes and records final cumulative totals once. Disconnects, missing final usage, and router retries limit gateway-observed accounting. This interface does not claim complete accounting of all GPU work.

Prompts, response content, plaintext keys, arbitrary headers, caller metadata, and exception text are not permitted fields. The receiver authenticates producer scope before accepting records. Reports expose only approved usage fields and completeness, never registry verifier material.
