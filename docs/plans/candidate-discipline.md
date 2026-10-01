# Candidate deployment discipline

## Model

There are two software environments and release types: prod and staging.
There are three deployment targets: candidate, prod, and staging.

Candidate runs the same prod release and pinned pod configuration intended
for production. Promotion must not require changes to pod arguments,
environment variables, or mounts. Keep deployment target separate from
software environment.

## Candidate testing

Admin selects which API key records each cluster receives and where its logs,
metrics, and usage appear. Separate candidate test records from customer records
by deployment target. Verify every authentication source, including fallback
sources. Do not send customer keys to candidate during routine tests.

Give each cluster a permanent ID. Use that ID to route telemetry through an
approved interface. Do not trust a caller-supplied environment label as the
only isolation control. Keep test usage and alerts out of production totals
and paging. Bound telemetry rate and storage on shared infrastructure.

Candidate HTTPS can be public. Require keys for inference. Attestation is
public without an inference key. Keep management ports private. Verify TLS,
certificate renewal, gateway discovery, aggregate attestation, rejection of
wrong pins, TEErminator inference, key revocation, workers, and telemetry.

Check that hostname and admin endpoint selection comply with the measured
policy. If the software cannot support promotion without configuration changes,
fix the prod release and test that mechanism before deployment.

## Admin records

Show cluster ID, target role, release and image pins, hostname and TLS identity,
key synchronization revision, telemetry destination, last data time, and test
results. Show intended and observed DNS and routing separately. Include check
times, errors, and partial transition state.

Historical candidate data stays candidate history after promotion. The cluster
ID stays unchanged. The role attached to new data changes at a recorded boundary.

## Promotion

Use a reviewed operation with these checkpoints:

1. Pass candidate acceptance on the exact prod release and node image.
2. Prepare production routing and admin mapping. Load the existing customer
   key records through the unchanged gateway interface. Verify the acknowledged
   revision and compatible key hashing configuration. Remove candidate test
   keys and check all authentication sources.
3. Synchronize customer key changes and revocations to both clusters while
   either can receive traffic or serve as rollback.
4. Retain or flush queued candidate telemetry under its original target
   identity. Route new production telemetry to production views on admin.
   Do not change pinned pod configuration or relabel test history.
5. Change production routing only with separate authority. Remove candidate
   DNS and hostname routing from the promoted cluster. Verify actual traffic;
   DNS TTL expiry does not prove all clients have switched.
6. Verify keys, inference, attestation, logs, metrics, and admin state. Keep
   the old cluster for a defined drain and rollback period. Then stop its key
   synchronization and retire it.

These changes are not one atomic transaction. Record partial progress, stop
on failed checks, and support retry or rollback from each checkpoint.

The next candidate gets a new cluster ID and fresh test authority. It still
runs prod software. Use unique hostnames for simultaneous candidates. DNS
selects a target; it is not an attestation trust anchor.

## Automation boundary

A target-specific plan must pin the signed release, c8s image, CVM placement,
hostname, key source, and telemetry destination. Change only affected parts.
Keep private topology, live state, secrets, and operation receipts in the
private deployment repository. Record each attempt and recheck live state
before apply.
