# NVIDIA CDI records

One file for each NVIDIA driver version: `nvidia-<driver>.json`.

```json
{
  "driverVersion": "595.71.05",
  "toolkitVersion": "1.19.1",
  "nodeImages": ["ghcr.io/confidential-dot-ai/node-guest-base@sha256:..."],
  "driverInputs": {"confosFetchGpuSha256": "sha256:..."},
  "source": "who captured it, how, and from which node image",
  "env": {"NVIDIA_VISIBLE_DEVICES": "void", "NVIDIA_CTK_LIBCUDA_DIR": "/usr/lib/x86_64-linux-gnu"},
  "mounts": [{"destination": "...", "kind": "host", "source": "...", "readOnly": true}]
}
```

`nodeImages` lists every node image that the record holds for. The allowlist
generator refuses a record that does not list the node image of the profile.

`driverInputs.confosFetchGpuSha256` is the SHA-256 of `bin/confos-fetch-gpu` in
confidential-os-builder at the ref that c8s pins in `.github/build-pins.json`.
That script pins the NVIDIA driver and the container toolkit. When a c8s
release keeps the same ref, or a ref whose script has the same SHA-256,
`scripts/bump-c8s.py` adds the new node image to `nodeImages`. Otherwise it
stops, and a person derives the record again.

`source` describes how the record was derived. It does not change when the
record is reused for a later node image.
