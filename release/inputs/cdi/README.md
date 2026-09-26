# NVIDIA CDI records

One file for each NVIDIA driver version: `nvidia-<driver>.json`.

```json
{
  "driverVersion": "595.71.05",
  "toolkitVersion": "1.19.1",
  "nodeImage": "ghcr.io/confidential-dot-ai/node-guest-base@sha256:...",
  "source": "who captured it, how, and from which CVM",
  "env": {"NVIDIA_VISIBLE_DEVICES": "void", "NVIDIA_CTK_LIBCUDA_DIR": "/usr/lib/x86_64-linux-gnu"},
  "mounts": [{"destination": "...", "kind": "host", "source": "...", "readOnly": true}]
}
```

**Missing:** `nvidia-595.71.05.json`, for the c8s v0.33.2 node image. c8s issue
#693 reports two environment values and 15 driver mounts from a probe CVM, but
the full probe record is in neither repository. Do not reconstruct it from
the counts. Add the reviewed record here. Until then, the allowlist generator
refuses the GPU workers.
