# Staging release profile

This profile builds `v0.14.0-staging`. It uses the same pinned public source,
c8s node image, model identity, and SGLang image as `v0.14.0`.

The worker uses the CPU SGLang simulator. It first runs `wait-for-model` against
the encrypted model mount. This check exercises model download, encryption,
placement, opening, and byte-manifest validation without loading the model
weights into the simulator.

Generate and check this profile with the standard release tools and
`--release release/staging`.
