# Gateway Image

This recipe builds the public gateway from `services/gateway`.

The build script requires committed source. It supplies the exact public source commit.

```bash
images/gateway/build.sh \
  --no-cache \
  --provenance=false \
  --sbom=false \
  --platform linux/amd64 \
  --output type=oci,dest=/tmp/gateway.oci.tar,rewrite-timestamp=true
```

The local command verifies the application build. An OCI digest can also depend on the OCI
builder and layer timestamps. The release workflow pins Buildx and BuildKit. It builds two
clean OCI archives and compares their Linux AMD64 platform manifests.
It publishes the audited OCI archive. The published platform digest must
equal the verified digest.

Use the approved `Release images` workflow in
[release-images.yml](../../.github/workflows/release-images.yml) on public
`main`. Set `publish` and `rebuild_audit` to `true` and provide the reviewed
`base_ref` and `base_ref_commit`. The workflow selects affected images.
See [release publication](../../release/README.md) for the full sequence.

The local command above is for development tests. A production-ready candidate
must use images from the approved build and signed release pipeline.

The final image runs one binary as UID and GID `65532`. Kubernetes supplies all configuration and writable mounts.

The image contains no shell, SSH server, init system, cloud helper, or overlay network client. The gateway uses high pod ports.
