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
clean OCI archives and compares their Linux AMD64 platform manifests. It then builds the
published image and requires the published platform digest to equal the verified digest.

Use the `V0 image and release builds` workflow with `publish: true` and
`publish_target: gateway` to publish a gateway. Do not publish a release image with an
unverified local command.

The final image runs one binary as UID and GID `65532`. Kubernetes supplies all configuration and writable mounts.

The image contains no shell, SSH server, init system, cloud helper, or overlay network client. The gateway uses high pod ports.

The workflow builds this image after all source files exist. The workflow does not publish the gateway image yet.
