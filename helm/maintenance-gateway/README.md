# Maintenance gateway chart

This chart installs one stateless fallback gateway in a confidential VM.

Set `image` to the published digest.
The c8s TLS-LB owns the public TLS certificate. It sends HTTP to this workload through the attested internal mesh.
The pod has no service account token, state volume, upstream route, or egress access.
Set `trustedProxyCidrs` only for a proxy that overwrites `X-Forwarded-For` with one address.
The process rejects all other forwarding headers.
