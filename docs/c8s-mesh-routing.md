# C8s mesh routing

The current C8s mesh redirects pod TCP connections to the local node listener
on port `15001`. The application egress policy must permit that listener.
Set `network.c8sMeshNodeCidrs` to the inner node CIDRs of the deployment.
The chart permits only TCP port `15001` on those CIDRs. An empty list keeps
the earlier chart behavior.

This setting also makes the SGLang router, metrics collector, and
kube-state-metrics Services headless. DNS then gives the pod address before
the mesh redirect runs. A normal Service can change its virtual address to a
pod address after that redirect. The C8s guard can reject that direct path.

The router Service publishes its address during model startup. This lets the
gateway reach the receipt sidecar before the router can serve completions.

The mesh keeps its attested TLS hop between nodes. The application must not
disable the C8s guards or expose the node attestation API to the network.
Retain the Unix socket configuration for receipt sidecars.

For an existing deployment, review the rendered diff first. Kubernetes does
not permit changing an allocated Service address to `None`. Recreate only
the three affected Services during the Helm update. This does not restart
their pods. Record the brief service outage and the updated chart source.
Keep public DNS and the production cluster unchanged for a candidate update.
