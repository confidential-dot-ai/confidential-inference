"""Named native router policy from the pinned measured-node chart render.

Platform images retain their existing seed environment and mount scope.
Only the exact declared composition and complete process vectors are added.
"""

import copy
import re


class NativeRuleError(ValueError):
    pass


def router_controller(documents):
    matches = [item for item in documents if isinstance(item, dict)
               and item.get("kind") == "Deployment"
               and item.get("metadata", {}).get("name") == "c8s-router"
               and item.get("metadata", {}).get("namespace") == "c8s-system"]
    if len(matches) != 1:
        raise NativeRuleError("the pinned node render must contain one native c8s-router")
    return copy.deepcopy(matches[0])


def native_entries(c8s, configs, record):
    if record.get("sourceCommit") != c8s["sourceCommit"] or record.get("coreImages") != c8s["coreImages"]:
        raise NativeRuleError("native router source or core images differ from the selected C8s pins")
    controller = router_controller([record.get("nativeRouter")])
    pod = controller["spec"]["template"]["spec"]
    mains = pod.get("containers", [])
    inits = pod.get("initContainers", [])
    if {item["name"] for item in mains} != {"nginx", "cds-attest", "allowlist-proxy"}:
        raise NativeRuleError("the pinned native router has an unsupported main composition")
    if {item["name"] for item in inits} != {"acme", "c8s-cert", "c8s-cert-wait"}:
        raise NativeRuleError("the pinned native router has an unsupported init composition")
    if len(mains) != 3 or len(inits) != 3:
        raise NativeRuleError("the pinned native router repeats a container")
    if next(item for item in inits if item["name"] == "acme").get("restartPolicy") != "Always":
        raise NativeRuleError("native router acme must retain its declared init sidecar role")

    def process(item):
        image = item.get("image")
        if image not in c8s["coreImages"] or image not in configs:
            raise NativeRuleError("native router image is not a configured pinned core image")
        match = re.fullmatch(r"[^@\s]+@(sha256:[0-9a-f]{64})", image)
        if match is None:
            raise NativeRuleError("native router image needs an immutable digest")
        config = configs[image]
        command = item.get("command") or config.get("entrypoint") or []
        args = item.get("args")
        if args is None:
            args = [] if item.get("command") else config.get("cmd") or []
        argv = command + args
        if not command or not all(isinstance(arg, str) and "$(" not in arg for arg in argv):
            raise NativeRuleError("native router process is absent or uses dynamic expansion")
        return image, match[1], argv

    for item in inits:
        if item["name"] in {"c8s-cert", "c8s-cert-wait"}:
            _, _, argv = process(item)
            mode = "get-cert" if item["name"] == "c8s-cert" else "probe-file"
            if argv[:2] != ["/c8s", mode]:
                raise NativeRuleError("native router injected component process differs")

    def rule(item):
        image, digest, argv = process(item)
        prefix = list(configs[image].get("entrypoint") or [])
        if image.partition("@")[0] == "nginxinc/nginx-unprivileged":
            prefix.append("nginx")
        if not prefix or argv[:len(prefix)] != prefix:
            raise NativeRuleError("native router command differs from its component entrypoint")
        args = argv[len(prefix):]
        return {"image": image, "digest": digest,
                "command": {"policy": "exact", "argv": prefix},
                "args": {"policy": "exact", "argv": args} if args else {"policy": "deny"},
                "env": {"policy": "any"}, "mounts": {"policy": "any"}}

    return {"c8s-router": {"label": "C8s native baked router",
            "initContainers": [rule(item) for item in inits if item["name"] == "acme"],
            "containers": [rule(item) for item in mains]}}
