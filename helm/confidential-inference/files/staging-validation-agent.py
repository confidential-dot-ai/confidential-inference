"""Run bounded staging checks inside the C8s mesh.

The operator submits tasks through one namespaced Secret.
The service account can read only that Secret. No signer private key enters
this process. Responses exclude request headers, tokens, and snapshot bodies.
"""
import base64
import concurrent.futures
import json
import os
import re
import ssl
import socket
import time
import urllib.error
import urllib.parse
import urllib.request




class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ValueError("Redirects are not permitted for signed gateway requests.")


def validate_action(action, allowed_hosts, router_hosts=(), *, worker_hosts=(), worker_control=False):
    """Permit only bounded staging checks. Reload comes from native file readers."""
    parsed = urllib.parse.urlsplit(action["url"])
    gateway = {"/health": (9443, "GET"), "/ready": (9443, "GET"),
               "/v1/chat/completions": (9443, "POST"), "/attestation": (9443, "GET"),
               "/metrics": (9090, "GET"), "/runtime-config": (9090, "GET"),
               "/release-config": (9090, "GET")}
    router = {"/health": (30000, "GET"), "/readiness": (30000, "GET"),
              "/model-routes": (30000, "GET"), "/model-routes/status": (30000, "GET")}
    paths = gateway if parsed.hostname in allowed_hosts else router if parsed.hostname in router_hosts else {}
    if (parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment
            or parsed.path not in paths or (parsed.query and parsed.path != "/attestation")
            or (parsed.port, action.get("method", "GET")) != paths.get(parsed.path)):
        raise ValueError("The staging action destination, method, or port is not approved.")
    checked_body(action)
    return parsed


def checked_body(action):
    body = action.get("body")
    if body is not None and (not isinstance(body, str) or len(body.encode()) > 4 * 1024 * 1024):
        raise ValueError("The request body exceeds the limit.")
    if action.get('method', 'GET') == "GET" and body is not None:
        raise ValueError("A GET action cannot have a body.")


def perform(action, allowed_hosts, router_hosts=(), *, worker_hosts=(), worker_control=False):
    parsed = validate_action(action, allowed_hosts, router_hosts,
                             worker_hosts=worker_hosts, worker_control=worker_control)
    body = action.get("body")
    data = None if body is None else body.encode()
    request = urllib.request.Request(action["url"], data=data,
                                    headers=action.get("headers", {}),
                                    method=action.get("method", "GET"))
    start = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=45) as response:
            status = response.status
            instance = response.headers.get('X-Confidential-Gateway')
            raw = response.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(8192)
        instance = error.headers.get('X-Confidential-Gateway')
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("The response exceeds the limit.")
    result = {"name": action["name"], "status": status,
              "durationSeconds": round(time.monotonic() - start, 3)}
    if instance:
        result['gatewayIdentity'] = instance
    if parsed.path == "/metrics":
        result["metrics"] = raw.decode()
    else:
        try:
            document = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            document = {"code": "non_json_response"}
        if parsed.path == "/v1/chat/completions":
            result["validCompletion"] = isinstance(document.get("choices"), list) and bool(document["choices"])
            result["requestId"] = document.get("id")
            result['responseModel'] = document.get('model')
        else:
            # These endpoints return public evidence or safe key-source state.
            result["response"] = document
    return result


def main():
    namespace = os.environ["UPDATE_NAMESPACE"]
    secret = os.environ["UPDATE_SECRET"]
    hosts = json.loads(os.environ["UPDATE_HOSTS"])
    router_hosts = json.loads(os.environ.get('UPDATE_ROUTER_HOSTS', '[]'))
    worker_hosts = json.loads(os.environ.get('UPDATE_WORKER_HOSTS', '[]'))
    worker_control = os.environ.get('UPDATE_WORKER_CONTROL', 'false') == 'true'
    account = "/var/run/secrets/kubernetes.io/serviceaccount/"
    context = ssl.create_default_context(cafile=account + "ca.crt")
    url = f"https://kubernetes.default.svc/api/v1/namespaces/{namespace}/secrets/{secret}"
    last = None
    while True:
        try:
            with open(account + "token") as stream:
                token = stream.read().strip()
            request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
            with urllib.request.urlopen(request, context=context, timeout=10) as response:
                record = json.load(response)
            packet = json.loads(base64.b64decode(record["data"]["task.json"]))
            if not isinstance(packet.get("actions"), list) or not 1 <= len(packet["actions"]) <= 32:
                raise ValueError("The task must have one to 32 actions.")
            if packet["id"] != last:
                results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(perform, action, hosts, router_hosts,
                                          worker_hosts=worker_hosts, worker_control=worker_control)
                               for action in packet["actions"]]
                    for action, future in zip(packet["actions"], futures):
                        try:
                            results.append(future.result())
                        except Exception as error:
                            results.append({"name": action["name"], "status": 0,
                                            "error": type(error).__name__,
                                            "cause": type(getattr(error, "reason", error)).__name__,
                                            "errno": getattr(getattr(error, "reason", error), "errno", None)})
                print(json.dumps({"taskId": packet["id"], "results": results}), flush=True)
                last = packet["id"]
        except Exception as error:
            print(json.dumps({"agentError": type(error).__name__}), flush=True)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
