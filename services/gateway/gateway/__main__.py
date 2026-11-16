"""Gateway process entry point."""

import logging
import os
from pathlib import Path

from aiohttp import web
import uvloop

from .app import create_app
from .config import Config
from .keys import AdminAuth, Keys


def main():
    # HTTP access and exception logs can carry customer text. The application
    # writes reviewed records; no library logger may expose request material.
    logging.disable(logging.CRITICAL)
    config = Config.from_env()
    pepper = Path(os.environ.get("GATEWAY_API_KEY_PEPPER_FILE", "/run/c8s/secrets/GATEWAY_API_KEY_PEPPER")).read_bytes()
    hashes = Path(os.environ.get("GATEWAY_ADMIN_API_KEY_HASHES_FILE", "/mnt/c8s-data/admin-api-key/sha256")).read_text().splitlines()
    certificate = Path(os.environ.get("GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE", "/mnt/c8s-data/admin-auth/client.crt")).read_bytes()
    app = create_app(config, Keys(pepper, config.environment), AdminAuth(certificate, hashes))
    address = os.environ.get("GATEWAY_LISTEN", "0.0.0.0:9443")
    host, port = address.rsplit(":", 1)
    web.run_app(app, loop=uvloop.new_event_loop(), host=host, port=int(port), access_log=None, print=None, handler_cancellation=True,
                shutdown_timeout=float(os.environ.get("GATEWAY_SHUTDOWN_GRACE_SECONDS", "900")))


if __name__ == "__main__":
    main()
