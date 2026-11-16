"""Startup inputs shared by the listeners and request handlers."""

import json
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    environment: str = ""
    models: list[str] = field(default_factory=list)
    catalog: list[str] = field(default_factory=list)
    upstream: str = "http://127.0.0.1:30001"
    maximum_body: int = 2_097_152
    body_memory: int = 268_435_456
    body_timeout: float = 10
    first_timeout: float = 60
    idle_timeout: float = 60
    upstream_timeout: float = 900
    execution: int = 64
    queue: int = 64
    queue_timeout: float = 2
    per_key: int = 4
    public_capacity: int = 256
    per_address: int = 16
    address_rate: int = 30
    trusted_proxies: list[str] = field(default_factory=list)
    maximum_headers: int = 64
    maximum_header_bytes: int = 16_384
    maximum_uri: int = 2048
    admin_endpoint: str = ""
    usage_enabled: bool = False
    usage_models: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls):
        config = cls()
        mappings = {
            "environment": ("DEPLOYMENT_ENVIRONMENT", str),
            "upstream": ("GATEWAY_INFERENCE_URL", str),
            "maximum_body": ("GATEWAY_MAXIMUM_BODY_BYTES", int),
            "body_memory": ("GATEWAY_BODY_MEMORY_BYTES", int),
            "body_timeout": ("GATEWAY_BODY_TIMEOUT_SECONDS", float),
            "first_timeout": ("GATEWAY_FIRST_TOKEN_TIMEOUT_SECONDS", float),
            "idle_timeout": ("GATEWAY_STREAM_IDLE_TIMEOUT_SECONDS", float),
            "upstream_timeout": ("GATEWAY_UPSTREAM_TIMEOUT_SECONDS", float),
            "execution": ("GATEWAY_INFERENCE_CONCURRENCY", int),
            "queue": ("GATEWAY_INFERENCE_QUEUE", int),
            "queue_timeout": ("GATEWAY_QUEUE_TIMEOUT_SECONDS", float),
            "per_key": ("GATEWAY_PER_KEY_CONCURRENCY", int),
            "public_capacity": ("GATEWAY_GLOBAL_REQUEST_CONCURRENCY", int),
            "per_address": ("GATEWAY_PER_ADDRESS_CONCURRENCY", int),
            "address_rate": ("GATEWAY_REQUESTS_PER_ADDRESS_PER_SECOND", int),
            "maximum_headers": ("GATEWAY_MAXIMUM_HEADERS", int),
            "maximum_header_bytes": ("GATEWAY_MAXIMUM_HEADER_BYTES", int),
            "maximum_uri": ("GATEWAY_MAXIMUM_URI_BYTES", int),
            "admin_endpoint": ("GATEWAY_ADMIN_ENDPOINT", str),
        }
        for attribute, (name, parse) in mappings.items():
            if name in os.environ:
                setattr(config, attribute, parse(os.environ[name]))
        config.models = [os.environ.get("GATEWAY_MODEL", "")]
        config.catalog = config.models.copy()
        config.trusted_proxies = list(filter(None, os.environ.get("GATEWAY_TRUSTED_PROXY_CIDRS", "").split(",")))
        config.usage_enabled = os.environ.get("GATEWAY_USAGE_ENABLED", "false") == "true"
        config.usage_models = json.loads(os.environ.get("GATEWAY_USAGE_MODELS", "{}"))
        settings = json.loads(os.environ.get("GATEWAY_RUNTIME_CONFIG", "null"))
        if settings is not None:
            names = {
                "maximumBodyBytes": "maximum_body", "bodyMemoryBytes": "body_memory",
                "bodyTimeoutSeconds": "body_timeout", "firstTokenTimeoutSeconds": "first_timeout",
                "streamIdleTimeoutSeconds": "idle_timeout", "upstreamTimeoutSeconds": "upstream_timeout",
                "inferenceConcurrency": "execution", "inferenceQueue": "queue",
                "queueTimeoutSeconds": "queue_timeout", "perKeyConcurrency": "per_key",
                "globalRequestConcurrency": "public_capacity", "perAddressConcurrency": "per_address",
                "requestsPerAddressPerSecond": "address_rate",
            }
            allowed = set(names) | {"schemaVersion", "routerService", "catalogModelIds", "inferenceModelIds", "attestationCacheSeconds", "attestationConcurrency"}
            if settings.get("schemaVersion") != 1 or set(settings) - allowed:
                raise ValueError("invalid gateway settings")
            config.models, config.catalog = settings["inferenceModelIds"], settings["catalogModelIds"]
            for name, attribute in names.items():
                if name in settings:
                    setattr(config, attribute, settings[name])
            config.first_timeout = settings.get("firstTokenTimeoutSeconds", config.idle_timeout)
        if not 1024 <= config.maximum_body <= 64 * 1024**2:
            raise ValueError("invalid body limit")
        if not config.maximum_body * 5 + 65536 <= config.body_memory <= 1 << 40:
            raise ValueError("invalid body memory budget")
        if not config.models or not all(isinstance(m, str) and m for m in config.models):
            raise ValueError("invalid model list")
        if not set(config.catalog) <= set(config.models):
            raise ValueError("invalid catalog")
        return config
