"""
Loads config.yaml (or an override path) into a simple AppConfig object.
CLI flags in main.py can override individual fields after loading.
"""
from dataclasses import dataclass, field

import yaml


@dataclass
class AppConfig:
    provider: str
    model: str
    allowed_hosts: list
    max_steps: int
    max_ports_scanned: int
    confirm_state_changes: bool
    common_paths: list
    raw: dict = field(default_factory=dict)


def load_config(path: str = "config.yaml", provider_override: str | None = None,
                 model_override: str | None = None) -> AppConfig:
    with open(path) as f:
        raw = yaml.safe_load(f)

    provider = provider_override or raw["provider"]
    model = model_override or raw[provider]["model"]

    return AppConfig(
        provider=provider,
        model=model,
        allowed_hosts=raw["allowed_hosts"],
        max_steps=raw["max_steps"],
        max_ports_scanned=raw["max_ports_scanned"],
        confirm_state_changes=raw["confirm_state_changes"],
        common_paths=raw["common_paths"],
        raw=raw,
    )
