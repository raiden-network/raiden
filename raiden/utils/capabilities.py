from typing import Any, Dict, Optional

from raiden.constants import Capabilities
from raiden.settings import CapabilitiesConfig


def parse_capabilities(capstring: str) -> Dict[str, Any]:
    if capstring.startswith("mxc://"):
        capstring = capstring[6:]
    elif "/" in capstring:
        capstring = capstring[capstring.rindex("/") + 1 :]
    result: Dict[str, Any] = {}
    if len(capstring) == 0:
        return result
    for token in capstring.split(","):
        if "=" in token:
            key, value = token.split("=")
            value = value.strip('"')
            result[key] = value
        else:
            result[token] = True
    return result


def serialize_capabilities(capdict: Optional[Dict[str, Any]]) -> str:
    for key in (capdict or {}).keys():
        if "/" in str(key):
            raise ValueError(f"Key {key} is malformed, '/' not allowed")
    if capdict is None:
        return "mxc://"
    entries = []
    for key, value in capdict.items():
        if isinstance(value, bool):
            if value:
                entries.append(key)
        else:
            entries.append(f'{key}="{value}"')
    if len(entries):
        return f"mxc://{','.join(entries)}"
    return "mxc://"


def capdict_to_config(capdict: Dict[str, Any]) -> CapabilitiesConfig:
    config = CapabilitiesConfig(
        no_receive=capdict.get(Capabilities.NO_RECEIVE.value, False),
        no_mediate=capdict.get(Capabilities.NO_MEDIATE.value, False),
        no_delivery=capdict.get(Capabilities.NO_DELIVERY.value, False),
        web_rtc=capdict.get(Capabilities.WEBRTC.value, False),
    )
    for key in capdict.keys():
        if key not in [_.value for _ in Capabilities]:
            setattr(config, key, capdict[key])
    return config


def capconfig_to_dict(config: CapabilitiesConfig) -> Dict[str, Any]:
    result = {}
    result[Capabilities.NO_RECEIVE.value] = config.no_receive
    result[Capabilities.NO_MEDIATE.value] = config.no_mediate
    result[Capabilities.NO_DELIVERY.value] = config.no_delivery
    result[Capabilities.WEBRTC.value] = config.web_rtc
    for key in config.__dict__.keys():
        if key not in [_.value for _ in Capabilities]:
            result[key] = getattr(config, key)
    return result
