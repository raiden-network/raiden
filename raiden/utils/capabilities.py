from typing import Any, Dict, Union

import structlog

from raiden.constants import Capabilities
from raiden.settings import CapabilitiesConfig

log = structlog.get_logger(__name__)


def _bool_to_binary(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value is True else "0"
    return value


def int_bool(value: str) -> Union[bool, str]:
    try:
        if int(value) in {0, 1}:
            return bool(int(value))
        else:
            return value
    except ValueError:
        return value


def capdict_to_config(capdict: Dict[str, Any]) -> CapabilitiesConfig:
    config = CapabilitiesConfig(
        receive=capdict.get(Capabilities.RECEIVE.value, True),
        mediate=capdict.get(Capabilities.MEDIATE.value, True),
        delivery=capdict.get(Capabilities.DELIVERY.value, True),
        web_rtc=capdict.get(Capabilities.WEBRTC.value, False),
        to_device=capdict.get(Capabilities.TODEVICE.value, False),
        immutable_metadata=capdict.get(Capabilities.IMMUTABLE_METADATA.value, False),
    )
    for key in capdict.keys():
        if key not in [_.value for _ in Capabilities]:
            setattr(config, key, capdict[key])
    return config


def capconfig_to_dict(config: CapabilitiesConfig) -> Dict[str, Any]:
    result = {
        Capabilities.RECEIVE.value: config.receive,
        Capabilities.MEDIATE.value: config.mediate,
        Capabilities.DELIVERY.value: config.delivery,
        Capabilities.WEBRTC.value: config.web_rtc,
        Capabilities.TODEVICE.value: config.to_device,
        Capabilities.IMMUTABLE_METADATA.value: config.immutable_metadata,
    }
    other_keys = [
        key
        for key in config.__dict__.keys()
        if key
        not in ["receive", "mediate", "delivery", "web_rtc", "to_device", "immutable_metadata"]
    ]
    for key in other_keys:
        if key not in [_.value for _ in Capabilities]:
            result[key] = getattr(config, key)
    return result
