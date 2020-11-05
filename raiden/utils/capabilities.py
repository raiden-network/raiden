from typing import Any, Dict, Optional, Union

import structlog
from werkzeug.urls import url_decode, url_encode

from raiden.constants import Capabilities
from raiden.settings import CapabilitiesConfig

log = structlog.get_logger(__name__)


def _bool_to_binary(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value is True else "0"
    return value


def _serialize(capdict: Optional[Dict[str, Any]]) -> str:
    if capdict is None:
        capdict = {}
    for key in capdict:
        capdict[key] = _bool_to_binary(capdict[key])
    return url_encode(capdict)


def serialize_capabilities(capdict: Optional[Dict[str, Any]]) -> str:
    if not capdict:
        return "mxc://"
    return f"mxc://raiden.network/cap?{_serialize(capdict)}"


def _strip_capstring(capstring: str) -> str:
    if capstring.startswith("mxc://"):
        capstring = capstring[6:]
    _, _, capstring = capstring.rpartition("/")
    _, _, capstring = capstring.rpartition("?")
    return capstring


def deserialize_capabilities(capstring: str) -> Dict[str, Any]:
    capstring = _strip_capstring(capstring)
    capdict = url_decode(capstring.encode())
    capabilities: Dict[str, Any] = dict()
    for key in capdict:
        value = capdict.getlist(key, type=int_bool)
        # reduce lists with one entry to just their element
        if len(value) == 1:
            capabilities[key] = value.pop()
        else:
            capabilities[key] = value
    return capabilities


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
    }
    other_keys = [
        key
        for key in config.__dict__.keys()
        if key not in ["receive", "mediate", "delivery", "web_rtc", "to_device"]
    ]
    for key in other_keys:
        if key not in [_.value for _ in Capabilities]:
            result[key] = getattr(config, key)
    return result
