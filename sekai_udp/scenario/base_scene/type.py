from enum import IntEnum
from dataclasses import dataclass
from typing import TypeAlias

from sekai_client.client import SekaiClient # implement http client by yourself
from ...udp import SekaiUdp

class MetaTypeId(IntEnum):
    invalid = 0
    byte = 1
    int32 = 2
    int64 = 3
    string = 4
    float = 5
    bool = 6
    object = 7

class MetaType:
    Invalid: TypeAlias = None
    Byte: TypeAlias = bytes | None
    Int32: TypeAlias = int | None
    Int64: TypeAlias = int | None
    String: TypeAlias = str | None
    Float: TypeAlias = float | None
    Bool: TypeAlias = bool | None
    Object: TypeAlias = object | None

def meta_dump(data, meta_type: MetaTypeId):
    match meta_type:
        case MetaTypeId.invalid:
            raise NotImplementedError()

        case MetaTypeId.byte:
            assert isinstance(data, bytes), "This field is supposed to be `bytes`."

            type_bytes = int.to_bytes(MetaTypeId.byte, 1)
            len_bytes = int.to_bytes(len(data), 4)
            return type_bytes + len_bytes + data

        case MetaTypeId.int32:
            assert isinstance(data, int), "This field is supposed to be `int32`."
            assert -2**31 <= data < 2**31, "Values out of `int32` range."

            type_bytes = int.to_bytes(MetaTypeId.int32, 1)
            len_bytes = int.to_bytes(4, 4)
            return type_bytes + len_bytes + int.to_bytes(data, 4)

        case MetaTypeId.int64:
            assert isinstance(data, int), "This field is supposed to be `int32`."
            assert -2**63 <= data < 2**63, "Values out of `int32` range."

            type_bytes = int.to_bytes(MetaTypeId.int64, 1)
            len_bytes = int.to_bytes(8, 4)
            return type_bytes + len_bytes + int.to_bytes(data, 8)

        case MetaTypeId.string:
            assert isinstance(data, str), "This field is supposed to be `str`."

            type_bytes = int.to_bytes(MetaTypeId.string, 1)
            len_bytes = int.to_bytes(len(data), 4)
            return type_bytes + len_bytes + data.encode("utf-8")

        case MetaTypeId.float:
            raise NotImplementedError()
            # assert isinstance(data, float), "This field is supposed to be `float`."

            # type_bytes = int.to_bytes(MetaTypeId.float, 1)
            # len_bytes = int.to_bytes(4, 4)
            # return type_bytes + len_bytes + float.to_bytes(data, 4)

        case MetaTypeId.bool:
            assert isinstance(data, bool), "This field is supposed to be `bool`."

            type_bytes = int.to_bytes(MetaTypeId.bool, 1)
            len_bytes = int.to_bytes(1, 4)
            return type_bytes + len_bytes + int.to_bytes(data, 1)

        case MetaTypeId.object:
            type_bytes = int.to_bytes(MetaTypeId.object, 1)
            len_bytes = int.to_bytes(len(data), 4)
            return type_bytes + len_bytes + data.encode()

        case _:
            raise NotImplementedError(f"Unknown meta type: {meta_type}")


class BaseSekaiUdpClient:
    http_cli: SekaiClient
    _udp_cli: SekaiUdp | None = None

    @property
    def udp_cli(self) -> SekaiUdp:
        if self._udp_cli is None:
            raise RuntimeError("Udp client not initialized.")
        return self._udp_cli

    def create_udp_client(self, *args, **kwargs):
        """Create a new udp client.

        Will close and remove old udp client (if exists).
        """

        if self._udp_cli is not None:
            self._udp_cli.close_client()
            self._udp_cli = None

        self._udp_cli = SekaiUdp(*args, **kwargs)

