import asyncio
from functools import partial, wraps
import struct
from typing import Callable, Coroutine, Literal, ParamSpec, TypeVar, overload, override

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import msgpack

# https://github.com/nonebot/nonebot2/blob/7eaf581762480629e0fba8fa47663b57a5967a76/nonebot/utils.py#L174
P = ParamSpec("P")
R = TypeVar("R")

def wrap_sync[**P, R](call: Callable[P, R]) -> Callable[P, Coroutine[None, None, R]]:
    """一个用于包装 sync function 为 async function 的装饰器

    参数:
        call: 被装饰的任意同步或异步函数
    """

    if asyncio.iscoroutinefunction(call):
        return call

    @wraps(call)
    async def _wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        return await asyncio.to_thread(partial(call, *args, **kwargs))

    return _wrapper


def serialize_msgpack(dict: dict) -> bytes | None:
    return b"" if dict is None else msgpack.packb(dict)

@overload
def deserialize_msgpack(data: bytes, multi_msg: Literal[False] = False) -> dict: ...
@overload
def deserialize_msgpack(data: bytes, multi_msg: Literal[True]) -> list[dict]: ...

def deserialize_msgpack(data: bytes, multi_msg: bool = False) -> list[dict] | dict:
    if not multi_msg:
        return msgpack.unpackb(data, strict_map_key=False)

    items: list[dict] = []
    offset = 0
    total_len = len(data)

    # 4 bytes (int as msgpack data size) | msgpack data
    while offset + 4 <= total_len:
        size = int.from_bytes(data[offset : offset + 4])
        if size < 0 or offset + 4 + size > total_len:
            items.clear()
            break

        chunk = data[offset + 4 : offset + 4 + size]
        items.append(msgpack.unpackb(chunk, strict_map_key=False))
        offset += 4 + size

    if items and offset == total_len:
        return items

    return [msgpack.unpackb(data, strict_map_key=False)]

def encrypt_aes(plaintext: bytes, key: bytes, iv: bytes, trailing_zero: bool = False) -> bytes:
    if trailing_zero:
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        padded = plaintext + b"\x00" * padding_length
    else:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext

def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes, do_unpad: bool = False) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    if do_unpad:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plain) + unpadder.finalize()
        return plaintext
    else:
        return padded_plain

def pack_request(data: dict, key: bytes, iv: bytes) -> bytes | None:
    pack = serialize_msgpack(data)
    assert pack is not None, "Data cannot be None"
    return encrypt_aes(pack, key, iv)

def unpack_response(data: bytes, key: bytes, iv: bytes) -> dict | None:
    return deserialize_msgpack(decrypt_aes(data, key, iv))

def sign_sha256(data: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def stringlist_to_bytes(string_list: list[str]):
    buf = bytearray()

    for s in string_list:
        encoded = s.encode("utf-8")
        buf += struct.pack(">I", len(encoded))
        buf += encoded

    return buf

class ByteSlicer:
    """Easy wrapper for slicing continuous bytes"""

    _bytes: bytes

    def __init__(self, raw: bytes):
        self._bytes = raw

    def bslice(self, length: int) -> bytes:
        """Equivalent to ret = raw[:length], raw = raw[length:]"""

        result = self._bytes[:length]
        self._bytes = self._bytes[length:]
        return result

    def remain(self) -> bytes:
        return self._bytes
