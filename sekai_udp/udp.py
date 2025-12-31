import asyncio
from collections import defaultdict
from collections.abc import Callable, Coroutine
from enum import IntEnum
import socket
import struct
import time
from typing import Any, TypeVar, override

from .log import colorlog, dump_binary, logger
from .utils import (
    ByteSlicer,
    decrypt_aes,
    encrypt_aes,
    sign_sha256,
    stringlist_to_bytes,
    wrap_sync,
)

_SERVER_H = "<LR><b> < </></>"  # head
_CLIENT_H = "<LE><b> > </></>"

_SERVER_T = "<LR><b> | </></>"  # trail
_CLIENT_T = "<LE><b> | </></>"

_SERVER_E = "<LR><b> = </></>"  # end
_CLIENT_E = "<LE><b> = </></>"

T = TypeVar("T")
type SyncCallbackType[T] = Callable[[int, bytes], T]
type AsyncCallbackType[T] = Callable[[int, bytes], Coroutine[None, None, T]]
type CallbackType[T] = SyncCallbackType[T] | AsyncCallbackType[T]

type RSendSyncCallbackType[T] = Callable[[bytes], T]
type RSendAsyncCallbackType[T] = Callable[[bytes], Coroutine[None, None, T]]
type RSendCallbackType[T] = RSendSyncCallbackType[T] | RSendAsyncCallbackType[T]

class ResponsePacketStatus(IntEnum):
    ok = 1
    bad = 4
    err = 5
    change_server = 255 # not sure


class SekaiUdp(asyncio.DatagramProtocol):
    udpHost: str
    udpPort: int

    sid: str
    clientKey: str
    encryptionKey: str
    encryptionIv: str
    encryptionMacKey: str
    protocol_para: dict

    socket_timeout: float

    _transport: asyncio.DatagramTransport | None
    @property
    def transport(self) -> asyncio.DatagramTransport:
        if self._transport is None:
            raise RuntimeError("Udp Client is not set. Ensure the client is started.")
        return self._transport

    _synced: asyncio.Event | None
    @property
    def synced(self) -> asyncio.Event:
        if self._synced is None:
            raise RuntimeError("Sync event is not set. Ensure the client is started.")
        return self._synced

    _seq: int
    _local_addr: str
    _client_ack: set[int] # Client packet seq (receive seq ack from server)
    _server_ack: set[int]

    _bg_tasks: set[asyncio.Task]

    def run_in_background(self, func: Callable[..., Coroutine[None, None, Any]], *args, **kwarg):
        task = asyncio.create_task(func(*args, **kwarg))
        task.add_done_callback(self._bg_tasks.discard)
        self._bg_tasks.add(task)

    # region: network
    _event_callbacks: dict[bytes, list[AsyncCallbackType[Any]]]
    @override
    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        self.synced.set()

        if len(data) < 4:
            logger.warning(f"Received packet too short: {dump_binary(data)}")
            return

        seq = int.from_bytes(data[:1])
        flag = data[2:4]

        colorlog.debug(
            f"{_SERVER_H} Received packet: <fg #808080>({seq = }, flag = 0x{flag.hex()})</>\n{ \
              dump_binary(data)}"
        )

        for callback in self._event_callbacks[b"00"]:
            self.run_in_background(callback, seq, data[4:])

        for callback in self._event_callbacks.get(flag, []):
            self.run_in_background(callback, seq, data[4:])


    def register_event_callback(self, header: bytes, callback: CallbackType[Any]):
        """Register a callback for a specific header when receiving packets.

        To trigger callbacks on all received data, put the header as b"00".
        """

        self._event_callbacks[header].append(wrap_sync(callback))

    @override
    def error_received(self, exc):
        colorlog.error(f"Error received when connecting with server: {exc}")
        self.close_client()

    @override
    def connection_made(self, transport):
        logger.debug("Socket connected successfully.")

    @override
    def connection_lost(self, exc):
        logger.debug("Socket closed, stop the event loop.")

    async def start_client(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        local_addr = str(s.getsockname()[0])

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=("0.0.0.0", 0),
        )
        self._transport = transport
        local_port = self.transport.get_extra_info("sockname")[1]
        self._local_addr = f"{local_addr}:{local_port}"

        logger.debug(f"Local UDP connection: {local_addr}:{local_port}")

    def close_client(self):
        """Gracefully close udp client

        **Do not** open it again after you close it. Reopen with a same para dict if you need.
        """

        if self._transport is None:
            return

        for task in self._bg_tasks:
            task.cancel()

        self._transport.close()
        self._transport = None
        logger.debug("UDP client stopped.")

    # endregion

    # region: low level methods
    # We follow C# naming convention for all the method if it is intended to imitate game's udp client sdk behavior
    # All these methods will use async defination even though it may not really be needed
    def send(
            self,
            flag: int | bytes,
            data: bytes,
            *,
            seq: int = -1,
            increase_seq: bool = True,
            remove_sync: bool = False
        ) -> int:
        """Send an UDP packet to the destination host.

        This method will only add `seq` and `flag` before the data and then directly send it to the udp host.  
        If you need to send msgpack data you probably need `SekaiUdp.RSend` instead of `SekaiUdp.send`.  

        Return client send seq.
        """  # noqa: W291

        if isinstance(flag, int):
            flag = int.to_bytes(flag, 2)
        flag_header = flag

        if seq == -1:
            seq = self._seq
        seq_header = int.to_bytes(seq, 2, byteorder="little")

        if remove_sync and seq == 0:    # syn packet confict with rsend when start connection (seq = 0)
            self._client_ack.discard(0)

        packet = seq_header + flag_header + data

        if self.transport.is_closing():
            raise ConnectionError("Udp client closed.")
        self.transport.sendto(packet, (self.udpHost, self.udpPort))

        colorlog.debug(
            f"{_CLIENT_H} Send packet: <fg #808080>(seq = {seq}, flag = 0x{flag.hex()})</>\n{dump_binary(packet)}"
        )

        if increase_seq:
            self._seq += 1

        return seq

    async def RSend(self, ver: int, cmd: int, payload: bytes):
        """Send data to server reliably.

        Usually used when sending custom data.
        """

        encrypted_payload = encrypt_aes(
            payload, bytes.fromhex(self.encryptionKey), bytes.fromhex(self.encryptionIv),
            trailing_zero = True
        )

        rsend_header = bytes.fromhex("febedeef")
        ver_b = int.to_bytes(ver, 1)
        cmd_b = int.to_bytes(cmd, 2)
        sid = bytes.fromhex(self.sid)
        data_size = int.to_bytes(len(payload), 4)
        signature = sign_sha256(encrypted_payload, bytes.fromhex(self.encryptionMacKey))

        packet = sid + data_size + signature + encrypted_payload
        packet_size = int.to_bytes(len(packet), 3)

        full_packet = rsend_header + ver_b + packet_size + cmd_b + packet
        send_seq = self.send(3, full_packet, remove_sync = True)

        colorlog.trace(f"{_CLIENT_T} Send RSend message (raw):\n{dump_binary(payload)}")

        # RSend retry
        async def retry():
            await asyncio.sleep(1.5)
            retry_count = 3
            while send_seq not in self._client_ack and retry_count > 0:
                colorlog.trace(
                    f"{_CLIENT_T} Send RSend (Retry) message <fg #808080>(seq = { \
                        send_seq}, retry_left = {retry_count}</>)"
                )
                self.send(5, full_packet, seq = send_seq, increase_seq = False)
                await asyncio.sleep(1)

            if send_seq not in self._client_ack:
                raise ConnectionAbortedError("Unable to send RUDP packet to server. Connection closed.")

        self.run_in_background(retry)

    async def rcv_ack(self, seq: int, data: bytes):
        colorlog.trace(f"{_SERVER_T} Will handle by <b><r>Ack</></> event")
        self._client_ack.add(seq)

    _rsend_callbacks: dict[tuple[int, int], list[RSendCallbackType[Any]]]  # (ver, cmd) -> callback
    async def rcv_rsend(self, seq: int, data: bytes):
        colorlog.trace(f"{_SERVER_T} Will handle by <b><r>RSend</></> event")
        packet = ByteSlicer(data)

        rsend_header = packet.bslice(4)
        ver = packet.bslice(1)
        packet_size = packet.bslice(3)  # noqa: F841, this variable really useless
        cmd = packet.bslice(2)
        status = packet.bslice(1)
        payload_size = packet.bslice(4)
        signature = packet.bslice(32)
        encryped_payload = packet.remain()

        if rsend_header.hex() != "febedeef":
            colorlog.warning(f"{_SERVER_E} Invalid RSend packet, this packet will be ignored. (Header mismatch)")
            return

        if signature != sign_sha256(encryped_payload, bytes.fromhex(self.encryptionMacKey)):
            colorlog.warning(f"{_SERVER_E} Invalid RSend packet, this packet will be ignored. (Signature mismatch)")
            return

        if int.from_bytes(status) not in [ResponsePacketStatus.ok, ResponsePacketStatus.change_server]:
            colorlog.error(f"{_SERVER_E} Error from server: ret code: ({ResponsePacketStatus(int.from_bytes(status))})")
            raise ConnectionError("Invalid udp request")

        payload = decrypt_aes(encryped_payload, bytes.fromhex(self.encryptionKey), bytes.fromhex(self.encryptionIv))
        payload = payload[:int.from_bytes(payload_size)]

        ver = int.from_bytes(ver)
        cmd = int.from_bytes(cmd)

        colorlog.debug(f"{_SERVER_T} RSend message: <fg #808080>({ver = }, {cmd = })</>\n{dump_binary(payload)}")

        for callback in self._rsend_callbacks.get((ver, cmd), []):
            self.run_in_background(callback, payload)

        self._server_ack.add(seq)
        await self.SendAck(seq)

    async def rcv_rsend_retry(self, seq: int, data: bytes):
        colorlog.trace(f"{_SERVER_T} Will handle by <b><r>RSend (Retry)</></> event")

        if seq in self._server_ack:
            colorlog.trace(f"{_SERVER_E} Packet already been received, will ignore it. <fg #808080>({seq = })</>")
            await self.SendAck(seq)
            return

        await self.rcv_rsend(seq, data)

    def register_rsend_callback(self, ver: int | str, cmd: int | str, callback: RSendCallbackType[Any]):
        """Register a callback for a specific ver and cmd when receiving RSend packets.

        Can pass int and hex string to `ver` and `cmd`.
        """

        ver = int(ver, 16) if isinstance(ver, str) else ver
        cmd = int(cmd, 16) if isinstance(cmd, str) else cmd

        self._rsend_callbacks[(ver, cmd)].append(wrap_sync(callback))

    def register_rsend_async(self, ver: int | str, cmd: int | str, callback: RSendCallbackType[T]) -> asyncio.Future[T]:
        """Register an awaitable object, will give you the most recent received RSend packets.

        It will return packet data and only return once when receiving satisfied packets.  
        Be aware that it will return the newest satisfied packet **after** you register it.  
        It's recommand to register it before any operation.
        """  # noqa: W291

        ver = int(ver, 16) if isinstance(ver, str) else ver
        cmd = int(cmd, 16) if isinstance(cmd, str) else cmd

        future = asyncio.get_event_loop().create_future()

        async def _cb(payload: bytes):
            if not future.done():
                future.set_result(await wrap_sync(callback)(payload))

            self._rsend_callbacks[(ver, cmd)].remove(_cb)

        self._rsend_callbacks[(ver, cmd)].append(_cb)
        return future

    # endregion

    # region: application methods
    async def SendSyn(self):
        """Send sync packet to server.

        Usually used when establishing a new connection with server.  
        Will exit when server has any response, or close client after timeout.
        """  # noqa: W291

        self.synced.clear()

        async def _send_sync():
            while not self.synced.is_set():
                self.send(2, bytes.fromhex(self.sid), increase_seq = False)
                await asyncio.sleep(0.1)

        try:
            await asyncio.wait_for(_send_sync(), timeout=self.socket_timeout)
        except TimeoutError:
            self.close_client()
            colorlog.warning("Sync operation timed out, client closed.")

    async def SendFin(self):
        """Send sync packet to server.

        Usually used when gracefully disconnecting from server.
        """

        seq = self.send(7, bytes.fromhex(self.sid), increase_seq = False)

        colorlog.trace(f"{_CLIENT_E} Type: <b><e>SendFin</></>")
        return seq

    async def SendClientKey(self):
        """Send client key to server"""

        await self.RSend(0, 4, self.clientKey.encode("utf-8"))

        colorlog.trace(f"{_CLIENT_E} Type: <b><e>SendClientKey</></>")

    async def SendEcho(self):
        """Send echo packet to server

        Packet format: | milisecond timestamp | pack([local_ip_addr]) |
        """

        timestamp_mili_b = struct.pack("<d", time.time() * 1000)
        await self.RSend(0, 1, timestamp_mili_b + stringlist_to_bytes([self._local_addr]))

        colorlog.trace(f"{_CLIENT_E} Type: <b><e>SendEchoInternal</></>")

    async def SendAck(self, seq: int):
        """Send ack packet to server when received data packet."""

        self.send(4, bytes.fromhex(self.sid), seq = seq, increase_seq = False)

    # endregion
    def __init__(self, socket_timeout: float = 5.0):
        self.socket_timeout = socket_timeout
        self._event_callbacks = defaultdict(list)
        self._rsend_callbacks = defaultdict(list)
        self._synced = asyncio.Event()
        self._bg_tasks = set()
        self._client_ack = set()
        self._server_ack = set()
        self._seq = 0

    def setup(
            self,
            udpHost: str | None = None,
            udpPort: int | None = None,
            sid: str | None = None,
            clientKey: str | None = None,
            encryptionKey: str | None = None,
            encryptionIv: str | None = None,
            encryptionMacKey: str | None = None,
            *,
            protocol_para: dict = {}
        ):
        """Initialize the udp client with necessary parameters.

        You can choose either assign parameters or pass a dict contains it. (Cannot be both)
        """

        require_keys = ("udpHost", "udpPort", "sid", "clientKey", "encryptionKey", "encryptionIv", "encryptionMacKey")

        if not protocol_para:
            protocol_para["udpHost"] = udpHost
            protocol_para["udpPort"] = udpPort
            protocol_para["sid"] = sid
            protocol_para["clientKey"] = clientKey
            protocol_para["encryptionKey"] = encryptionKey
            protocol_para["encryptionIv"] = encryptionIv
            protocol_para["encryptionMacKey"] = encryptionMacKey

        self.protocol_para = protocol_para
        for key in require_keys:
            if key not in protocol_para:
                continue

            if protocol_para[key] is None:
                raise KeyError(f"Parameter {key} cannot be None.")
            setattr(self, key, protocol_para[key])

        self.register_event_callback(bytes.fromhex("0004"), self.rcv_ack)
        self.register_event_callback(bytes.fromhex("0003"), self.rcv_rsend)
        self.register_event_callback(bytes.fromhex("0005"), self.rcv_rsend_retry)
