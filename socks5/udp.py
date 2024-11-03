# Copyright 2024 Dhiego Cassiano Fogaça Barbosa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from select import select
from socket import AF_INET, SOCK_DGRAM, getaddrinfo, socket
from socketserver import ThreadingUDPServer, BaseRequestHandler
from struct import pack
from threading import Event
from typing import Callable

from socks5 import AddressType, UDPRequest, pack_address, recv_or_none
from socks5.auth import UsernameAuthRequest, UsernameAuthReply
from logger import Logger


class SocksUDPServer(ThreadingUDPServer):
    daemon_threads = True
    atyp = AddressType.IPV4
    bnd_addr = pack(">BBBB", 127, 0, 0, 1)
    bnd_port = 1080
    event: Event
    logger: Logger

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseRequestHandler],
        event: Event,
        logger: Logger,
        bind_and_activate: bool = True,
        *args, **kwargs
    ):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate, *args, **kwargs)
        self.atyp = AddressType.IPV4 if self.address_family == AF_INET else AddressType.IPV6
        self.bnd_addr = pack_address(self.atyp, server_address[0])
        self.bnd_port = server_address[1]
        self.event = event
        self.logger = logger

        self.logger.info(f"UDP listening on {self.server_address[0]}:{self.server_address[1]}")

    def service_actions(self) -> None:
        if self.event.is_set():
            self.logger.info("Closing UDP server...")
            self.server_close()


class UDPHandler(BaseRequestHandler):
    server: SocksUDPServer
    client_address: tuple[str, int]
    request: socket

    def handle(self) -> None:
        logger = self.server.logger

        logger.debug(f"Connection from {self.client_address}")
        while True:
            data = recv_or_none(self.request, 4096)
            if not data:
                return

            request = UDPRequest.from_bytes(data)
            logger.debug(f"{request=}")

            if request.atyp != AddressType.IPV4 and request.atyp != AddressType.DOMAINNAME and request.atyp != AddressType.IPV6:
                logger.debug(f"Unsupported address type {request.atyp}")
                continue

            try:
                for af, socktype, proto, canonname, sa in getaddrinfo(request.get_address_str(), request.dst_port):
                    connection = socket(af, SOCK_DGRAM)
                    connection.sendto(request.data, sa)
                    break
            except:
                logger.debug(f"Failed to connect to {request.get_address_str()}:{request.dst_port}")
                continue
