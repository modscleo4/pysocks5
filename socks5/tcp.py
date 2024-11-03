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
from socket import AF_INET, create_connection, socket, timeout, gaierror
from socketserver import ThreadingTCPServer, BaseRequestHandler
from struct import pack
from threading import Event
from typing import Callable

from socks5 import AddressType, AuthMethod, Command, ReplyType, VersionIdentifier, MethodSelection, Request, Reply, pack_address, recv_or_none
from socks5.auth import UsernameAuthRequest, UsernameAuthReply
from logger import Logger

class SocksTCPServer(ThreadingTCPServer):
    daemon_threads = True
    atyp = AddressType.IPV4
    bnd_addr = pack(">BBBB", 127, 0, 0, 1)
    bnd_port = 1080
    stop_event: Event
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
        self.stop_event = event
        self.logger = logger

        self.logger.info(f"TCP listening on {self.server_address[0]}:{self.server_address[1]}")


    def service_actions(self) -> None:
        if self.stop_event.is_set():
            self.logger.info("Closing TCP server...")
            self.server_close()


class TCPHandler(BaseRequestHandler):
    server: SocksTCPServer
    client_address: tuple[str, int]
    request: socket


    def handle(self) -> None:
        logger = self.server.logger

        logger.debug(f"Connection from {self.client_address}")
        data = recv_or_none(self.request, 257)
        if not data:
            return

        version_identifier = VersionIdentifier.from_bytes(data)
        logger.debug(f"{version_identifier=}")

        if version_identifier.ver != 5:
            logger.debug("Invalid version identifier")
            return

        if version_identifier.nmethods == 0:
            logger.debug("No authentication methods provided")
            return

        encrypt = lambda data: data
        decrypt = lambda data: data

        if AuthMethod.USERNAME_PASSWORD in version_identifier.methods:
            logger.debug("Using username/password authentication")
            self.request.send(MethodSelection(5, AuthMethod.USERNAME_PASSWORD).to_bytes())

            data = recv_or_none(self.request, 513)
            if not data:
                return

            authRequest = UsernameAuthRequest.from_bytes(data)
            logger.debug(f"{authRequest=}")

            if authRequest.uname == "admin" and authRequest.passwd == "admin":
                self.request.send(UsernameAuthReply(1, 0).to_bytes())
            else:
                self.request.send(UsernameAuthReply(1, 1).to_bytes())
                return
        else:
            self.request.send(MethodSelection(5, AuthMethod.NO_AUTHENTICATION_REQUIRED).to_bytes())

        data = recv_or_none(self.request, 261)
        if not data:
            return

        request = Request.from_bytes(data)
        logger.debug(f"{request=}")

        if request.atyp != AddressType.IPV4 and request.atyp != AddressType.DOMAINNAME and request.atyp != AddressType.IPV6:
            logger.debug(f"Unsupported address type {request.atyp}")
            self.request.send(Reply(5, ReplyType.ADDRESS_TYPE_NOT_SUPPORTED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
            return

        if request.cmd == Command.CONNECT:
            try:
                connection = create_connection((request.get_address_str(), request.dst_port))
                logger.debug(f"Connected to {request.get_address_str()}:{request.dst_port}")

                self.request.send(Reply(5, ReplyType.SUCCEEDED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
            except gaierror:
                logger.debug(f"Failed to resolve {request.get_address_str()}")
                self.request.send(Reply(5, ReplyType.HOST_UNREACHABLE, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                return
            except timeout:
                logger.debug(f"Connection to {request.get_address_str()}:{request.dst_port} timed out")
                self.request.send(Reply(5, ReplyType.TTL_EXPIRED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                return
            except Exception as e:
                logger.debug(f"Failed to connect to {request.get_address_str()}:{request.dst_port}")
                self.request.send(Reply(5, ReplyType.CONNECTION_REFUSED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                return
        elif request.cmd == Command.BIND:
            try:
                connection = create_connection((request.get_address_str(), request.dst_port))
                logger.debug(f"Connected to {request.get_address_str()}:{request.dst_port}")

                self.request.send(Reply(5, ReplyType.SUCCEEDED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                self.request.send(Reply(5, ReplyType.SUCCEEDED, 0, request.atyp, request.dst_addr, request.dst_port).to_bytes())
            except gaierror:
                logger.debug(f"Failed to resolve {request.get_address_str()}")
                self.request.send(Reply(5, ReplyType.HOST_UNREACHABLE, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                return
            except timeout:
                logger.debug(f"Connection to {request.get_address_str()}:{request.dst_port} timed out")
                self.request.send(Reply(5, ReplyType.TTL_EXPIRED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                return
            except Exception as e:
                logger.debug(f"Failed to connect to {request.get_address_str()}:{request.dst_port}")
                self.request.send(Reply(5, ReplyType.CONNECTION_REFUSED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
                return
        elif request.cmd == Command.UDP_ASSOCIATE:
            logger.debug(f"Serving UDP requests on {self.client_address}")
            self.request.send(Reply(5, ReplyType.SUCCEEDED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
            return
        else:
            self.request.send(Reply(5, ReplyType.COMMAND_NOT_SUPPORTED, 0, self.server.atyp, self.server.bnd_addr, self.server.bnd_port).to_bytes())
            return

        self.wait_for_data(self.request, connection, encrypt, decrypt)


    def finish(self) -> None:
        logger = self.server.logger

        logger.debug(f"Connection from {self.client_address} closed")
        return super().finish()


    @staticmethod
    def wait_for_data(client: socket, server: socket, encrypt: Callable[[bytes], bytes], decrypt: Callable[[bytes], bytes]) -> None:
        while True:
            rlist, _, _ = select([client, server], [], [])

            try:
                if client in rlist:
                    data = client.recv(4096)
                    if server.send(data) <= 0:
                        break
                elif server in rlist:
                    data = server.recv(4096)
                    if client.send(data) <= 0:
                        break
            except:
                break
