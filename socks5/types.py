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


from dataclasses import dataclass
from enum import Enum
from socket import socket
from struct import pack, unpack
from typing import Self


class Command(Enum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class AddressType(Enum):
    IPV4 = 0x01
    '''The address is a version-4 IP address, with a length of 4 octets.'''

    DOMAINNAME = 0x03
    '''The address field contains a fully-qualified domain name.  The first
    octet of the address field contains the number of octets of name that
    follow, there is no terminating NUL octet.'''

    IPV6 = 0x04
    '''The address is a version-6 IP address, with a length of 16 octets.'''


class AuthMethod(Enum):
    '''
    Values from 0x03 to 0x7F will be assigned by IANA.
    Values from 0x80 to 0xFE are reserved for private methods.
    '''

    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE_METHODS = 0xFF


class ReplyType(Enum):
    '''
    Values from 0x09 to 0xFF are reserved for private use.
    '''

    SUCCEEDED = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


@dataclass
class VersionIdentifier:
    '''
    The client connects to the server, and sends a version
    identifier/method selection message:
    '''

    ver: int
    '''The VER field is set to X'05' for this version of the protocol.'''

    nmethods: int
    '''The NMETHODS field contains the number of method identifier octets that
    appear in the METHODS field.'''

    methods: list[AuthMethod]
    '''The METHODS field contains a list of method identifiers that the client
    supports.'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ver = unpack('>B', data[0:1])[0]
        nmethods = unpack('>B', data[1:2])[0]

        if nmethods != len(data) - 2:
            raise ValueError('Invalid number of methods')

        return cls(
            ver=ver,
            nmethods=nmethods,
            methods=[AuthMethod(unpack('>B', data[2 + i:2 + i + 1])[0]) for i in range(nmethods)]
        )

    def to_bytes(self) -> bytes:
        return pack('>BB', self.ver, self.nmethods) + b''.join([pack('>B', method.value) for method in self.methods])


@dataclass
class MethodSelection:
    '''
    The server selects from one of the methods given in METHODS, and
    sends a METHOD selection message:
    '''

    ver: int
    '''The VER field is set to X'05' for this version of the protocol.'''

    method: AuthMethod
    '''The METHOD field contains the method selected by the server from the
    list of methods offered by the client.'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ver = unpack('>B', data[0:1])[0]
        method = AuthMethod(unpack('>B', data[1:2])[0])

        return cls(
            ver=ver,
            method=method
        )

    def to_bytes(self) -> bytes:
        return pack('>BB', self.ver, self.method.value)


@dataclass
class Request:
    '''
    Once the method-dependent subnegotiation has completed, the client
    sends the request details.  If the negotiated method includes
    encapsulation for purposes of integrity checking and/or
    confidentiality, these requests MUST be encapsulated in the method-
    dependent encapsulation.
    '''

    ver: int
    '''The VER field is set to X'05' for this version of the protocol.'''

    cmd: Command
    '''Command code.'''

    rsv: int
    '''Fields marked RESERVED (RSV) must be set to X'00'.'''

    atyp: AddressType
    '''Address type.'''

    dst_addr: bytes
    '''Desired destination address.'''

    dst_port: int
    '''Desired destination port in network octet order.'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ver = unpack('>B', data[0:1])[0]
        cmd = Command(unpack('>B', data[1:2])[0])
        rsv = unpack('>B', data[2:3])[0]
        atyp = AddressType(unpack('>B', data[3:4])[0])

        if atyp == AddressType.IPV4:
            dst_addr = data[4:8]
            dst_port = unpack('>H', data[8:10])[0]
        elif atyp == AddressType.DOMAINNAME:
            dst_addr_len = unpack('>B', data[4:5])[0]
            if dst_addr_len < 1 or dst_addr_len > 255:
                raise ValueError('Invalid domain name length')

            dst_addr = data[5:5 + dst_addr_len]
            dst_port = unpack('>H', data[5 + dst_addr_len:7 + dst_addr_len])[0]
        elif atyp == AddressType.IPV6:
            dst_addr = data[4:20]
            dst_port = unpack('>H', data[20:22])[0]

        return cls(
            ver=ver,
            cmd=cmd,
            rsv=rsv,
            atyp=atyp,
            dst_addr=dst_addr,
            dst_port=dst_port
        )

    def to_bytes(self) -> bytes:
        if self.atyp == AddressType.IPV4:
            return pack('>BBBB4sH', self.ver, self.cmd.value, self.rsv, self.atyp.value, self.dst_addr, self.dst_port)
        elif self.atyp == AddressType.DOMAINNAME:
            return pack('>BBBBB', self.ver, self.cmd.value, self.rsv, self.atyp.value, len(self.dst_addr)) + self.dst_addr + pack('>H', self.dst_port)
        elif self.atyp == AddressType.IPV6:
            return pack('>BBBB16sH', self.ver, self.cmd.value, self.rsv, self.atyp.value, self.dst_addr, self.dst_port)

        return b''

    def get_address_str(self) -> str:
        if self.atyp == AddressType.IPV4:
            return '.'.join([str(octet) for octet in self.dst_addr])
        elif self.atyp == AddressType.DOMAINNAME:
            return self.dst_addr.decode('utf-8')
        elif self.atyp == AddressType.IPV6:
            return ':'.join([hex(octet) for octet in self.dst_addr])

        return ''


@dataclass
class Reply:
    '''
    The SOCKS request information is sent by the client as soon as it has
    established a connection to the SOCKS server, and completed the
    authentication negotiations.  The server evaluates the request, and
    returns a reply formed as follows:
    '''

    ver: int
    '''The VER field is set to X'05' for this version of the protocol.'''

    rep: ReplyType
    '''reply field.'''

    rsv: int
    '''Fields marked RESERVED (RSV) must be set to X'00'.'''

    atyp: AddressType
    '''Address type.'''

    bnd_addr: bytes
    '''Server bound address.'''

    bnd_port: int
    '''Server bound port in network octet order.'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ver = unpack('>B', data[0:1])[0]
        rep = ReplyType(unpack('>B', data[1:2])[0])
        rsv = unpack('>B', data[2:3])[0]
        atyp = AddressType(unpack('>B', data[3:4])[0])

        if atyp == AddressType.IPV4:
            bnd_addr = data[4:8]
            bnd_port = unpack('>H', data[8:10])[0]
        elif atyp == AddressType.DOMAINNAME:
            bnd_addr_len = unpack('>B', data[4:5])[0]
            if bnd_addr_len < 1 or bnd_addr_len > 255:
                raise ValueError('Invalid domain name length')

            bnd_addr = data[5:5 + bnd_addr_len]
            bnd_port = unpack('>H', data[5 + bnd_addr_len:7 + bnd_addr_len])[0]
        elif atyp == AddressType.IPV6:
            bnd_addr = data[4:20]
            bnd_port = unpack('>H', data[20:22])[0]

        return cls(
            ver=ver,
            rep=rep,
            rsv=rsv,
            atyp=atyp,
            bnd_addr=bnd_addr,
            bnd_port=bnd_port
        )

    def to_bytes(self) -> bytes:
        if self.atyp == AddressType.IPV4:
            return pack('>BBBB4sH', self.ver, self.rep.value, self.rsv, self.atyp.value, self.bnd_addr, self.bnd_port)
        elif self.atyp == AddressType.DOMAINNAME:
            return pack('>BBBBB', self.ver, self.rep.value, self.rsv, self.atyp.value, len(self.bnd_addr)) + self.bnd_addr + pack('>H', self.bnd_port)
        elif self.atyp == AddressType.IPV6:
            return pack('>BBBB16sH', self.ver, self.rep.value, self.rsv, self.atyp.value, self.bnd_addr, self.bnd_port)

        return b''


@dataclass
class UDPRequest:
    '''
    A UDP-based client MUST send its datagrams to the UDP relay server at
    the UDP port indicated by BND.PORT in the reply to the UDP ASSOCIATE
    request.  If the selected authentication method provides
    encapsulation for the purposes of authenticity, integrity, and/or
    confidentiality, the datagram MUST be encapsulated using the
    appropriate encapsulation.  Each UDP datagram carries a UDP request
    header with it:
    '''

    rsv: int
    '''Fields marked RESERVED (RSV) must be set to X'00'.'''

    frag: int
    '''Current fragment number.'''

    atyp: AddressType
    '''Address type.'''

    dst_addr: bytes
    '''Desired destination address.'''

    dst_port: int
    '''Desired destination port.'''

    data: bytes
    '''User data.'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        rsv = unpack('>B', data[0:1])[0]
        frag = unpack('>B', data[1:2])[0]
        atyp = AddressType(unpack('>B', data[2:3])[0])

        if atyp == AddressType.IPV4:
            dst_addr = data[3:7]
            dst_port = unpack('>H', data[7:9])[0]
        elif atyp == AddressType.DOMAINNAME:
            dst_addr_len = unpack('>B', data[3:4])[0]
            if dst_addr_len < 1 or dst_addr_len > 255:
                raise ValueError('Invalid domain name length')

            dst_addr = data[4:4 + dst_addr_len]
            dst_port = unpack('>H', data[4 + dst_addr_len:6 + dst_addr_len])[0]
        elif atyp == AddressType.IPV6:
            dst_addr = data[3:19]
            dst_port = unpack('>H', data[19:21])[0]

        return cls(
            rsv=rsv,
            frag=frag,
            atyp=atyp,
            dst_addr=dst_addr,
            dst_port=dst_port,
            data=data[21:]
        )

    def to_bytes(self) -> bytes:
        if self.atyp == AddressType.IPV4:
            return pack('>BBB4sH', self.rsv, self.frag, self.atyp.value, self.dst_addr, self.dst_port) + self.data
        elif self.atyp == AddressType.DOMAINNAME:
            return pack('>BBB', self.rsv, self.frag, self.atyp.value) + pack('>B', len(self.dst_addr)) + self.dst_addr + pack('>H', self.dst_port) + self.data
        elif self.atyp == AddressType.IPV6:
            return pack('>BBB16sH', self.rsv, self.frag, self.atyp.value, self.dst_addr, self.dst_port) + self.data

        return b''

    def get_address_str(self) -> str:
        if self.atyp == AddressType.IPV4:
            return '.'.join([str(octet) for octet in self.dst_addr])
        elif self.atyp == AddressType.DOMAINNAME:
            return self.dst_addr.decode('utf-8')
        elif self.atyp == AddressType.IPV6:
            return ':'.join([hex(octet) for octet in self.dst_addr])

        return ''


def recv_or_none(sock: socket, size: int) -> bytes | None:
    try:
        return sock.recv(size)
    except:
        return None


def pack_address(atyp: AddressType, address: str) -> bytes:
    if atyp == AddressType.IPV4:
        return pack(">BBBB", *map(int, address.split(".")))
    elif atyp == AddressType.DOMAINNAME:
        return pack(f">{len(address)}s", address.encode("utf-8"))
    elif atyp == AddressType.IPV6:
        return pack(">BBBBBBBBBBBBBBBB", *map(int, address.split(":")))

    return b''
