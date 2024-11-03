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
from struct import pack, unpack
from typing import Self


@dataclass
class UsernameAuthRequest:
    '''
    Once the SOCKS V5 server has started, and the client has selected the
    Username/Password Authentication protocol, the Username/Password
    subnegotiation begins.  This begins with the client producing a
    Username/Password request:
    '''

    ver: int
    '''The VER field contains the current version of the subnegotiation,
    which is X'01'.'''

    ulen: int
    '''The ULEN field contains the length of the UNAME field in octets.'''

    uname: str
    '''The UNAME field contains the username as known to the source
    operating system.'''

    plen: int
    '''The PLEN field contains the length of the PASSWD field in octets.'''

    passwd: str
    '''The PASSWD field contains the password associated with the given
    UNAME.'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ver, ulen = unpack('>BB', data[:2])
        uname = data[2:2 + ulen].decode('utf-8')
        plen = unpack('>B', data[2 + ulen:3 + ulen])[0]
        passwd = data[2 + ulen + 1:].decode('utf-8')

        return cls(ver, ulen, uname, plen, passwd)

    def to_bytes(self) -> bytes:
        return pack('>BB', self.ver, self.ulen) + self.uname.encode('utf-8') + pack('>B', self.plen) + self.passwd.encode('utf-8')


@dataclass
class UsernameAuthReply:
    '''
    The server verifies the supplied UNAME and PASSWD, and sends the
    following response:
    '''

    ver: int
    '''The VER field contains the current version of the subnegotiation,
    which is X'01'.'''

    status: int
    '''The STATUS field contains one of:
    - X'00': success
    - X'01': failure'''

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ver, status = unpack('>BB', data)

        return cls(ver, status)

    def to_bytes(self) -> bytes:
        return pack('>BB', self.ver, self.status)
