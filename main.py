# Copyright 2024 Dhiego Cassiano Fogaça Barbosa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from signal import SIGINT, signal
from threading import Event
from time import sleep

from socks5.tcp import SocksTCPServer, TCPHandler
from socks5.udp import SocksUDPServer, UDPHandler
from logger import LogLevel, Logger


event = Event()
logger = Logger(min_level=LogLevel.DEBUG)


def start_tcp_server(address: str, port: int) -> None:
    with SocksTCPServer((address, port),TCPHandler, event, logger) as server:
        server.serve_forever()


def start_udp_server(address: str, port: int) -> None:
    with SocksUDPServer((address, port),UDPHandler, event, logger) as server:
        server.serve_forever()


def main() -> None:
    arg_parser = ArgumentParser(description="A simple SOCKS5 server")
    arg_parser.add_argument("--address", default="0.0.0.0", type=str, help="The address to listen on")
    arg_parser.add_argument("--port", "-p", default=1080, type=int, help="The port to listen on")

    args = arg_parser.parse_args()

    signal(SIGINT, lambda sig, frame: event.set())

    with ThreadPoolExecutor() as executor:
        tcp_future = executor.submit(start_tcp_server, args.address, args.port)
        udp_future = executor.submit(start_udp_server, args.address, args.port)

        logger.info("Press Ctrl+C to exit.")
        try:
            while tcp_future.running() or udp_future.running():
                sleep(1)
        except KeyboardInterrupt:
            event.set()
            return


if __name__ == "__main__":
    main()
