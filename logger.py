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
from datetime import datetime
from enum import Enum


class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    ALERT = 6
    EMERGENCY = 7


@dataclass
class Logger:
    '''
    The Logger class is a simple logging interface that defines the basic
    methods for logging messages.
    '''
    min_level: LogLevel = LogLevel.DEBUG

    def emergency(self, message: str) -> None:
        '''
        System is unusable.
        '''
        self._log(LogLevel.EMERGENCY, message)

    def alert(self, message: str) -> None:
        '''
        Action must be taken immediately.
        '''
        self._log(LogLevel.ALERT, message)

    def critical(self, message: str) -> None:
        '''
        Critical conditions.
        '''
        self._log(LogLevel.CRITICAL, message)

    def error(self, message: str) -> None:
        '''
        Error conditions.
        '''
        self._log(LogLevel.ERROR, message)

    def warning(self, message: str) -> None:
        '''
        Warning conditions.
        '''
        self._log(LogLevel.WARNING, message)

    def notice(self, message: str) -> None:
        '''
        Normal but significant condition.
        '''
        self._log(LogLevel.NOTICE, message)

    def info(self, message: str) -> None:
        '''
        Informational messages.
        '''
        self._log(LogLevel.INFO, message)

    def debug(self, message: str) -> None:
        '''
        Debug-level messages.
        '''
        self._log(LogLevel.DEBUG, message)

    def _log(self, level: LogLevel, message: str) -> None:
        '''
        Log a message with a given level.
        '''

        if level.value < self.min_level.value:
            return

        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{time}] [{level.name}] {message}')
