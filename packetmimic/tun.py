"""
PacketMimic TUN/TAP utilities (Linux-focused)

Создание и работа с TUN интерфейсом для туннелирования IP трафика.
Требуются права root. Поддержка Linux; для macOS/Windows пока не реализована.
"""

import os
import fcntl
import struct
import platform
from typing import Optional

# Константы для ioctl (Linux)
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


class TunInterface:
    """Простейшая обёртка над TUN интерфейсом (Linux)."""

    def __init__(self, name: str = "packetmimic0", kind: str = "tun", mtu: int = 1500):
        """
        Создаёт TUN/TAP интерфейс.

        Args:
            name: желаемое имя интерфейса (ядро может подменить)
            kind: 'tun' или 'tap'
            mtu: MTU интерфейса
        """
        self.name = name
        self.kind = kind
        self.mtu = mtu
        self.fd: Optional[int] = None

        system = platform.system().lower()
        if system != "linux":
            raise OSError("TUN/TAP supported only on Linux for now")

        self._open()

    def _open(self):
        flags = IFF_NO_PI | (IFF_TUN if self.kind == "tun" else IFF_TAP)
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifreq = struct.pack("16sH", self.name.encode(), flags)
        res = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)
        self.name = struct.unpack("16sH", res)[0].rstrip(b"\x00").decode()
        # Установка MTU (через sysctl/ip должен сделать пользователь; здесь только сохраняем значение)

    def fileno(self) -> int:
        if self.fd is None:
            raise OSError("TUN interface not open")
        return self.fd

    def read_packet(self, max_len: int = 65535) -> Optional[bytes]:
        if self.fd is None:
            return None
        try:
            return os.read(self.fd, max_len)
        except BlockingIOError:
            return None
        except OSError:
            return None

    def write_packet(self, data: bytes) -> bool:
        if self.fd is None:
            return False
        try:
            os.write(self.fd, data)
            return True
        except OSError:
            return False

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            finally:
                self.fd = None



