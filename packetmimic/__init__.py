"""
PacketMimic VPN Protocol

Современный VPN протокол для безопасного туннелирования IP трафика
"""

from .protocol import PacketMimicProtocol, PacketType
from .server import PacketMimicServer
from .client import PacketMimicClient
from .traffic_interceptor import TrafficInterceptor, PassiveInterceptor
from .traffic_filter import TrafficFilter, FilterRule, Action
from .obfuscator import TrafficObfuscator
from .tun import TunInterface

__version__ = '1.0.0'
__all__ = [
    'PacketMimicProtocol', 'PacketType',
    'PacketMimicServer', 'PacketMimicClient',
    'TrafficInterceptor', 'PassiveInterceptor',
    'TrafficFilter', 'FilterRule', 'Action',
    'TunInterface'
]

