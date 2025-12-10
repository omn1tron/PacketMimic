"""
PacketMimic VPN Client

Клиент подключается к серверу и туннелирует IP трафик
"""

import socket
import threading
import time
import struct
from typing import Optional
from .protocol import PacketMimicProtocol, PacketType
from .traffic_filter import TrafficFilter
from .tun import TunInterface
from .traffic_filter import TrafficFilter


class PacketMimicClient:
    """Клиент PacketMimic VPN"""
    
    def __init__(self, server_host: str, server_port: int, password: str,
                 rules_file: Optional[str] = None, use_tun: bool = False, tun_name: str = 'packetmimic0'):
        """
        Инициализация клиента
        
        Args:
            server_host: Адрес сервера
            server_port: Порт сервера
            password: Пароль для аутентификации
            rules_file: Путь к файлу с правилами фильтрации
            use_tun: Использовать TUN интерфейс
            tun_name: Имя TUN интерфейса
        """
        self.server_host = server_host
        self.server_port = server_port
        self.password = password
        self.protocol = PacketMimicProtocol(password)
        self.client_id = self.protocol.generate_client_id()
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.running = False
        self.tun_interface: Optional[TunInterface] = None
        
        # Инициализация фильтра трафика
        self.traffic_filter = TrafficFilter(rules_file)
        self.use_tun = use_tun
        self.tun_name = tun_name

    def _start_tun(self):
        """Запуск TUN интерфейса (Linux only)."""
        try:
            self.tun_interface = TunInterface(name=self.tun_name, kind="tun")
            print(f"[Client] TUN interface up: {self.tun_interface.name}")
            print("  Настройте IP/маршруты вручную, пример:")
            print(f"    sudo ip link set dev {self.tun_interface.name} up")
            print(f"    sudo ip addr add 10.10.0.2/24 dev {self.tun_interface.name}")
            print(f"    sudo ip route add default dev {self.tun_interface.name}")
        except Exception as e:
            print(f"[Client] Failed to start TUN: {e}")
            self.tun_interface = None
    
    def connect(self) -> bool:
        """
        Подключение к серверу
        
        Returns:
            True если подключение успешно
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.socket.settimeout(10)
            
            # Отправка handshake
            handshake = self.protocol.create_handshake(self.client_id)
            self.socket.sendall(struct.pack('!I', len(handshake)) + handshake)
            
            # Получение ответа
            length_data = self.socket.recv(4)
            if len(length_data) != 4:
                return False
            
            packet_length = struct.unpack('!I', length_data)[0]
            response_data = self.socket.recv(packet_length)
            
            if len(response_data) != packet_length:
                return False
            
            packet_type, payload = self.protocol.parse_packet(response_data)
            
            if packet_type != PacketType.HANDSHAKE_RESPONSE or payload is None:
                return False
            
            success = payload[0] == 1
            if not success:
                return False
            
            self.connected = True
            self.socket.settimeout(None)
            print(f"[Client] Connected to {self.server_host}:{self.server_port}")
            return True
            
        except Exception as e:
            print(f"[Client] Connection error: {e}")
            return False
    
    def start(self):
        """Запуск клиента"""
        if not self.connect():
            print("[Client] Failed to connect to server")
            return
        
        self.running = True
        if self.use_tun:
            self._start_tun()
        
        # Запуск обработки данных от сервера
        receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        receive_thread.start()
        
        # Запуск keepalive
        keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        keepalive_thread.start()
        
        # Запуск чтения из TUN интерфейса
        tun_thread = threading.Thread(target=self._tun_read_loop, daemon=True)
        tun_thread.start()
        
        try:
            while self.running and self.connected:
                time.sleep(1)
        except KeyboardInterrupt:
            self.disconnect()
    
    def _receive_loop(self):
        """Обработка данных от сервера"""
        while self.running and self.connected:
            try:
                # Чтение длины пакета
                length_data = self.socket.recv(4)
                if len(length_data) != 4:
                    break
                
                packet_length = struct.unpack('!I', length_data)[0]
                if packet_length > 65536:
                    break
                
                # Чтение пакета
                packet_data = b''
                while len(packet_data) < packet_length:
                    chunk = self.socket.recv(packet_length - len(packet_data))
                    if not chunk:
                        break
                    packet_data += chunk
                
                if len(packet_data) != packet_length:
                    break
                
                # Парсинг пакета
                packet_type, payload = self.protocol.parse_packet(packet_data)
                
                if packet_type is None:
                    continue
                
                if packet_type == PacketType.DATA:
                    # Пересылка IP пакета в TUN интерфейс
                    if payload and self.protocol.validate_ip_packet(payload):
                        self._forward_to_tun(payload)
                
                elif packet_type == PacketType.KEEPALIVE:
                    # Игнорируем keepalive, просто подтверждаем соединение
                    pass
                
                elif packet_type == PacketType.DISCONNECT:
                    print("[Client] Server requested disconnect")
                    self.connected = False
                    break
                
                elif packet_type == PacketType.ERROR:
                    if payload:
                        error_code = payload[0]
                        error_msg = payload[1:].decode('utf-8', errors='ignore')
                        print(f"[Client] Server error {error_code}: {error_msg}")
                    self.connected = False
                    break
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[Client] Receive error: {e}")
                break
        
        self.connected = False
    
    def _keepalive_loop(self):
        """Отправка keepalive пакетов"""
        while self.running and self.connected:
            time.sleep(30)
            if self.connected:
                try:
                    keepalive = self.protocol.create_keepalive()
                    self.socket.sendall(struct.pack('!I', len(keepalive)) + keepalive)
                except Exception:
                    self.connected = False
    
    def _tun_read_loop(self):
        """Чтение IP пакетов из TUN интерфейса"""
        # В реальной реализации здесь будет чтение из TUN интерфейса
        # и отправка пакетов на сервер
        while self.running and self.connected:
            time.sleep(0.01)
            if self.tun_interface:
                packet = self.tun_interface.read_packet()
                if packet:
                    self.send_ip_packet(packet)
    
    def send_ip_packet(self, ip_packet: bytes) -> bool:
        """
        Отправка IP пакета на сервер
        
        Args:
            ip_packet: IP пакет для отправки
            
        Returns:
            True если отправка успешна
        """
        if not self.connected or not self.socket:
            return False
        
        try:
            if not self.protocol.validate_ip_packet(ip_packet):
                return False
            
            # Проверка пакета через фильтр перед отправкой
            if len(ip_packet) >= 20:
                src_ip = socket.inet_ntoa(ip_packet[12:16])
                dst_ip = socket.inet_ntoa(ip_packet[16:20])
                
                should_block, matched_rule = self.traffic_filter.check_packet(ip_packet, src_ip, dst_ip)
                
                if should_block:
                    print(f"[Client] Blocked outgoing packet to {dst_ip} (rule: {matched_rule.name if matched_rule else 'default'})")
                    return False  # Блокируем пакет
            
            packet = self.protocol.create_data_packet(ip_packet)
            self.socket.sendall(struct.pack('!I', len(packet)) + packet)
            return True
        except Exception as e:
            print(f"[Client] Error sending packet: {e}")
            self.connected = False
            return False
    
    def _forward_to_tun(self, ip_packet: bytes):
        """Пересылка IP пакета в TUN интерфейс"""
        # Проверка входящего пакета через фильтр
        if len(ip_packet) >= 20:
            src_ip = socket.inet_ntoa(ip_packet[12:16])
            dst_ip = socket.inet_ntoa(ip_packet[16:20])
            
            should_block, matched_rule = self.traffic_filter.check_packet(ip_packet, src_ip, dst_ip)
            
            if should_block:
                print(f"[Client] Blocked incoming packet from {src_ip} (rule: {matched_rule.name if matched_rule else 'default'})")
                return  # Блокируем пакет
        
        # В реальной реализации здесь будет запись в TUN интерфейс
        if self.tun_interface:
            self.tun_interface.write_packet(ip_packet)
            return
        # Заглушка: без TUN просто игнорируем
        pass
    
    def disconnect(self):
        """Отключение от сервера"""
        print("[Client] Disconnecting...")
        self.running = False
        self.connected = False
        
        if self.tun_interface:
            self.tun_interface.close()
        
        if self.socket:
            try:
                disconnect_packet = self.protocol.create_disconnect("Client disconnect")
                self.socket.sendall(struct.pack('!I', len(disconnect_packet)) + disconnect_packet)
            except Exception:
                pass
            
            self.socket.close()
            self.socket = None
        
        print("[Client] Disconnected")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python -m packetmimic.client <server_host> <server_port> [password] [use_tun]")
        sys.exit(1)
    
    server_host = sys.argv[1]
    server_port = int(sys.argv[2])
    password = sys.argv[3] if len(sys.argv) > 3 else 'default_password'
    use_tun = bool(int(sys.argv[4])) if len(sys.argv) > 4 else False
    
    client = PacketMimicClient(server_host, server_port, password, use_tun=use_tun)
    client.start()

