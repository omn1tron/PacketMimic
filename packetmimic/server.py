"""
PacketMimic VPN Server

Сервер принимает подключения от клиентов и туннелирует IP трафик
"""

import socket
import struct
import threading
import select
import time
from typing import Dict, Optional, Set
from .protocol import PacketMimicProtocol, PacketType
from .traffic_interceptor import TrafficInterceptor, PassiveInterceptor
from .traffic_filter import TrafficFilter
from .obfuscator import TrafficObfuscator
from .tun import TunInterface


class ClientSession:
    """Сессия клиента на сервере"""
    
    def __init__(self, client_socket: socket.socket, client_id: bytes, protocol: PacketMimicProtocol):
        self.socket = client_socket
        self.client_id = client_id
        self.protocol = protocol
        self.connected = True
        self.last_keepalive = time.time()
        self.remote_addr = client_socket.getpeername()
    
    def send_data(self, ip_packet: bytes) -> bool:
        """Отправка IP пакета клиенту"""
        try:
            packet = self.protocol.create_data_packet(ip_packet)
            self.socket.sendall(struct.pack('!I', len(packet)) + packet)
            return True
        except Exception:
            return False
    
    def is_alive(self) -> bool:
        """Проверка активности соединения"""
        return self.connected and (time.time() - self.last_keepalive) < 60


class PacketMimicServer:
    """Сервер PacketMimic VPN"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 5555, password: str = 'default_password',
                 enable_interceptor: bool = True, rules_file: Optional[str] = None,
                 use_tun: bool = False, tun_name: str = 'packetmimic0',
                 enable_obfuscation: bool = True, obfuscation_method: str = 'tls'):
        """
        Инициализация сервера
        
        Args:
            host: Адрес для прослушивания
            port: Порт для прослушивания
            password: Пароль для аутентификации
            enable_interceptor: Включить перехват трафика
            rules_file: Путь к файлу с правилами фильтрации
            use_tun: Использовать TUN интерфейс для реального туннелирования
            tun_name: Имя TUN интерфейса
        """
        self.host = host
        self.port = port
        self.password = password
        self.protocol = PacketMimicProtocol(password)
        self.server_socket: Optional[socket.socket] = None
        self.clients: Dict[bytes, ClientSession] = {}
        self.running = False
        self.tun_interface: Optional[TunInterface] = None
        
        # Инициализация перехватчика и фильтра трафика
        self.enable_interceptor = enable_interceptor
        self.authorized_ips: Set[str] = set()
        self.traffic_filter = TrafficFilter(rules_file, authorized_ips=self.authorized_ips)
        self.interceptor: Optional[TrafficInterceptor] = None
        self.passive_interceptor = PassiveInterceptor(self.authorized_ips)
        self.use_tun = use_tun
        self.tun_name = tun_name
        
        # Инициализация обфускатора для обхода DPI
        self.obfuscator = TrafficObfuscator(enabled=enable_obfuscation, method=obfuscation_method)
        
        # Настройка callback для фильтра
        self.traffic_filter.set_alert_callback(self._on_alert)
        
    def start(self):
        """Запуск сервера"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.server_socket.setblocking(False)
        
        self.running = True
        print(f"[Server] PacketMimic VPN Server started on {self.host}:{self.port}")
        
        # Запуск перехватчика трафика
        if self.enable_interceptor:
            self._start_interceptor()

        # Запуск TUN интерфейса (если включен)
        if self.use_tun:
            self._start_tun()
        
        # Запуск обработки подключений
        accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        accept_thread.start()
        
        # Запуск обработки данных от клиентов
        process_thread = threading.Thread(target=self._process_clients, daemon=True)
        process_thread.start()
        
        # Запуск keepalive
        keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        keepalive_thread.start()
        
        # Запуск статистики
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def _accept_connections(self):
        """Принятие новых подключений"""
        while self.running:
            try:
                readable, _, _ = select.select([self.server_socket], [], [], 1.0)
                if readable:
                    client_socket, addr = self.server_socket.accept()
                    print(f"[Server] New connection from {addr}")
                    
                    # Запуск обработки клиента
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket,),
                        daemon=True
                    )
                    client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[Server] Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: socket.socket):
        """Обработка подключения клиента"""
        client_id = None
        try:
            client_socket.settimeout(30)
            
            # Чтение handshake
            length_data = client_socket.recv(4)
            if len(length_data) != 4:
                client_socket.close()
                return
            
            packet_length = struct.unpack('!I', length_data)[0]
            handshake_data = client_socket.recv(packet_length)
            
            if len(handshake_data) != packet_length:
                client_socket.close()
                return
            
            # Деобфускация handshake перед парсингом
            deobfuscated_handshake = self.obfuscator.deobfuscate_packet(handshake_data)
            packet_type, payload = self.protocol.parse_packet(deobfuscated_handshake)
            
            if packet_type != PacketType.HANDSHAKE or payload is None:
                client_socket.close()
                return
            
            # Извлечение client_id
            client_id_len = payload[0]
            client_id = payload[1:1+client_id_len]
            
            # Проверка аутентификации (упрощенная - по паролю)
            # В реальной системе здесь должна быть проверка сертификатов/ключей
            
            # Отправка ответа с обфускацией
            response = self.protocol.create_handshake_response(True, b'PacketMimicServer')
            obfuscated_response = self.obfuscator.obfuscate_packet(response)
            client_socket.sendall(struct.pack('!I', len(obfuscated_response)) + obfuscated_response)
            
            # Создание сессии (передаем обфускатор для отправки данных)
            session = ClientSession(client_socket, client_id, self.protocol)
            session.obfuscator = self.obfuscator  # Добавляем обфускатор в сессию
            self.clients[client_id] = session
            
            # Добавление IP клиента в список авторизованных
            client_ip = client_socket.getpeername()[0]
            self.authorized_ips.add(client_ip)
            self.passive_interceptor.add_authorized_ip(client_ip)
            if self.interceptor:
                self.interceptor.add_authorized_ip(client_ip)
            
            print(f"[Server] Client {client_id.hex()[:8]} authenticated from {client_ip}")
            
            # Обработка данных от клиента
            self._process_client_data(session)
            
        except Exception as e:
            print(f"[Server] Error handling client: {e}")
        finally:
            if client_id and client_id in self.clients:
                session = self.clients[client_id]
                # Удаление IP из авторизованных при отключении
                if hasattr(session, 'remote_addr'):
                    client_ip = session.remote_addr[0]
                    self.authorized_ips.discard(client_ip)
                    self.passive_interceptor.remove_authorized_ip(client_ip)
                    if self.interceptor:
                        self.interceptor.remove_authorized_ip(client_ip)
                del self.clients[client_id]
            client_socket.close()
    
    def _process_client_data(self, session: ClientSession):
        """Обработка данных от клиента"""
        while session.connected and self.running:
            try:
                # Чтение длины пакета
                length_data = session.socket.recv(4)
                if len(length_data) != 4:
                    break
                
                packet_length = struct.unpack('!I', length_data)[0]
                if packet_length > 65536:  # Защита от больших пакетов
                    break
                
                # Чтение пакета
                packet_data = b''
                while len(packet_data) < packet_length:
                    chunk = session.socket.recv(packet_length - len(packet_data))
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
                    # Пересылка IP пакета в сеть
                    if payload and self.protocol.validate_ip_packet(payload):
                        self._forward_ip_packet(payload)
                
                elif packet_type == PacketType.KEEPALIVE:
                    session.last_keepalive = time.time()
                    # Отправка keepalive обратно с обфускацией
                    keepalive = self.protocol.create_keepalive()
                    obfuscated_keepalive = self.obfuscator.obfuscate_packet(keepalive)
                    session.socket.sendall(struct.pack('!I', len(obfuscated_keepalive)) + obfuscated_keepalive)
                
                elif packet_type == PacketType.DISCONNECT:
                    session.connected = False
                    break
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Server] Error processing client data: {e}")
                break
        
        session.connected = False
    
    def _process_clients(self):
        """Обработка всех клиентов (для чтения из TUN интерфейса)"""
        # В реальной реализации здесь будет чтение из TUN интерфейса
        # и пересылка пакетов клиентам
        while self.running:
            time.sleep(0.01)
            if self.tun_interface:
                packet = self.tun_interface.read_packet()
                if packet:
                    # Отправить пакет всем активным клиентам
                    for session in list(self.clients.values()):
                        if session.connected:
                            session.send_data(packet)
    
    def _forward_ip_packet(self, ip_packet: bytes):
        """Пересылка IP пакета в сеть"""
        # Проверка пакета через фильтр
        if len(ip_packet) >= 20:
            src_ip = socket.inet_ntoa(ip_packet[12:16])
            dst_ip = socket.inet_ntoa(ip_packet[16:20])
            
            should_block, matched_rule = self.traffic_filter.check_packet(ip_packet, src_ip, dst_ip)
            
            if should_block:
                print(f"[Server] Blocked packet from {src_ip} to {dst_ip} (rule: {matched_rule.name if matched_rule else 'default'})")
                return  # Блокируем пакет
        
        # Отправка пакета в TUN интерфейс, если он включён
        if self.tun_interface:
            self.tun_interface.write_packet(ip_packet)
            return

        # Заглушка для случая без TUN (никаких действий)
        pass
    
    def _keepalive_loop(self):
        """Отправка keepalive пакетов"""
        while self.running:
            time.sleep(30)
            
            # Удаление неактивных клиентов
            inactive_clients = [
                client_id for client_id, session in self.clients.items()
                if not session.is_alive()
            ]
            
            for client_id in inactive_clients:
                print(f"[Server] Removing inactive client {client_id.hex()[:8]}")
                session = self.clients[client_id]
                session.connected = False
                session.socket.close()
                del self.clients[client_id]
            
            # Отправка keepalive активным клиентам
            for session in list(self.clients.values()):
                if session.connected:
                    try:
                        keepalive = self.protocol.create_keepalive()
                        obfuscated_keepalive = self.obfuscator.obfuscate_packet(keepalive)
                        session.socket.sendall(struct.pack('!I', len(obfuscated_keepalive)) + obfuscated_keepalive)
                    except Exception:
                        session.connected = False
    
    def _start_interceptor(self):
        """Запуск перехватчика трафика"""
        try:
            self.interceptor = TrafficInterceptor(authorized_ips=self.authorized_ips)
            # Настройка callback для проверки через фильтр
            self.interceptor.set_callback(self._interceptor_callback)
            self.interceptor.start()
        except Exception as e:
            print(f"[Server] Failed to start interceptor: {e}")
            print("[Server] Using passive interceptor mode")
            self.interceptor = None
    
    def _interceptor_callback(self, packet: bytes, src_ip: str, dst_ip: str) -> bool:
        """
        Callback для перехватчика - проверка пакета через фильтр
        
        Returns:
            True если пакет должен быть заблокирован
        """
        should_block, _ = self.traffic_filter.check_packet(packet, src_ip, dst_ip)
        return should_block
    
    def _on_alert(self, rule, packet: bytes, src_ip: str, dst_ip: str):
        """Обработка алерта от фильтра"""
        print(f"[Server] ALERT: Suspicious traffic detected - {src_ip} -> {dst_ip}")
    
    def _stats_loop(self):
        """Цикл вывода статистики"""
        while self.running:
            time.sleep(60)  # Каждую минуту
            if self.running:
                self._print_stats()
    
    def _print_stats(self):
        """Вывод статистики"""
        filter_stats = self.traffic_filter.get_stats()
        print(f"\n[Server] Statistics:")
        print(f"  Clients: {len(self.clients)}")
        print(f"  Authorized IPs: {len(self.authorized_ips)}")
        print(f"  Filter - Total: {filter_stats['total_checked']}, Blocked: {filter_stats['blocked']}, Allowed: {filter_stats['allowed']}, Alerts: {filter_stats['alerts']}")
        if self.interceptor:
            interceptor_stats = self.interceptor.get_stats()
            print(f"  Interceptor - Blocked: {interceptor_stats['blocked']}, Allowed: {interceptor_stats['allowed']}")
    
    def stop(self):
        """Остановка сервера"""
        print("[Server] Stopping server...")
        self.running = False
        
        if self.interceptor:
            self.interceptor.stop()

        if self.tun_interface:
            self.tun_interface.close()
        
        if self.server_socket:
            self.server_socket.close()
        
        for session in self.clients.values():
            session.connected = False
            session.socket.close()
        
        self.clients.clear()
        
        # Вывод финальной статистики
        self._print_stats()
        print("[Server] Server stopped")

    def _start_tun(self):
        """Запуск TUN интерфейса (Linux only)."""
        try:
            self.tun_interface = TunInterface(name=self.tun_name, kind="tun")
            print(f"[Server] TUN interface up: {self.tun_interface.name}")
            print("  Настройте IP/маршруты вручную, пример:")
            print(f"    sudo ip link set dev {self.tun_interface.name} up")
            print(f"    sudo ip addr add 10.10.0.1/24 dev {self.tun_interface.name}")
            print(f"    sudo iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -j MASQUERADE")
            print(f"    sudo sysctl -w net.ipv4.ip_forward=1")
        except Exception as e:
            print(f"[Server] Failed to start TUN: {e}")
            self.tun_interface = None


if __name__ == '__main__':
    import sys
    
    password = sys.argv[1] if len(sys.argv) > 1 else 'default_password'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5555
    
    server = PacketMimicServer(port=port, password=password)
    server.start()

