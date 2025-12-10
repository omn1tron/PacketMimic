"""
PacketMimic Traffic Interceptor

Модуль для перехвата сетевого трафика и проверки авторизации через VPN
"""

import socket
import struct
import threading
import time
from typing import Set, Optional, Callable
from collections import defaultdict


class TrafficInterceptor:
    """Перехватчик сетевого трафика"""
    
    def __init__(self, interface: Optional[str] = None, authorized_ips: Optional[Set[str]] = None):
        """
        Инициализация перехватчика трафика
        
        Args:
            interface: Сетевой интерфейс для перехвата (None = все интерфейсы)
            authorized_ips: Множество авторизованных IP адресов (VPN клиентов)
        """
        self.interface = interface
        self.authorized_ips: Set[str] = authorized_ips or set()
        self.running = False
        self.raw_socket: Optional[socket.socket] = None
        self.blocked_packets = 0
        self.allowed_packets = 0
        self.packet_stats = defaultdict(int)
        self.callback: Optional[Callable] = None
        
    def add_authorized_ip(self, ip: str):
        """Добавление авторизованного IP адреса"""
        self.authorized_ips.add(ip)
    
    def remove_authorized_ip(self, ip: str):
        """Удаление авторизованного IP адреса"""
        self.authorized_ips.discard(ip)
    
    def set_callback(self, callback: Callable[[bytes, str, str], bool]):
        """
        Установка callback функции для обработки пакетов
        
        Args:
            callback: Функция принимающая (packet_data, src_ip, dst_ip) и возвращающая True для блокировки
        """
        self.callback = callback
    
    def start(self):
        """Запуск перехватчика трафика"""
        if self.running:
            return
        
        try:
            # Создание raw socket для перехвата IP пакетов
            # На Linux/Mac требуется права root
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Настройка для получения всех IP пакетов (Linux)
            try:
                if hasattr(socket, 'IP_HDRINCL'):
                    self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except (AttributeError, OSError):
                pass  # Не поддерживается на всех платформах
            
            # Привязка к интерфейсу (если указан)
            if self.interface:
                try:
                    self.raw_socket.bind((self.interface, 0))
                except Exception:
                    pass  # На некоторых системах bind не требуется
            
            self.running = True
            print(f"[Interceptor] Traffic interceptor started on interface {self.interface or 'all'}")
            
            # Запуск потока перехвата
            intercept_thread = threading.Thread(target=self._intercept_loop, daemon=True)
            intercept_thread.start()
            
        except PermissionError:
            print("[Interceptor] ERROR: Root privileges required for traffic interception")
            print("[Interceptor] Run with sudo or as administrator")
            self.running = False
        except Exception as e:
            print(f"[Interceptor] Error starting interceptor: {e}")
            self.running = False
    
    def _intercept_loop(self):
        """Основной цикл перехвата пакетов"""
        while self.running:
            try:
                # Чтение пакета (максимум 65535 байт)
                packet, addr = self.raw_socket.recvfrom(65535)
                
                if len(packet) < 20:  # Минимальный размер IP заголовка
                    continue
                
                # Парсинг IP заголовка
                ip_header = packet[:20]
                version_ihl = ip_header[0]
                version = (version_ihl >> 4) & 0x0F
                
                if version != 4:  # Только IPv4 для упрощения
                    continue
                
                # Извлечение адресов
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                
                # Проверка авторизации
                should_block = self._should_block_packet(packet, src_ip, dst_ip)
                
                if should_block:
                    self.blocked_packets += 1
                    self.packet_stats['blocked'] += 1
                    # Пакет блокируется (не пересылается дальше)
                    continue
                else:
                    self.allowed_packets += 1
                    self.packet_stats['allowed'] += 1
                
            except socket.error as e:
                if self.running:
                    print(f"[Interceptor] Socket error: {e}")
                break
            except Exception as e:
                if self.running:
                    print(f"[Interceptor] Error intercepting packet: {e}")
                time.sleep(0.1)
    
    def _should_block_packet(self, packet: bytes, src_ip: str, dst_ip: str) -> bool:
        """
        Определение, нужно ли блокировать пакет
        
        Args:
            packet: Данные пакета
            src_ip: IP адрес источника
            dst_ip: IP адрес назначения
            
        Returns:
            True если пакет должен быть заблокирован
        """
        # Проверка через callback (если установлен)
        if self.callback:
            try:
                if self.callback(packet, src_ip, dst_ip):
                    return True
            except Exception:
                pass
        
        # Блокировка трафика, не проходящего через VPN
        # Если IP не в списке авторизованных и не локальный
        if src_ip not in self.authorized_ips and not self._is_local_ip(src_ip):
            # Разрешаем только локальный трафик (loopback, private networks)
            if not self._is_local_ip(dst_ip):
                return True  # Блокируем внешний трафик от неавторизованных IP
        
        return False
    
    def _is_local_ip(self, ip: str) -> bool:
        """
        Проверка, является ли IP локальным
        
        Args:
            ip: IP адрес для проверки
            
        Returns:
            True если IP локальный
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first_octet = int(parts[0])
        second_octet = int(parts[1])
        
        # Loopback
        if first_octet == 127:
            return True
        
        # Private networks (RFC 1918)
        if first_octet == 10:
            return True
        if first_octet == 172 and 16 <= second_octet <= 31:
            return True
        if first_octet == 192 and second_octet == 168:
            return True
        
        # Link-local
        if first_octet == 169 and second_octet == 254:
            return True
        
        return False
    
    def get_stats(self) -> dict:
        """Получение статистики перехвата"""
        return {
            'blocked': self.blocked_packets,
            'allowed': self.allowed_packets,
            'total': self.blocked_packets + self.allowed_packets,
            'authorized_ips': len(self.authorized_ips),
            'stats': dict(self.packet_stats)
        }
    
    def stop(self):
        """Остановка перехватчика"""
        print("[Interceptor] Stopping traffic interceptor...")
        self.running = False
        
        if self.raw_socket:
            try:
                self.raw_socket.close()
            except Exception:
                pass
        
        stats = self.get_stats()
        print(f"[Interceptor] Statistics: {stats['blocked']} blocked, {stats['allowed']} allowed")


class PassiveInterceptor:
    """
    Пассивный перехватчик трафика (без блокировки)
    Используется для мониторинга без прав root
    """
    
    def __init__(self, authorized_ips: Optional[Set[str]] = None):
        """
        Инициализация пассивного перехватчика
        
        Args:
            authorized_ips: Множество авторизованных IP адресов
        """
        self.authorized_ips: Set[str] = authorized_ips or set()
        self.running = False
        self.blocked_count = 0
        self.allowed_count = 0
        self.callback: Optional[Callable] = None
    
    def add_authorized_ip(self, ip: str):
        """Добавление авторизованного IP адреса"""
        self.authorized_ips.add(ip)
    
    def remove_authorized_ip(self, ip: str):
        """Удаление авторизованного IP адреса"""
        self.authorized_ips.discard(ip)
    
    def check_packet(self, packet: bytes, src_ip: str, dst_ip: str) -> bool:
        """
        Проверка пакета (без перехвата)
        
        Args:
            packet: Данные пакета
            src_ip: IP адрес источника
            dst_ip: IP адрес назначения
            
        Returns:
            True если пакет должен быть заблокирован
        """
        # Проверка через callback
        if self.callback:
            try:
                if self.callback(packet, src_ip, dst_ip):
                    self.blocked_count += 1
                    return True
            except Exception:
                pass
        
        # Блокировка неавторизованного трафика
        if src_ip not in self.authorized_ips and not self._is_local_ip(src_ip):
            if not self._is_local_ip(dst_ip):
                self.blocked_count += 1
                return True
        
        self.allowed_count += 1
        return False
    
    def _is_local_ip(self, ip: str) -> bool:
        """Проверка, является ли IP локальным"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first_octet = int(parts[0])
        second_octet = int(parts[1])
        
        if first_octet == 127:
            return True
        if first_octet == 10:
            return True
        if first_octet == 172 and 16 <= second_octet <= 31:
            return True
        if first_octet == 192 and second_octet == 168:
            return True
        if first_octet == 169 and second_octet == 254:
            return True
        
        return False
    
    def get_stats(self) -> dict:
        """Получение статистики"""
        return {
            'blocked': self.blocked_count,
            'allowed': self.allowed_count,
            'total': self.blocked_count + self.allowed_count,
            'authorized_ips': len(self.authorized_ips)
        }

