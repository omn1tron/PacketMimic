"""
PacketMimic Traffic Obfuscation Module

Обфускация трафика для обхода DPI (Deep Packet Inspection)
Маскирует VPN пакеты под обычный HTTPS трафик
"""

import struct
import random
import hashlib
from typing import Tuple


class TrafficObfuscator:
    """Обфускатор трафика для обхода DPI"""
    
    def __init__(self, enabled: bool = True, method: str = 'tls'):
        """
        Инициализация обфускатора
        
        Args:
            enabled: Включить обфускацию
            method: Метод обфускации ('tls', 'http', 'random')
        """
        self.enabled = enabled
        self.method = method
        self.tls_version = b'\x03\x03'  # TLS 1.2
        self.random_padding = True
    
    def obfuscate_packet(self, encrypted_data: bytes) -> bytes:
        """
        Обфускация зашифрованного пакета
        
        Args:
            encrypted_data: Зашифрованные данные VPN пакета
            
        Returns:
            Обфусцированные данные, выглядящие как HTTPS трафик
        """
        if not self.enabled:
            return encrypted_data
        
        if self.method == 'tls':
            return self._tls_obfuscation(encrypted_data)
        elif self.method == 'http':
            return self._http_obfuscation(encrypted_data)
        elif self.method == 'random':
            return self._random_obfuscation(encrypted_data)
        else:
            return encrypted_data
    
    def deobfuscate_packet(self, obfuscated_data: bytes) -> bytes:
        """
        Деобфускация пакета
        
        Args:
            obfuscated_data: Обфусцированные данные
            
        Returns:
            Оригинальные зашифрованные данные
        """
        if not self.enabled:
            return obfuscated_data
        
        if self.method == 'tls':
            return self._tls_deobfuscation(obfuscated_data)
        elif self.method == 'http':
            return self._http_deobfuscation(obfuscated_data)
        elif self.method == 'random':
            return self._random_deobfuscation(obfuscated_data)
        else:
            return obfuscated_data
    
    def _tls_obfuscation(self, data: bytes) -> bytes:
        """
        Обфускация под TLS handshake (выглядит как HTTPS)
        
        Структура:
        - TLS Record Header (5 bytes): Type + Version + Length
        - TLS Handshake Header (4 bytes)
        - Оригинальные данные
        - Random padding (если включен)
        """
        # TLS Record Type: 0x17 = Application Data (зашифрованное)
        # Используем 0x17 чтобы выглядело как зашифрованный TLS трафик
        record_type = b'\x17'
        
        # TLS Version (TLS 1.2)
        version = self.tls_version
        
        # Размер данных (включая padding)
        padding_size = random.randint(0, 32) if self.random_padding else 0
        total_length = len(data) + padding_size + 4  # +4 для handshake header
        
        # TLS Record Header
        record_header = record_type + version + struct.pack('!H', total_length)
        
        # TLS Handshake Header (маскируем под ClientHello/ServerHello)
        # Type (1) + Length (3)
        handshake_type = b'\x16'  # Handshake
        handshake_length = struct.pack('!I', len(data) + padding_size)[1:]  # 3 bytes
        
        # Оригинальные данные
        obfuscated = record_header + handshake_type + handshake_length + data
        
        # Добавляем random padding для маскировки размера
        if padding_size > 0:
            padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
            obfuscated += padding
        
        return obfuscated
    
    def _tls_deobfuscation(self, data: bytes) -> bytes:
        """Деобфускация TLS-подобного пакета"""
        if len(data) < 9:
            return data
        
        # Пропускаем TLS Record Header (5 bytes)
        # Пропускаем Handshake Header (4 bytes)
        header_size = 9
        
        # Извлекаем длину из TLS Record
        if len(data) >= 5:
            record_length = struct.unpack('!H', data[3:5])[0]
            # Извлекаем длину из Handshake Header
            if len(data) >= 9:
                handshake_length = struct.unpack('!I', b'\x00' + data[6:9])[0]
                # Возвращаем данные без заголовков
                if len(data) >= header_size + handshake_length:
                    return data[header_size:header_size + handshake_length]
                elif len(data) > header_size:
                    # Если padding был обрезан, возвращаем что есть
                    return data[header_size:]
        
        return data[header_size:] if len(data) > header_size else data
    
    def _http_obfuscation(self, data: bytes) -> bytes:
        """
        Обфускация под HTTP запрос/ответ
        Выглядит как обычный HTTPS трафик через HTTP CONNECT
        """
        # Случайный выбор: HTTP запрос или ответ
        if random.random() < 0.5:
            # HTTP запрос
            method = random.choice([b'GET', b'POST', b'PUT', b'PATCH'])
            path = b'/' + bytes([random.randint(97, 122) for _ in range(random.randint(5, 15))])
            http_header = f"{method.decode()} {path.decode()} HTTP/1.1\r\n".encode()
            http_header += b"Host: " + self._random_hostname() + b"\r\n"
            http_header += b"Connection: keep-alive\r\n"
            http_header += b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n"
        else:
            # HTTP ответ
            status_code = random.choice([200, 304, 404])
            http_header = f"HTTP/1.1 {status_code} OK\r\n".encode()
            http_header += b"Content-Length: " + str(len(data)).encode() + b"\r\n"
            http_header += b"Connection: keep-alive\r\n\r\n"
        
        # Base64-like обфускация данных (не реальный base64, но похоже)
        encoded_data = self._simple_encode(data)
        
        return http_header + encoded_data
    
    def _http_deobfuscation(self, data: bytes) -> bytes:
        """Деобфускация HTTP-подобного пакета"""
        # Ищем конец HTTP заголовков
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            return data
        
        # Извлекаем данные после заголовков
        payload = data[header_end + 4:]
        return self._simple_decode(payload)
    
    def _random_obfuscation(self, data: bytes) -> bytes:
        """Случайная обфускация с padding"""
        # Добавляем случайный префикс и суффикс
        prefix_size = random.randint(8, 32)
        suffix_size = random.randint(8, 32)
        
        prefix = bytes([random.randint(0, 255) for _ in range(prefix_size)])
        suffix = bytes([random.randint(0, 255) for _ in range(suffix_size)])
        
        # Длина данных в середине
        length_header = struct.pack('!I', len(data))
        
        return prefix + length_header + data + suffix
    
    def _random_deobfuscation(self, data: bytes) -> bytes:
        """Деобфускация случайно обфусцированного пакета"""
        if len(data) < 36:  # минимум 8+4+data+8
            return data
        
        # Пропускаем префикс (8-32 bytes, берем среднее значение 16)
        prefix_size = 16
        if len(data) > prefix_size + 4:
            length = struct.unpack('!I', data[prefix_size:prefix_size+4])[0]
            data_start = prefix_size + 4
            data_end = data_start + length
            
            if data_end <= len(data):
                return data[data_start:data_end]
        
        return data
    
    def _random_hostname(self) -> bytes:
        """Генерация случайного hostname"""
        domains = [
            b'google.com', b'youtube.com', b'facebook.com', b'instagram.com',
            b'twitter.com', b'reddit.com', b'github.com', b'stackoverflow.com',
            b'amazon.com', b'cloudflare.com', b'cdn.com', b'cdnjs.com'
        ]
        return random.choice(domains)
    
    def _simple_encode(self, data: bytes) -> bytes:
        """
        Простое кодирование (не реальный base64, но похоже для обфускации)
        На самом деле просто добавляем некоторые изменения для маскировки
        """
        # Добавляем случайные байты между блоками
        if len(data) < 100:
            return data
        
        encoded = b''
        chunk_size = 64
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            encoded += chunk
            if i + chunk_size < len(data):
                # Добавляем случайный разделитель
                encoded += bytes([random.randint(65, 90)])  # A-Z
        
        return encoded
    
    def _simple_decode(self, data: bytes) -> bytes:
        """Простое декодирование"""
        # Убираем случайные разделители (A-Z между блоками по 64 байта)
        decoded = b''
        chunk_size = 64
        i = 0
        
        while i < len(data):
            chunk_end = min(i + chunk_size, len(data))
            chunk = data[i:chunk_end]
            decoded += chunk
            i = chunk_end
            
            # Пропускаем разделитель если есть
            if i < len(data) and 65 <= data[i] <= 90:
                i += 1
        
        return decoded
    
    def enable(self):
        """Включить обфускацию"""
        self.enabled = True
    
    def disable(self):
        """Отключить обфускацию"""
        self.enabled = False
    
    def set_method(self, method: str):
        """Изменить метод обфускации"""
        if method in ['tls', 'http', 'random']:
            self.method = method

