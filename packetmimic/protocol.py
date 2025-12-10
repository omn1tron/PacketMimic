"""
PacketMimic VPN Protocol Implementation

Протокол PacketMimic обеспечивает:
- Инкапсуляцию IP пакетов
- Шифрование данных (AES-256-GCM)
- Аутентификацию клиентов
- Управление соединениями
"""

import struct
import hashlib
from enum import IntEnum
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os


class PacketType(IntEnum):
    """Типы пакетов протокола PacketMimic"""
    HANDSHAKE = 0x01
    HANDSHAKE_RESPONSE = 0x02
    DATA = 0x03
    KEEPALIVE = 0x04
    DISCONNECT = 0x05
    ERROR = 0x06


class PacketMimicProtocol:
    """Реализация протокола PacketMimic"""
    
    # Заголовок пакета: версия(1) + тип(1) + длина(2) + nonce(12) + tag(16) = 32 байта
    HEADER_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    VERSION = 1
    
    def __init__(self, password: str):
        """
        Инициализация протокола с паролем
        
        Args:
            password: Пароль для генерации ключа шифрования
        """
        self.password = password.encode('utf-8')
        self.cipher: Optional[AESGCM] = None
        self._derive_key()
    
    def _derive_key(self):
        """Генерация ключа шифрования из пароля"""
        salt = b'PacketMimicVPN2024'  # Фиксированная соль для упрощения
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.password)
        self.cipher = AESGCM(key)
    
    def create_handshake(self, client_id: bytes) -> bytes:
        """
        Создание пакета handshake
        
        Args:
            client_id: Уникальный идентификатор клиента
            
        Returns:
            Зашифрованный пакет handshake
        """
        payload = struct.pack('!B', len(client_id)) + client_id
        return self._encrypt_packet(PacketType.HANDSHAKE, payload)
    
    def create_handshake_response(self, success: bool, server_id: bytes = b'') -> bytes:
        """
        Создание ответа на handshake
        
        Args:
            success: Успешность handshake
            server_id: Идентификатор сервера
            
        Returns:
            Зашифрованный пакет ответа
        """
        payload = struct.pack('!B', 1 if success else 0) + server_id
        return self._encrypt_packet(PacketType.HANDSHAKE_RESPONSE, payload)
    
    def create_data_packet(self, ip_packet: bytes) -> bytes:
        """
        Создание пакета данных с инкапсуляцией IP пакета
        
        Args:
            ip_packet: Исходный IP пакет для туннелирования
            
        Returns:
            Зашифрованный пакет данных
        """
        return self._encrypt_packet(PacketType.DATA, ip_packet)
    
    def create_keepalive(self) -> bytes:
        """Создание keepalive пакета"""
        return self._encrypt_packet(PacketType.KEEPALIVE, b'')
    
    def create_disconnect(self, reason: str = '') -> bytes:
        """
        Создание пакета отключения
        
        Args:
            reason: Причина отключения
        """
        payload = reason.encode('utf-8')
        return self._encrypt_packet(PacketType.DISCONNECT, payload)
    
    def create_error(self, error_code: int, message: str = '') -> bytes:
        """
        Создание пакета ошибки
        
        Args:
            error_code: Код ошибки
            message: Сообщение об ошибке
        """
        payload = struct.pack('!B', error_code) + message.encode('utf-8')
        return self._encrypt_packet(PacketType.ERROR, payload)
    
    def _encrypt_packet(self, packet_type: PacketType, payload: bytes) -> bytes:
        """
        Шифрование пакета
        
        Args:
            packet_type: Тип пакета
            payload: Данные для шифрования
            
        Returns:
            Зашифрованный пакет с заголовком
        """
        # Генерация nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Шифрование данных
        plaintext = struct.pack('!B', packet_type) + payload
        ciphertext = self.cipher.encrypt(nonce, plaintext, None)
        
        # Разделение ciphertext на данные и tag
        encrypted_data = ciphertext[:-self.TAG_SIZE]
        tag = ciphertext[-self.TAG_SIZE:]
        
        # Формирование заголовка: версия(1) + тип(1) + длина(2) + nonce(12) + tag(16)
        length = len(encrypted_data)
        header = struct.pack('!BBH', self.VERSION, packet_type, length)
        
        return header + nonce + tag + encrypted_data
    
    def parse_packet(self, data: bytes) -> Tuple[Optional[PacketType], Optional[bytes]]:
        """
        Парсинг и расшифровка пакета
        
        Args:
            data: Полученные данные
            
        Returns:
            Кортеж (тип_пакета, расшифрованные_данные) или (None, None) при ошибке
        """
        if len(data) < self.HEADER_SIZE:
            return None, None
        
        try:
            # Парсинг заголовка
            version, packet_type, length = struct.unpack('!BBH', data[:4])
            nonce = data[4:4+self.NONCE_SIZE]
            tag = data[4+self.NONCE_SIZE:4+self.NONCE_SIZE+self.TAG_SIZE]
            encrypted_data = data[4+self.NONCE_SIZE+self.TAG_SIZE:4+self.NONCE_SIZE+self.TAG_SIZE+length]
            
            if version != self.VERSION:
                return None, None
            
            # Восстановление ciphertext
            ciphertext = encrypted_data + tag
            
            # Расшифровка
            plaintext = self.cipher.decrypt(nonce, ciphertext, None)
            
            # Извлечение типа и payload
            decrypted_type = PacketType(plaintext[0])
            payload = plaintext[1:]
            
            return decrypted_type, payload
            
        except Exception as e:
            return None, None
    
    @staticmethod
    def generate_client_id() -> bytes:
        """Генерация уникального идентификатора клиента"""
        return os.urandom(16)
    
    @staticmethod
    def validate_ip_packet(packet: bytes) -> bool:
        """
        Валидация IP пакета
        
        Args:
            packet: Данные пакета
            
        Returns:
            True если пакет валиден
        """
        if len(packet) < 20:  # Минимальный размер IP заголовка
            return False
        
        # Проверка версии IP (должна быть 4 или 6)
        version = (packet[0] >> 4) & 0x0F
        return version == 4 or version == 6


