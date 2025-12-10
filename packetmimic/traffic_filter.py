"""
PacketMimic Traffic Filter (Snort-like)

Система правил фильтрации трафика для обнаружения и блокировки подозрительного трафика
"""

import re
import struct
from enum import IntEnum
from typing import List, Optional, Callable, Tuple, Set
from dataclasses import dataclass


class Action(IntEnum):
    """Действие при срабатывании правила"""
    ALLOW = 0
    BLOCK = 1
    LOG = 2
    ALERT = 3


@dataclass
class FilterRule:
    """Правило фильтрации трафика"""
    name: str
    action: Action
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # 'TCP', 'UDP', 'ICMP', etc.
    payload_pattern: Optional[bytes] = None  # Паттерн для поиска в payload
    enabled: bool = True
    
    def __post_init__(self):
        """Валидация правила после инициализации"""
        if self.src_ip:
            self.src_ip = self._normalize_ip(self.src_ip)
        if self.dst_ip:
            self.dst_ip = self._normalize_ip(self.dst_ip)
    
    @staticmethod
    def _normalize_ip(ip: str) -> str:
        """Нормализация IP адреса (поддержка CIDR)"""
        # Поддержка CIDR нотации (например, 192.168.1.0/24)
        if '/' in ip:
            return ip  # CIDR будет обрабатываться отдельно
        return ip


class TrafficFilter:
    """Фильтр трафика с поддержкой правил (аналог Snort)"""
    
    def __init__(self, rules_file: Optional[str] = None, authorized_ips: Optional[Set[str]] = None):
        """
        Инициализация фильтра
        
        Args:
            rules_file: Путь к файлу с правилами
            authorized_ips: Набор авторизованных IP (например, VPN-клиенты)
        """
        self.rules: List[FilterRule] = []
        self.stats = {
            'total_checked': 0,
            'blocked': 0,
            'allowed': 0,
            'alerts': 0,
            'rule_matches': {}
        }
        self.alert_callback: Optional[Callable] = None
        self.authorized_ips: Set[str] = authorized_ips or set()
        
        if rules_file:
            self.load_rules(rules_file)
        else:
            self._load_default_rules()
    
    def add_rule(self, rule: FilterRule):
        """Добавление правила фильтрации"""
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str):
        """Удаление правила по имени"""
        self.rules = [r for r in self.rules if r.name != rule_name]
    
    def enable_rule(self, rule_name: str):
        """Включение правила"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
    
    def disable_rule(self, rule_name: str):
        """Отключение правила"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
    
    def _load_default_rules(self):
        """Загрузка правил по умолчанию"""
        # Правило: блокировать трафик от неавторизованных источников
        self.add_rule(FilterRule(
            name="block_unauthorized_traffic",
            action=Action.BLOCK,
            enabled=False  # Отключено: предавторизация выполняется отдельно
        ))
        
        # Правило: блокировать известные вредоносные IP
        self.add_rule(FilterRule(
            name="block_malicious_ips",
            action=Action.BLOCK,
            enabled=False  # По умолчанию отключено
        ))
        
        # Правило: логировать подозрительный трафик
        self.add_rule(FilterRule(
            name="log_suspicious",
            action=Action.LOG,
            enabled=True
        ))
    
    def load_rules(self, rules_file: str):
        """
        Загрузка правил из файла
        
        Формат файла:
        action name src_ip dst_ip src_port dst_port protocol payload_pattern
        """
        try:
            with open(rules_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        rule = self._parse_rule_line(line)
                        if rule:
                            self.add_rule(rule)
                    except Exception as e:
                        print(f"[Filter] Error parsing rule at line {line_num}: {e}")
        except FileNotFoundError:
            print(f"[Filter] Rules file not found: {rules_file}")
        except Exception as e:
            print(f"[Filter] Error loading rules: {e}")
    
    def _parse_rule_line(self, line: str) -> Optional[FilterRule]:
        """Парсинг строки правила"""
        parts = line.split()
        if len(parts) < 2:
            return None
        
        action_str = parts[0].upper()
        name = parts[1]
        
        action_map = {
            'ALLOW': Action.ALLOW,
            'BLOCK': Action.BLOCK,
            'LOG': Action.LOG,
            'ALERT': Action.ALERT
        }
        
        action = action_map.get(action_str, Action.BLOCK)
        
        # Парсинг опциональных параметров
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = None
        payload_pattern = None
        
        i = 2
        while i < len(parts):
            if parts[i] == 'src_ip' and i + 1 < len(parts):
                src_ip = parts[i + 1]
                i += 2
            elif parts[i] == 'dst_ip' and i + 1 < len(parts):
                dst_ip = parts[i + 1]
                i += 2
            elif parts[i] == 'src_port' and i + 1 < len(parts):
                src_port = int(parts[i + 1])
                i += 2
            elif parts[i] == 'dst_port' and i + 1 < len(parts):
                dst_port = int(parts[i + 1])
                i += 2
            elif parts[i] == 'protocol' and i + 1 < len(parts):
                protocol = parts[i + 1].upper()
                i += 2
            elif parts[i] == 'payload' and i + 1 < len(parts):
                payload_pattern = parts[i + 1].encode()
                i += 2
            else:
                i += 1
        
        return FilterRule(
            name=name,
            action=action,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload_pattern=payload_pattern
        )
    
    def check_packet(self, packet: bytes, src_ip: str, dst_ip: str) -> Tuple[bool, Optional[FilterRule]]:
        """
        Проверка пакета по правилам
        
        Args:
            packet: Данные IP пакета
            src_ip: IP адрес источника
            dst_ip: IP адрес назначения
            
        Returns:
            Кортеж (should_block, matched_rule)
        """
        self.stats['total_checked'] += 1
        
        if len(packet) < 20:
            return False, None

        # Предварительная проверка авторизованных IP: блокируем внешний трафик,
        # если источник не авторизован и не локален
        if src_ip not in self.authorized_ips and not self._is_local_ip(src_ip):
            if not self._is_local_ip(dst_ip):
                self.stats['blocked'] += 1
                return True, None
        
        # Парсинг IP заголовка
        ip_header = packet[:20]
        protocol_num = ip_header[9]
        
        # Извлечение портов и протокола (для TCP/UDP)
        src_port = None
        dst_port = None
        protocol = None
        
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        }
        
        protocol = protocol_map.get(protocol_num, f'UNKNOWN({protocol_num})')
        
        # Извлечение портов для TCP/UDP
        if protocol_num in [6, 17] and len(packet) >= 40:
            src_port = struct.unpack('!H', packet[20:22])[0]
            dst_port = struct.unpack('!H', packet[22:24])[0]
        
        # Проверка правил
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if self._rule_matches(rule, packet, src_ip, dst_ip, src_port, dst_port, protocol):
                # Обновление статистики
                if rule.name not in self.stats['rule_matches']:
                    self.stats['rule_matches'][rule.name] = 0
                self.stats['rule_matches'][rule.name] += 1
                
                # Обработка действия
                if rule.action == Action.BLOCK:
                    self.stats['blocked'] += 1
                    return True, rule
                elif rule.action == Action.ALLOW:
                    self.stats['allowed'] += 1
                    return False, rule
                elif rule.action == Action.LOG:
                    print(f"[Filter] LOG: Rule '{rule.name}' matched - {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    self.stats['allowed'] += 1
                    return False, rule
                elif rule.action == Action.ALERT:
                    self.stats['alerts'] += 1
                    alert_msg = f"ALERT: Rule '{rule.name}' matched - {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    print(f"[Filter] {alert_msg}")
                    if self.alert_callback:
                        try:
                            self.alert_callback(rule, packet, src_ip, dst_ip)
                        except Exception:
                            pass
                    return True, rule
        
        # По умолчанию разрешаем
        self.stats['allowed'] += 1
        return False, None

    def _is_local_ip(self, ip: str) -> bool:
        """Проверка, является ли IP локальным или приватным"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
        except ValueError:
            return False
        
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
    
    def _rule_matches(self, rule: FilterRule, packet: bytes, src_ip: str, dst_ip: str,
                     src_port: Optional[int], dst_port: Optional[int], protocol: Optional[str]) -> bool:
        """Проверка соответствия пакета правилу"""
        # Проверка IP адресов
        if rule.src_ip and not self._ip_matches(src_ip, rule.src_ip):
            return False
        
        if rule.dst_ip and not self._ip_matches(dst_ip, rule.dst_ip):
            return False
        
        # Проверка портов
        if rule.src_port is not None and src_port != rule.src_port:
            return False
        
        if rule.dst_port is not None and dst_port != rule.dst_port:
            return False
        
        # Проверка протокола
        if rule.protocol and protocol != rule.protocol:
            return False
        
        # Проверка паттерна в payload
        if rule.payload_pattern:
            if rule.payload_pattern not in packet:
                return False
        
        return True
    
    def _ip_matches(self, ip: str, pattern: str) -> bool:
        """Проверка соответствия IP адреса паттерну (поддержка CIDR)"""
        if '/' in pattern:
            # CIDR нотация
            network_ip, prefix_len = pattern.split('/')
            prefix_len = int(prefix_len)
            
            # Упрощенная проверка CIDR (для полной реализации нужна библиотека ipaddress)
            if prefix_len == 32:
                return ip == network_ip
            elif prefix_len == 24:
                return ip.startswith('.'.join(network_ip.split('.')[:3]) + '.')
            elif prefix_len == 16:
                return ip.startswith('.'.join(network_ip.split('.')[:2]) + '.')
            elif prefix_len == 8:
                return ip.startswith(network_ip.split('.')[0] + '.')
            else:
                # Для других префиксов используем простое сравнение
                return ip == network_ip
        else:
            return ip == pattern
    
    def set_alert_callback(self, callback: Callable):
        """Установка callback для обработки алертов"""
        self.alert_callback = callback
    
    def get_stats(self) -> dict:
        """Получение статистики фильтрации"""
        return dict(self.stats)
    
    def save_rules(self, rules_file: str):
        """Сохранение правил в файл"""
        try:
            with open(rules_file, 'w') as f:
                f.write("# PacketMimic Traffic Filter Rules\n")
                f.write("# Format: action name [src_ip=...] [dst_ip=...] [src_port=...] [dst_port=...] [protocol=...] [payload=...]\n\n")
                
                for rule in self.rules:
                    line = f"{rule.action.name} {rule.name}"
                    if rule.src_ip:
                        line += f" src_ip={rule.src_ip}"
                    if rule.dst_ip:
                        line += f" dst_ip={rule.dst_ip}"
                    if rule.src_port is not None:
                        line += f" src_port={rule.src_port}"
                    if rule.dst_port is not None:
                        line += f" dst_port={rule.dst_port}"
                    if rule.protocol:
                        line += f" protocol={rule.protocol}"
                    if rule.payload_pattern:
                        line += f" payload={rule.payload_pattern.decode(errors='ignore')}"
                    if not rule.enabled:
                        line += " # disabled"
                    f.write(line + "\n")
        except Exception as e:
            print(f"[Filter] Error saving rules: {e}")


