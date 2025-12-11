#!/usr/bin/env python3
"""
Пример использования PacketMimic VPN Server с перехватом и фильтрацией трафика
"""

import sys
from packetmimic import PacketMimicServer

if __name__ == '__main__':
    # Путь к файлу с правилами фильтрации (опционально)
    rules_file = sys.argv[1] if len(sys.argv) > 1 else 'rules.conf'
    use_tun = bool(int(sys.argv[2])) if len(sys.argv) > 2 else False  # 1 = включить TUN (Linux, root)
    
    # Запуск сервера на порту 5555 с паролем
    # enable_interceptor=True включает перехват трафика (требует root)
    server = PacketMimicServer(
        host='localhost',
        port=5556,
        password='my_secure_password_123',
        enable_interceptor=True,  # Включить перехват трафика
        rules_file=rules_file,     # Файл с правилами фильтрации
        use_tun=use_tun,           # Включить TUN для реального туннеля (Linux)
        tun_name='packetmimic0',
        enable_obfuscation=True,   # Включить обфускацию для обхода DPI
        obfuscation_method='tls'   # Метод: 'tls' (лучше для YouTube), 'http', 'random'
    )
    
    print("Запуск PacketMimic VPN Server...")
    print("Перехват трафика: включен")
    print(f"Правила фильтрации: {rules_file}")
    print("Нажмите Ctrl+C для остановки")
    print("\nВНИМАНИЕ: Для перехвата трафика требуются права root!")
    print("Запустите с sudo: sudo python example_server.py\n")
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nОстановка сервера...")
        server.stop()

