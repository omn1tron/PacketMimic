#!/usr/bin/env python3
"""
Пример использования PacketMimic VPN Client с фильтрацией трафика
"""

import sys
from packetmimic import PacketMimicClient

if __name__ == '__main__':
    # Путь к файлу с правилами фильтрации (опционально)
    rules_file = sys.argv[1] if len(sys.argv) > 1 else 'rules.conf'
    use_tun = bool(int(sys.argv[2])) if len(sys.argv) > 2 else False  # 1 = включить TUN (Linux, root)
    
    # Подключение к серверу
    client = PacketMimicClient(
        server_host='172.16.246.180',
        server_port=5556,
        password='my_secure_password_123',
        rules_file=rules_file,  # Файл с правилами фильтрации
        use_tun=use_tun,
        tun_name='packetmimic0'
    )
    
    print("Подключение к PacketMimic VPN Server...")
    print(f"Правила фильтрации: {rules_file}")
    print("Нажмите Ctrl+C для отключения")
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\nОтключение от сервера...")
        client.disconnect()

