# 🔒 SecureShare

**Peer-to-peer encrypted file sharing** — простий .exe для безпечної передачі файлів між двома комп'ютерами через інтернет.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-proprietary-red)
![Version](https://img.shields.io/badge/version-2.0.0-green)

## Що це

SecureShare — десктопна програма з графічним інтерфейсом для одноразової безпечної передачі файлів між двома користувачами. Не потребує серверів, реєстрації, налаштування мережі чи білих IP-адрес.

### Основні можливості

- **End-to-End шифрування** — X25519 (ECDH) + AES-256-GCM
- **Автоматичний NAT traversal** — STUN, UPnP, UDP hole punching
- **Cloudflare Tunnel relay** — коли пряме з'єднання неможливе
- **MQTT relay fallback** — останній резерв через публічні брокери
- **Верифікація MITM** — візуальне порівняння коду безпеки
- **SHA-256 цілісність** — перевірка хешу після передачі
- **Один .exe файл** — без інсталяції, без залежностей

## Як користуватись

### Відправник

1. Запустити `SecureShare.exe`
2. Обрати файл
3. Повідомити код сесії (напр. `a7f3-bc21`) отримувачу
4. Порівняти код верифікації
5. Дочекатись завершення передачі

### Отримувач

1. Запустити `SecureShare.exe`
2. Ввести код сесії від відправника
3. Обрати папку для збереження
4. Порівняти код верифікації
5. Дочекатись завершення отримання

## Як це працює

```
Відправник                                    Отримувач
    │                                              │
    ├── 1. Генерує код сесії ──(голосом/чатом)────►│
    │                                              │
    ├── 2. STUN/UPnP (мережева розвідка) ─────────►│
    │                                              │
    ├── 3. Signaling (MQTT + ntfy.sh) ◄───────────►│
    │      обмін зашифрованою інформацією           │
    │                                              │
    ├── 4. X25519 key exchange ◄──────────────────►│
    │      верифікація коду безпеки                 │
    │                                              │
    ├── 5. Встановлення з'єднання:                  │
    │      → Пряме TCP (LAN/UPnP)                  │
    │      → UDP hole punch                        │
    │      → WS Relay (Cloudflare Tunnel)          │
    │      → MQTT Relay (fallback)                 │
    │                                              │
    ├── 6. E2E encrypted transfer ════════════════►│
    │      AES-256-GCM + SHA-256 verify            │
    └──────────────────────────────────────────────┘
```

### Ланцюг fallback з'єднань

| Пріоритет | Метод | Швидкість | Коли працює |
|-----------|-------|-----------|-------------|
| 1 | Direct TCP | Повна | LAN або UPnP |
| 2 | UDP Hole Punch | Повна | ~30% NAT |
| 3 | WS Relay (CF Tunnel) | 1-5 MB/s | Завжди |
| 4 | MQTT Relay | 0.3-2 MB/s | Завжди |

## Розробка

### Вимоги

- Python 3.11+
- Windows 10/11

### Встановлення залежностей

```bash
pip install -r requirements.txt
```

### Запуск з коду

```bash
python main.py
```

### Запуск тестів

```bash
python -X utf8 test_transfer.py
python -X utf8 test_transfer.py --sizes 1 10 100
python -X utf8 test_transfer.py --only basic
```

### Збірка .exe

```bash
python build.py
```

Результат: `dist/SecureShare.exe`

### Підпис .exe (опціонально)

```powershell
.\sign.ps1
```

## Структура проекту

```
fileshare/
├── app/
│   ├── config.py          # Конфігурація (порти, розміри, таймаути)
│   ├── crypto_utils.py    # X25519, AES-256-GCM, HKDF, signaling crypto
│   ├── gui.py             # CustomTkinter GUI + оркестрація transfer
│   ├── network.py         # STUN, UPnP, UDP hole punch, TCP helpers
│   ├── signaling.py       # MQTT + ntfy.sh паралельний signaling
│   ├── transfer.py        # TCP та UDP sender/receiver
│   ├── relay.py           # MQTT relay (fallback)
│   ├── relay_server.py    # Локальний WebSocket relay сервер
│   ├── ws_relay.py        # WS Relay sender/receiver (через CF Tunnel)
│   └── cf_tunnel.py       # Cloudflare Tunnel менеджер
├── main.py                # Точка входу
├── build.py               # PyInstaller build script
├── test_transfer.py       # Автоматизовані тести
├── requirements.txt       # Python залежності
├── version_info.txt       # Метадані .exe (версія, видавець)
├── sign.ps1               # PowerShell скрипт для підпису
└── tools/
    └── cloudflared.exe    # Вбудований CF Tunnel binary (не в git)
```

## Безпека

### Криптографія

| Компонент | Алгоритм | Призначення |
|-----------|----------|-------------|
| Key Exchange | X25519 (ECDH) | Обмін ключами без передачі секрету |
| Encryption | AES-256-GCM | Authenticated encryption з AAD |
| KDF | HKDF-SHA256 | Деривація ключів |
| Nonce | Counter + prefix | Запобігання повторення nonce |
| Integrity | SHA-256 | Перевірка цілісності файлу |
| Signaling | AES-256-GCM (pre-shared key) | Шифрування метаданих сесії |
| Topics | HMAC-SHA256 | Обфускація MQTT topics |
| Transport | TLS 1.2+ / HTTPS | Шифрування транспорту |

### Захист від атак

- **MITM** — обов'язкова верифікація коду безпеки
- **Replay** — counter-based nonces з унікальним prefix
- **Cross-session** — session code як AAD в AES-GCM
- **Discovery** — HMAC-hashed MQTT topics
- **Metadata** — зашифрований signaling

## Автор

**Artem Marchenko** — © 2026. All rights reserved.
