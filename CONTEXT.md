# Контекст розробки

Документ для відновлення контексту при продовженні роботи над проектом.

## Історія розробки (хронологія)

### Фаза 1 — Початок

1. **Вибір підходу** — клієнт-клієнт, без серверів, одноразові сесії
2. **Базовий стек** — Python + CustomTkinter GUI + PyInstaller → один .exe
3. **P2P з'єднання** — STUN (публічний IP), UPnP (проброс портів), TCP/UDP hole punch
4. **Криптографія** — X25519 key exchange + AES-256-GCM
5. **Signaling** — MQTT брокер (broker.hivemq.com) для обміну метаданими

### Фаза 2 — Вирішення проблем з'єднання

6. **Deadlock** — обидва клієнти намагались connect() одночасно. Виправлено: sender=server, receiver=client
7. **Таймаути** — послідовні спроби з'єднання занадто повільні. Виправлено: паралельні TCP, пріоритизація IP, коротші таймаути
8. **Virtual IP** — VirtualBox/Docker адаптери заважали. Виправлено: `_is_virtual_ip()` фільтр
9. **MQTT relay fallback** — додано для випадків коли пряме з'єднання неможливе

### Фаза 3 — Оптимізація MQTT relay

10. **QoS 0 → 27% втрат** — sender відправляв швидше ніж брокер міг обробити
11. **QoS 1 → 700 KB/s** — кожен чанк чекав PUBACK, round-trip latency
12. **Token bucket** — rate limiter для QoS 0, але все одно втрати
13. **Async writer** — decoupled мережевий прийом від disk I/O
14. **Висновок** — MQTT relay фундаментально обмежений ~2 MB/s через публічні брокери

### Фаза 4 — Безпека v2

15. **Signaling encryption** — AES-256-GCM з ключем від session code
16. **Topic obfuscation** — HMAC-hashed MQTT topics
17. **Nonce prefix** — 0/1 за публічним ключем → ніколи не повторюються
18. **AAD** — session code як Associated Data в AES-GCM
19. **MITM verification** — обов'язковий діалог порівняння кодів
20. **Реліз v2.0.0** — збережений в `releases/v2.0.0/`

### Фаза 5 — Cloudflare Tunnel relay

21. **Концепція** — sender запускає локальний WS сервер, cloudflared створює публічний URL
22. **Завантаження cloudflared** — спочатку при першому запуску, потім вбудований в .exe
23. **Проблеми download** — HTML замість binary, corrupted файли. Виправлено: GitHub API, PE validation
24. **Вбудовування** — `--add-binary tools/cloudflared.exe` в PyInstaller

### Фаза 6 — Надійність signaling

25. **MQTT broker down** — broker.hivemq.com почав вимагати auth. Виправлено: список з 3 брокерів
26. **Різні брокери** — sender на одному, receiver на іншому. Виправлено: підключення до ВСІХ паралельно
27. **MQTT port blocked** — port 8883 заблоковано firewall. Виправлено: ntfy.sh fallback (HTTPS port 443)
28. **Race condition** — обидві сторони чекають одна одну. Виправлено: re-publish кожні 20с, `since=15m`

### Фаза 7 — WS Relay проблеми

29. **Socket timeout** — sender flood → CF throttle → receiver timeout. Виправлено: 120с timeout
30. **Buffer overflow** — без flow control sender переповнював relay. Виправлено: window-based ACK
31. **Firewall popup** — Windows firewall блокував local relay. Виправлено: auto firewall rule
32. **Швидкість ~100 KB/s** — CF Quick Tunnel throttle. Це фундаментальне обмеження безкоштовного CF.

### Фаза 8 — Рефлексія та планування

33. **Код ревю** — детальний огляд всього проекту (оцінка 7/10)
34. **Аналіз альтернатив** — WebRTC, Tailscale, VPS relay, libp2p, Tor
35. **Рішення** — WebRTC (aiortc) як головний напрямок v3.0
36. **Git repo + документація** — ← ви тут

## Поточний стан коду

### Що працює
- ✅ GUI (CustomTkinter) — повністю функціональний
- ✅ Signaling — MQTT (3 брокери) + ntfy.sh паралельно
- ✅ Direct TCP — на LAN та з UPnP
- ✅ UDP hole punch — ~30% success rate
- ✅ WS Relay — працює, але повільно (CF Tunnel throttle)
- ✅ MQTT Relay — працює, ще повільніше
- ✅ E2E encryption — повноцінна
- ✅ Тести — 5 сценаріїв (basic, delayed, throttled, window_ctrl, signaling_mock)
- ✅ PyInstaller build — один .exe з вбудованим cloudflared

### Що не працює / не завершено
- ⚠️ Window ACK mismatch (sender: 8, receiver: 128)
- ⚠️ `retain=True` в signaling (metadata leakage)
- ⚠️ `chunk_start`/`chunk_stride` — додано в sender, не в receiver
- ⚠️ Code duplication (`_compress`, `_sha256_file`)

### Головна проблема
**Швидкість relay** — CF Tunnel ~1-5 MB/s, MQTT ~0.3-2 MB/s. Для файлів 10-30 GB це годинники очікування. Пряме з'єднання працює тільки у ~30% випадків.

## Наступний крок: WebRTC (aiortc)

**Чому:** ICE protocol пробує десятки candidate-пар паралельно → NAT traversal success ~80% замість ~30%. При прямому з'єднанні — повна швидкість мережі.

**Бібліотека:** `aiortc` — чистий Python WebRTC, працює з PyInstaller.

**Що змінюється:**
```
Новий файл:      app/webrtc.py (RTCPeerConnection + DataChannel wrapper)
Модифікація:     app/gui.py (додати WebRTC в fallback chain)
Signaling:       без змін (SDP offer/answer через існуючий MQTT/ntfy)
Залишається:     CF Tunnel + MQTT як fallback після WebRTC
```

**Fallback chain v3:**
```
1. Direct TCP (LAN/UPnP)     ← існує
2. WebRTC ICE (STUN)          ← НОВИЙ (80% success, повна швидкість)
3. WS Relay (CF Tunnel)       ← існує (fallback для 20%)
4. MQTT Relay                  ← існує (last resort)
```

**Опціонально:** Власний TURN сервер ($3/міс VPS) закриє останні 20%.

## Ключові рішення та чому

| Рішення | Чому | Альтернативи що розглядались |
|---------|------|------------------------------|
| Python + CustomTkinter | Швидкість розробки, крос-платформність | Electron (важкий), Go+Fyne (менш гнучкий) |
| X25519 + AES-256-GCM | Стандарт індустрії, бібліотека `cryptography` | NaCl/libsodium (менш гнучкий) |
| MQTT signaling | Безкоштовно, pub/sub модель ідеальна | WebSocket сервер (потрібен хостинг) |
| ntfy.sh fallback | HTTPS port 443 завжди відкритий | Signal protocol (складний) |
| CF Tunnel relay | Безкоштовно, zero-config | VPS relay ($), Tor (.onion повільний) |
| PyInstaller onefile | Один .exe, zero-install | Nuitka (складніший), cx_Freeze |
| Embedded cloudflared | Надійніше ніж download at runtime | Runtime download (проблеми з proxy/AV) |

## Тестове середовище

- **OS:** Windows 10/11
- **Python:** 3.11+
- **Тестувалось:** 2 ноутбуки в різних мережах (різні ISP)
- **Файли:** від 6 байт до 73.7 MB реальних тестів; тест-сюіт до 200 MB
- **Мережі:** домашній Wi-Fi, мобільний хотспот, корпоративний firewall (MQTT blocked)
