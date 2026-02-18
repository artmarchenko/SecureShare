# Roadmap та задачі

## 🔴 Критично — виправити перед наступним релізом

- [ ] **Виправити Window ACK невідповідність** — sender чекає ACK кожні 8 чанків (`ws_relay.py:205`), receiver ACK-ає кожні 128 чанків (`ws_relay.py:615`). Привести до єдиного значення.
- [ ] **Прибрати `retain=True` з `_BrokerConn.publish()`** — (`signaling.py:97`) залишає зашифровані повідомлення на MQTT брокері.
- [ ] **Ініціалізувати `_ping_stop`, `_window_cond` в `__init__`** — (`ws_relay.py`) замість `hasattr` перевірок.

## 🟡 Технічний борг

- [ ] Винести `_compress()`, `_sha256_file()` в спільний `app/utils.py`
- [ ] Видалити dead code: `MQTT_RELAY_BATCH_SIZE`, `MQTT_RELAY_RATE_LIMIT` з `config.py`
- [ ] Refactor `gui.py` — виділити `_send_worker`/`_recv_worker` в окремий `orchestrator.py`
- [ ] Замінити busy-wait `asyncio.sleep(0.05)` на `asyncio.Event()` в `relay_server.py`
- [ ] Прибрати `100.64.` (Tailscale) з `_is_virtual_ip()` в `network.py`
- [ ] Завершити або прибрати `chunk_start`/`chunk_stride` в `WSRelaySender`

## 🟢 v3.0 — WebRTC інтеграція (головний напрямок)

Фундаментальне покращення NAT traversal: замінити поточний примітивний STUN+hole punch на повноцінний WebRTC ICE.

### Що дає
- NAT traversal success rate: ~30% → ~80%
- Десятки ICE candidate пар паралельно (замість 1-2)
- Стандартизований DTLS шифрування
- DataChannel throughput: 10-50 MB/s (direct UDP)

### План
- [ ] Додати `aiortc` в залежності
- [ ] Створити `app/webrtc.py` — обгортка RTCPeerConnection + DataChannel
- [ ] Інтегрувати SDP offer/answer обмін через існуючий `signaling.py`
- [ ] Chunking + progress + SHA-256 через DataChannel
- [ ] Fallback chain: WebRTC → CF Tunnel → MQTT
- [ ] Тести з `aiortc` + PyInstaller

### Опціонально
- [ ] Власний TURN сервер (coturn на VPS $3/міс) для 20% випадків коли ICE не вдається
- [ ] Або безкоштовний TURN (Metered.ca free tier, OpenRelay)

## 🔵 Можливі покращення (low priority)

- [ ] Передача кількох файлів / папок
- [ ] Resume при обриві (збереження стану передачі)
- [ ] Drag & drop файлів у вікно
- [ ] Оцінка типу NAT (symmetric/full cone) для кращої стратегії
- [ ] Rate limiting на спроби підключення (анти brute-force session code)
- [ ] Cross-platform (macOS, Linux) — CustomTkinter вже підтримує
- [ ] Тести MQTT relay шляху
- [ ] Тести retransmit (симуляція dropped packets)
- [ ] CI/CD (GitHub Actions)
- [ ] Auto-update механізм
