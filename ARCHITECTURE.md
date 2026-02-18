# Архітектура SecureShare

## Огляд модулів

```
main.py
  └── app/gui.py  (App)
        ├── app/config.py          константи
        ├── app/crypto_utils.py    криптографія
        ├── app/network.py         мережеві утиліти
        ├── app/signaling.py       виявлення пірів
        ├── app/transfer.py        пряма передача (TCP/UDP)
        ├── app/relay.py           MQTT relay
        ├── app/relay_server.py    локальний WS relay сервер
        ├── app/ws_relay.py        WS relay sender/receiver
        └── app/cf_tunnel.py       Cloudflare Tunnel менеджер
```

## Потік даних (детально)

### 1. Signaling (`signaling.py`)

Виявлення пірів — **паралельне** підключення до всіх каналів:

```
SignalingClient
  ├── _BrokerConn × 3    (MQTT TLS port 8883)
  │   ├── broker.emqx.io
  │   ├── mqtt.eclipseprojects.io
  │   └── test.mosquitto.org
  └── _NtfyConn × 1      (HTTPS port 443 fallback)
      └── ntfy.sh
```

**Протокол:**
1. Обидва клієнти підключаються до всіх каналів паралельно
2. Публікують зашифровану інформацію (IP, порти, публічний ключ, relay_url)
3. Підписуються на topic іншого role (sender/receiver)
4. Хто першим знайде — виграв; re-publish кожні 20с

**Безпека signaling:**
- Topic = HMAC-SHA256(session_code, salt)[:16] → непомітний
- Payload = AES-256-GCM(HKDF(session_code)) → зашифрований
- Transport = TLS (MQTT) або HTTPS (ntfy.sh)

### 2. Key Exchange (`crypto_utils.py`)

```
Sender                              Receiver
  │                                    │
  ├── X25519 keypair ─────────────────►│
  │◄───────────────── X25519 keypair ──┤
  │                                    │
  ├── HKDF(DH_secret, session_code)    │  ← shared AES-256 key
  │                                    │
  ├── nonce_prefix = 0 (lower pubkey)  │
  │   nonce_prefix = 1 (higher pubkey)─┤  ← no nonce collision
  │                                    │
  ├── verification = SHA256(key+salt)  │
  │   "A7F3-BC21" ══════════════════   │  ← MITM detection
  └────────────────────────────────────┘
```

### 3. З'єднання (`network.py`, `gui.py`)

Ланцюг спроб (в `_send_worker` / `_recv_worker`):

```
1. Direct TCP            sender=server, receiver=client
   ├── LAN IPs           (якщо в одній мережі)
   └── Public IP+UPnP    (якщо UPnP доступний)

2. UDP Hole Punch        через STUN-визначені public IP:port
   └── 8 секунд спроб

3. WS Relay              Cloudflare Tunnel
   ├── sender:  ws://localhost:{port}  → LocalRelayServer
   └── receiver: wss://{cf-url}.trycloudflare.com

4. MQTT Relay            через публічний MQTT брокер
   └── 64KB chunks, QoS 1
```

### 4. Передача файлу

**TCP Transfer (`transfer.py`):**
```
[4B length][encrypted chunk]  →  1 MB chunks, sequential
```

**WS Relay Transfer (`ws_relay.py`):**
```
Frame format:
  [1B type][payload]

  type 0x43 'C' → control: [encrypted JSON]
  type 0x44 'D' → data:    [4B seq][encrypted compressed chunk]

Control messages:
  relay_meta        → file info (name, size, hash, chunks)
  relay_meta_ack    → ready
  relay_done        → all sent
  relay_done_ack    → verified (bool)
  relay_retransmit  → [missing seq list]
  relay_window_ack  → flow control ACK

Flow control:
  Sender sends 8 chunks (4 MB window) → waits for window_ack
  Receiver ACKs every 128 chunks received
  ⚠ KNOWN BUG: sender/receiver window sizes не збігаються (8 vs 128)
```

**MQTT Relay Transfer (`relay.py`):**
```
Topics:
  secureshare/v2/{topic_id}/data    → encrypted chunks (QoS 1)
  secureshare/v2/{topic_id}/ctl     → control messages (QoS 1)

64KB chunks, 16 max inflight, zlib compression
Async writer thread (decoupled from paho callback)
```

### 5. Cloudflare Tunnel (`cf_tunnel.py`, `relay_server.py`)

```
Sender machine:
  ┌─────────────────────────────────────────┐
  │  WSRelaySender                          │
  │    ↓ ws://localhost:{port}              │
  │  LocalRelayServer (asyncio websockets)  │
  │    ↓ localhost:{port}                   │
  │  cloudflared tunnel --url ...           │
  │    ↓ Cloudflare edge                    │
  └───────────┬─────────────────────────────┘
              │ wss://xyz.trycloudflare.com
              ↓
  ┌─────────────────────────────────────────┐
  │  WSRelayReceiver                        │
  │  (receiver machine)                     │
  └─────────────────────────────────────────┘
```

`cloudflared.exe` вбудований через PyInstaller (`--add-binary tools/cloudflared.exe`).

## Безпека — деталі

### Шифрування

```
Signaling level:
  key = HKDF(session_code, salt="secureshare-signaling-salt-v2")
  encrypt = AES-256-GCM(key, random_nonce, aad="secureshare-signaling-aad")

Data level:
  DH = X25519(my_private, peer_public)
  key = HKDF(DH, salt=session_code, info="secureshare-v2-aes")
  nonce = [4B prefix][8B counter]    (prefix=0 for lower pubkey, 1 for higher)
  encrypt = AES-256-GCM(key, nonce, aad=session_code)

Verification:
  code = SHA256(shared_key + "secureshare-verify")[:8].hex → "A7F3-BC21"
```

### Що бачить спостерігач

| Рівень | Що видно |
|--------|----------|
| MQTT брокер | Зашифрований blob, хешований topic |
| ntfy.sh | Base64-encoded зашифрований blob |
| Cloudflare | Encrypted WebSocket frames |
| Мережевий сніфер | TLS/HTTPS трафік до відомих сервісів |

## Відомі проблеми та технічний борг

### Критичні

1. **Window ACK невідповідність** — sender чекає ACK кожні 8 чанків, receiver ACK-ає кожні 128. Може викликати deadlock на великих файлах.

2. **`retain=True` в signaling** — `_BrokerConn.publish()` використовує `retain=True`, що залишає зашифровані повідомлення на брокері після сесії.

3. **Незавершена паралельна реалізація** — `WSRelaySender` має `chunk_start`/`chunk_stride`, `WSRelayReceiver` — ні. Але з дефолтними значеннями (0/1) працює коректно.

### Якість коду

4. **Дублювання** — `_compress()` в `relay.py` і `ws_relay.py`; `_sha256_file()` в `transfer.py` і `ws_relay.py`.

5. **`hasattr` замість ініціалізації** — `_ping_stop`, `_window_cond` в `WSRelaySender` не ініціалізуються в `__init__`.

6. **Монолітний `gui.py`** — `_send_worker()` і `_recv_worker()` по ~250 рядків кожен.

7. **Dead code** — `MQTT_RELAY_BATCH_SIZE`, `MQTT_RELAY_RATE_LIMIT` в `config.py` не використовуються.

### Продуктивність

8. **CF Tunnel throttle** — Cloudflare Quick Tunnel обмежений ~1-5 MB/s. Для 10-30 GB файлів — непрактично.

9. **MQTT relay** — 300 KB/s - 2 MB/s через публічні брокери.

10. **Busy-wait в relay_server.py** — `asyncio.sleep(0.05)` замість `asyncio.Event()`.
