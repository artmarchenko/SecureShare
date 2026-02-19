# Деплой SecureShare Relay Server на Oracle Cloud

## Крок 1: Створити VM Instance

1. Зайти в [Oracle Cloud Console](https://cloud.oracle.com/)
2. **Menu → Compute → Instances → Create Instance**
3. Налаштування:

| Параметр | Значення |
|----------|---------|
| **Name** | `secureshare-relay` |
| **Image** | Ubuntu 22.04 (або 24.04) |
| **Shape** | VM.Standard.E2.1.Micro (**Always Free**) |
| **OCPU** | 1 |
| **RAM** | 1 GB |
| **Boot volume** | 50 GB (default) |

4. **Networking:**
   - Створити нову VCN або використати існуючу
   - **Assign public IPv4 address** — ✅ ОБОВ'ЯЗКОВО
   - Subnet — public

5. **SSH Key:**
   - Обрати **Generate a key pair** → завантажити приватний ключ (.key файл)
   - АБО вставити свій публічний ключ (якщо вже є)

6. Натиснути **Create** → зачекати 2-3 хвилини

7. Скопіювати **Public IP Address** зі сторінки інстансу (напр. `132.145.xx.xx`)

## Крок 2: Відкрити порти у Oracle Cloud

Oracle Cloud має свій firewall (Security List) ОКРІМ iptables на VM!

1. **Menu → Networking → Virtual Cloud Networks**
2. Обрати свою VCN → **Security Lists** → клікнути на default security list
3. **Add Ingress Rules:**

| Source CIDR | Protocol | Dest Port | Опис |
|-------------|----------|-----------|------|
| `0.0.0.0/0` | TCP | 80 | HTTP (SSL cert) |
| `0.0.0.0/0` | TCP | 443 | HTTPS (relay) |

4. Натиснути **Add Ingress Rules**

## Крок 3: Підключитись по SSH

### Windows (PowerShell):

```powershell
# Replace <SSH_KEY_PATH> with path to your .key file from Oracle:
ssh -i <SSH_KEY_PATH> ubuntu@<PUBLIC_IP>
```

### Якщо помилка Permission denied:

```powershell
# Set correct permissions on the key file (PowerShell):
icacls "<SSH_KEY_PATH>" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

## Крок 4: Налаштувати сервер

Після підключення по SSH виконати:

```bash
# 1. Оновити систему
sudo apt update && sudo apt upgrade -y

# 2. Встановити Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# 3. Перелогінитись (щоб docker працював без sudo)
exit
```

Підключитись знову:

```bash
ssh -i <key> ubuntu@<PUBLIC_IP>

# 4. Перевірити Docker
docker --version
docker compose version
```

## Крок 5: Відкрити порти на VM (iptables)

Oracle Ubuntu має iptables правила по замовчуванню!

```bash
# Відкрити порти 80 і 443
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT

# Зберегти правила
sudo netfilter-persistent save
```

## Крок 6: Безкоштовний домен (DuckDNS)

1. Зайти на [duckdns.org](https://www.duckdns.org/)
2. Залогінитись через GitHub/Google
3. Створити піддомен, наприклад: `secureshare` → `secureshare.duckdns.org`
4. Вказати **Public IP** вашого Oracle VPS
5. Натиснути **Update IP**

### Автооновлення IP (на VPS):

```bash
# Cron job для оновлення IP кожні 5 хвилин (якщо IP зміниться)
mkdir -p ~/duckdns
echo "url=\"https://www.duckdns.org/update?domains=secureshare&token=YOUR_TOKEN&ip=\"" > ~/duckdns/duck.sh
chmod +x ~/duckdns/duck.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * ~/duckdns/duck.sh > ~/duckdns/duck.log 2>&1") | crontab -
```

## Крок 7: Деплой relay server

```bash
# 1. Клонувати репо (або скопіювати файли)
git clone <YOUR_REPO_URL> ~/secureshare
cd ~/secureshare/server

# АБО якщо без git — скопіювати файли через scp (з локальної машини):
# scp -i <key> -r server/* ubuntu@<PUBLIC_IP>:~/secureshare-server/

# 2. Налаштувати домен в Caddyfile
nano Caddyfile
```

Замінити `YOUR_DOMAIN` на свій домен:

```
secureshare.duckdns.org {
    reverse_proxy relay:8765
}
```

```bash
# 3. Запустити
docker compose up -d

# 4. Перевірити
docker compose ps
docker compose logs -f
```

Має бути:
```
relay-1  | 2026-02-19 12:00:00 [INFO] SecureShare Relay Server starting on 0.0.0.0:8765
relay-1  | 2026-02-19 12:00:00 [INFO] Relay server ready. Waiting for connections...
caddy-1  | ... certificate obtained for secureshare.duckdns.org ...
```

## Крок 8: Перевірити

З локальної машини (PowerShell):

```powershell
# Перевірити що сервер відповідає
curl https://secureshare.duckdns.org
# Має повернути помилку WebSocket — це нормально, значить працює

# Або Python:
python -c "import websocket; ws=websocket.create_connection('wss://secureshare.duckdns.org'); ws.send('test'); print('OK'); ws.close()"
```

## Крок 9: Безпека VPS

```bash
# SSH тільки по ключу (без пароля)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Fail2ban
sudo apt install -y fail2ban
sudo systemctl enable fail2ban

# Автооновлення системи
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## Оновлення серверу

```bash
ssh -i <key> ubuntu@<PUBLIC_IP>
cd ~/secureshare/server
git pull
docker compose up -d --build
# Готово за 30 секунд
```

## Моніторинг

```bash
# Логи relay
docker compose logs -f relay

# Логи Caddy (SSL)
docker compose logs -f caddy

# Статус
docker compose ps

# Ресурси
docker stats
```

## Troubleshooting

| Проблема | Рішення |
|----------|---------|
| `Connection refused` на 443 | Перевірити Oracle Security List + iptables |
| SSL certificate error | Перевірити DNS (домен → IP), зачекати 5 хв |
| `Cannot connect to Docker` | `sudo usermod -aG docker $USER` + перелогін |
| VM не стартує | Перевірити Always Free eligibility у вашому регіоні |
| Повільно | Oracle Free = 1 OCPU, нормально для relay |
