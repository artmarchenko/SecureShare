# SecureShare Relay — VPS Info

## Oracle Cloud Instance

| Параметр | Значення |
|----------|---------|
| **Provider** | Oracle Cloud (Always Free Tier) |
| **Instance Name** | `secureshare-relay` |
| **Region** | `eu-amsterdam-1` (Netherlands) |
| **Availability Domain** | `jvuR:eu-amsterdam-1-AD-1` |
| **Shape** | `VM.Standard.E2.1.Micro` (Always Free) |
| **CPU** | 1 OCPU / 2 vCPUs (AMD EPYC 7551) |
| **RAM** | 1 GB |
| **Boot Volume** | 46.6 GB |
| **OS** | Ubuntu 22.04 (kernel 6.8.0-1041-oracle) |
| **Public IP** | `84.235.175.29` |
| **Private IP** | `10.0.1.15` |

## OCIDs

```
Instance:       ocid1.instance.oc1.eu-amsterdam-1.anqw2ljrlzifl6qcw5ag3w4tamjv7cyeki64pcjp6dqppdll5dhmp3qhqlya
VCN:            ocid1.vcn.oc1.eu-amsterdam-1.amaaaaaalzifl6qazwgy6pyx6ffs4ymnbgk2ubknqdlp5zzkkscclx6fx2ha
Subnet:         ocid1.subnet.oc1.eu-amsterdam-1.aaaaaaaaqy3p22c7ajg4gzzosn2dxvqqnaj4es2zmwsw3z77qnkxs2u4rlqa
Internet GW:    ocid1.internetgateway.oc1.eu-amsterdam-1.aaaaaaaasfmrmssuqnvlxgw5ljvysw2245bdschh5k3a6tee6tea5hqrrdza
Route Table:    ocid1.routetable.oc1.eu-amsterdam-1.aaaaaaaaqh4vngtflhdkf3xhwe55abp4aynryupegqhpbmsu5ss6bj3gpzxq
Security List:  ocid1.securitylist.oc1.eu-amsterdam-1.aaaaaaaaqcligctvvdg2gddapb6ypzi6aycifruf3gjetzfysime6qal7r7q
Tenancy:        ocid1.tenancy.oc1..aaaaaaaajjr7bgx72ovtrpngvr2qwwr6i2pggszfol2q6o5rj5w7dtarkw4a
User:           ocid1.user.oc1..aaaaaaaaglv77izujb4syikbrbhtqoucr2kb7c57agqrsj2heoxwvyegshmq
```

## Мережа

### Відкриті порти (Security List + iptables)

| Порт | Протокол | Призначення |
|------|----------|-------------|
| 22 | TCP | SSH |
| 80 | TCP | HTTP (Let's Encrypt cert) |
| 443 | TCP | HTTPS (relay через Caddy) |
| 8765 | TCP | WebSocket relay (прямий, для тестування) |

### VCN

- CIDR: `10.0.0.0/16`
- Subnet: `10.0.1.0/24` (public)
- Internet Gateway: налаштований
- Default route: `0.0.0.0/0` → Internet Gateway

## SSH доступ

```powershell
# Підключитись:
ssh -i C:\Users\artma\.ssh\secureshare_vps ubuntu@84.235.175.29

# Або коротко (додати в ~/.ssh/config):
# Host relay
#     HostName 84.235.175.29
#     User ubuntu
#     IdentityFile C:\Users\artma\.ssh\secureshare_vps
```

### SSH ключі

| Файл | Призначення |
|------|-------------|
| `C:\Users\artma\.ssh\secureshare_vps` | Приватний ключ (ED25519) |
| `C:\Users\artma\.ssh\secureshare_vps.pub` | Публічний ключ |

## OCI CLI

### Конфігурація

| Файл | Призначення |
|------|-------------|
| `C:\Users\artma\.oci\config` | OCI CLI конфіг |
| `C:\Users\artma\.oci\oci_api_key.pem` | API приватний ключ (RSA 2048) |
| `C:\Users\artma\.oci\oci_api_key_public.pem` | API публічний ключ |

### Корисні команди

```powershell
$env:SUPPRESS_LABEL_WARNING="True"

# Статус VM
oci compute instance get --instance-id ocid1.instance.oc1.eu-amsterdam-1.anqw2ljrlzifl6qcw5ag3w4tamjv7cyeki64pcjp6dqppdll5dhmp3qhqlya --output table

# Перезапустити VM
oci compute instance action --instance-id ocid1.instance.oc1.eu-amsterdam-1.anqw2ljrlzifl6qcw5ag3w4tamjv7cyeki64pcjp6dqppdll5dhmp3qhqlya --action SOFTRESET

# Зупинити VM
oci compute instance action --instance-id ocid1.instance.oc1.eu-amsterdam-1.anqw2ljrlzifl6qcw5ag3w4tamjv7cyeki64pcjp6dqppdll5dhmp3qhqlya --action STOP

# Запустити VM
oci compute instance action --instance-id ocid1.instance.oc1.eu-amsterdam-1.anqw2ljrlzifl6qcw5ag3w4tamjv7cyeki64pcjp6dqppdll5dhmp3qhqlya --action START
```

## Docker (на VPS)

### Relay сервер

```bash
# Статус
docker ps

# Логи
docker logs relay -f

# Перезапуск
docker restart relay

# Оновити (після зміни файлів)
cd ~/secureshare-relay
docker build -t secureshare-relay .
docker stop relay && docker rm relay
docker run -d --name relay --restart always -p 8765:8765 secureshare-relay

# Ресурси
docker stats relay
```

### Файли на VPS

```
~/secureshare-relay/
├── relay_server.py
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Домен та SSL

| Параметр | Значення |
|----------|---------|
| **Домен** | `secureshare-relay.duckdns.org` |
| **WSS URL** | `wss://secureshare-relay.duckdns.org` |
| **SSL** | Let's Encrypt (auto-renew через Caddy) |
| **DNS Provider** | DuckDNS (безкоштовно) |

✅ Протестовано та працює (2026-02-19)

## Вартість

| Компонент | Ціна |
|-----------|------|
| Oracle Cloud VM | $0 (Always Free) |
| DuckDNS домен | $0 |
| Let's Encrypt SSL | $0 |
| **Разом** | **$0** |

## Створено

- **Дата:** 2026-02-19
- **Автор:** Artem Marchenko
