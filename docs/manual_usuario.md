# Manual de Usuario - Gleipnir IDS Institucional

## 1. Objetivo

Gleipnir es un IDS institucional defensivo y educativo para redes propias. Su
objetivo es apoyar al administrador en:

- Validar dispositivos mediante lista blanca de IP/MAC.
- Detectar dispositivos no autorizados.
- Registrar trafico DNS y HTTP cuando esos datos estan disponibles.
- Comparar destinos externos contra una lista negra local.
- Enviar alertas por SMTP cuando el modulo correspondiente lo determine.
- Enriquecer IPs externas con AbuseIPDB, VirusTotal y Whois.
- Guardar eventos en SQLite para generar reportes acumulados JSON y CSV.
- Aplicar politicas de alerta para evitar correos repetidos.
- Verificar salud operativa con `gleipnir status`.
- Ejecutar mantenimiento de retencion con `gleipnir maintenance`.
- Operar en modo 24/7 con `systemd` y `gleipnir live --forever`.

El sistema no implementa ataques, explotacion, evasion, spoofing ni descifrado
de trafico cifrado.

## 2. Sistema operativo recomendado

Sistema objetivo: Ubuntu 24.04.4 LTS.

El desarrollo actual tambien puede ejecutarse en otros sistemas para pruebas
offline, pero la captura live esta pensada para Linux con permisos de captura de
paquetes.

## 3. Requisitos

Paquetes del sistema en Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev tcpdump whois
```

Entorno Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
gleipnir --help
```

Para ejecutar pruebas automatizadas se puede instalar tambien el extra de
pruebas o usar `requirements.txt`:

```bash
python -m pip install -e ".[test]"
```

Directorios esperados:

```bash
mkdir -p data logs logs/reports
```

## 4. Configuracion con .env

Copiar la plantilla:

```bash
cp .env.example .env
chmod 600 .env
```

Editar `.env` con valores reales solo en el equipo de despliegue:

```env
SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_USER=alerts@example.org
SMTP_PASSWORD=
ADMIN_EMAIL=admin@example.org

WHITELIST_FILE=data/whitelist.csv
BLACKLIST_FILE=data/blacklist.txt
LOG_DIR=logs/
REPORT_DIR=logs/reports/
IDS_DB_PATH=data/gleipnir_events.db

ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
THREAT_INTEL_TIMEOUT_SECONDS=10
THREAT_INTEL_CACHE_TTL_SECONDS=86400

ALERT_COOLDOWN_SECONDS=300
ALERT_MAX_PER_MINUTE=5

GLEIPNIR_INTERFACE=
GLEIPNIR_MODE=live
HEALTH_LOG_INTERVAL_SECONDS=300
EVENT_RETENTION_DAYS=30
MAX_LOG_SIZE_MB=50
MAX_REPORTS_TO_KEEP=20
```

No subir `.env` al repositorio. La configuracion se valida con:

```bash
gleipnir test-config
gleipnir status
```

`gleipnir test-config` muestra valores redactados, no secretos. `gleipnir
status` revisa configuracion, listas, directorios, SQLite si existe,
disponibilidad SMTP sin enviar correo real y la interfaz configurada si
`GLEIPNIR_INTERFACE` esta definida.

## 5. Lista blanca

Archivo por defecto: `data/whitelist.csv`.

Formato CSV:

```csv
ip,mac,description
192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop administracion
2001:db8::10,00:11:22:33:44:55,Servidor pruebas IPv6
```

Campos:

- `ip`: IPv4 o IPv6 del dispositivo autorizado.
- `mac`: direccion MAC en formato `aa:bb:cc:dd:ee:ff` o con guiones.
- `description`: descripcion administrativa.

El modulo valida IP y MAC. Si el archivo esta mal formado, se reporta error con
informacion de la linea.

Administracion desde CLI:

```bash
gleipnir whitelist list
gleipnir whitelist add --ip 192.168.1.10 --mac AA:BB:CC:DD:EE:FF --description "Laptop administracion"
gleipnir whitelist remove --ip 192.168.1.10
gleipnir whitelist validate
```

## 6. Lista negra

Archivo por defecto: `data/blacklist.txt`.

Formato TXT:

```text
# Una IP por linea
8.8.8.8
2001:4860:4860::8888
```

Solo se aceptan IPs individuales. El codigo actual no acepta rangos CIDR en la
lista negra.

Administracion desde CLI:

```bash
gleipnir blacklist list
gleipnir blacklist add --ip 8.8.8.8 --reason "IP externa reportada como peligrosa"
gleipnir blacklist remove --ip 8.8.8.8
gleipnir blacklist validate
```

## 7. Modo offline

Procesa un PCAP sin retrasos y sin abrir interfaces de red:

```bash
gleipnir offline --pcap archivo.pcap
```

Este modo usa `sniffer.parse_pcap()` para convertir paquetes Ethernet IPv4/IPv6
en `PacketEvent`.

## 8. Modo replay

Reproduce un PCAP como simulacion de trafico:

```bash
gleipnir replay --pcap archivo.pcap --delay 1
```

El parametro `--delay` agrega una espera entre paquetes. Este modo envia eventos
al orquestador central `IDSEngine`, que coordina deteccion IP/MAC, DNS/HTTP,
blacklist, threat intelligence, alertas y SQLite. No abre una interfaz real.

## 9. Modo live

Captura trafico observado en una interfaz propia:

```bash
sudo gleipnir live --interface wlan0
```

Opciones adicionales:

```bash
sudo gleipnir live --interface wlan0 --packet-count 100 --timeout 60
sudo gleipnir live --interface wlan0 --forever
```

La captura live usa Scapy y filtra ARP, IPv4 e IPv6. El monitor puede extraer
DNS/HTTP cuando Scapy entrega esas capas o payloads legibles. No descifra HTTPS.
El flujo live tambien usa `IDSEngine`.

`--forever` esta pensado para ejecucion 24/7, especialmente bajo `systemd`.
Ejecuta ciclos supervisados de captura, reintenta errores recuperables, mantiene
contadores acumulados y registra `LIVE_CAPTURE_HEALTH` cada
`HEALTH_LOG_INTERVAL_SECONDS`. No oculta errores criticos como interfaz invalida,
falta de permisos de captura o Scapy ausente.

## 10. Permisos para captura live

En Ubuntu, la captura de paquetes normalmente requiere permisos elevados:

```bash
sudo gleipnir live --interface wlan0
```

Como alternativa administrada, se pueden asignar capacidades al interprete del
entorno virtual, evaluando el riesgo operativo:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
getcap $(readlink -f .venv/bin/python)
```

La captura debe usarse solo en redes propias y autorizadas.

## 11. Ejecucion 24/7 con systemd

La plantilla del servicio esta en:

```text
deploy/systemd/gleipnir.service
```

El servicio esperado usa:

```ini
WorkingDirectory=/opt/gleipnir
EnvironmentFile=/opt/gleipnir/.env
ExecStart=/opt/gleipnir/.venv/bin/gleipnir live --interface <INTERFAZ> --forever
Restart=always
RestartSec=5
```

Flujo recomendado en Ubuntu 24.04 LTS:

```bash
sudo mkdir -p /opt/gleipnir
sudo cp -a . /opt/gleipnir/
cd /opt/gleipnir
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
chmod 600 .env
gleipnir test-config
gleipnir status
```

Despues se edita `<INTERFAZ>`, se copia el servicio a
`/etc/systemd/system/gleipnir.service` y se gestiona con `systemctl`. No incluir
credenciales en el archivo `.service`; deben permanecer en `.env`.

## 12. Alertas SMTP

Las alertas usan `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` y
`ADMIN_EMAIL` desde `.env`.

El modulo `src/mailer.py` usa TLS mediante `starttls()`. Las pruebas usan mocks
y no envian correos reales.

Si no llegan alertas:

- Verificar usuario, password o password de aplicacion del proveedor SMTP.
- Revisar carpeta de spam.
- Confirmar que `SMTP_PORT` sea correcto, normalmente `587`.
- Validar que el proveedor permita SMTP desde la red institucional.
- Ejecutar `gleipnir test-config`.

## 13. Politicas de alerta

Antes de llamar a SMTP, Gleipnir evalua una politica para evitar correos
repetidos:

- `ALERT_COOLDOWN_SECONDS`: tiempo minimo entre alertas del mismo grupo.
- `ALERT_MAX_PER_MINUTE`: maximo de correos por minuto.

Los eventos repetidos se siguen registrando en logs y SQLite. Cuando se suprime
un correo, se guarda `ALERT_SUPPRESSED`; cuando se envia, se guarda
`ALERT_SENT`. Las severidades normalizadas son:

- `low`
- `medium`
- `high`
- `critical`

La severidad `critical` no se bloquea por cooldown ni por limite por minuto.

## 14. Threat Intelligence

El modulo `src/threat_intel.py` permite consultar:

- AbuseIPDB.
- VirusTotal.
- Whois local mediante comando `whois`.

Si `ABUSEIPDB_API_KEY` o `VIRUSTOTAL_API_KEY` estan vacias, el modulo devuelve
estado `skipped` y el IDS continua funcionando. Los errores de red, timeout y
rate limit se manejan como resultados estructurados.

El cache se guarda por defecto en:

```text
LOG_DIR/threat_intel_cache.json
```

Las consultas de threat intelligence se hacen solo cuando existe una IP externa
relevante o en blacklist; no se consultan APIs para todo el trafico.

## 15. SQLite

Los eventos del IDS se guardan en una base SQLite local configurada con:

```env
IDS_DB_PATH=data/gleipnir_events.db
```

La tabla `ids_events` conserva campos como tipo de evento, timestamp,
severidad, IP/MAC origen, IP/MAC destino, protocolo, dominio, mensaje y
`raw_json` sanitizado. No debe contener secretos.

Eventos principales:

- `AUTHORIZED_DEVICE`
- `UNAUTHORIZED_DEVICE`
- `DNS_EVENT`
- `HTTP_EVENT`
- `BLACKLISTED_EXTERNAL_IP`
- `THREAT_INTEL_RESULT`
- `ALERT_SENT`
- `ALERT_SUPPRESSED`

## 16. Reportes

Generar reportes acumulados desde SQLite:

```bash
gleipnir report
gleipnir report --format json
gleipnir report --format csv
gleipnir report --type UNAUTHORIZED_DEVICE
gleipnir report --type BLACKLISTED_EXTERNAL_IP
gleipnir report --since 2026-06-01 --until 2026-06-07
gleipnir report --source-ip 192.168.1.10
gleipnir report --domain ejemplo.com
gleipnir report --severity high
```

Los reportes se guardan en `REPORT_DIR` si esta definido; si no, en `LOG_DIR`.
Se generan dos formatos:

- JSON: estructura completa con resumen y secciones por tipo de evento.
- CSV: formato tabular, una fila por evento con columna `category`.

Filtros disponibles:

- Formato: `both`, `json`, `csv`.
- Tipo de evento.
- Rango de fechas.
- IP origen.
- Dominio DNS/HTTP.
- Severidad.

Los reportes no deben contener contrasenas, API keys, tokens ni secretos y
muestran un resumen en consola.

## 17. Politica de retencion

Para evitar crecimiento ilimitado durante ejecucion 24/7:

```bash
gleipnir maintenance
```

El comando:

- Elimina eventos SQLite anteriores a `EVENT_RETENTION_DAYS`.
- Conserva solo los ultimos `MAX_REPORTS_TO_KEEP` reportes generados por
  Gleipnir.
- Valida que los logs roten por tamano con `MAX_LOG_SIZE_MB`.

No borra eventos recientes ni archivos que no coincidan con el patron de
reportes `gleipnir_report_*.json` o `gleipnir_report_*.csv`.

## 18. Pruebas

Cuando las dependencias esten instaladas:

```bash
python -m pytest tests
```

Sin `pytest`, muchos modulos tambien pueden validarse con `unittest`:

```bash
python -m unittest discover -s tests
```

## 19. Troubleshooting basico

- Error de `.env`: ejecutar `gleipnir test-config`.
- Estado operativo dudoso: ejecutar `gleipnir status`.
- Error de permisos live: usar `sudo` o capacidades de captura autorizadas.
- Servicio 24/7 se reinicia: revisar `journalctl -u gleipnir -f` y logs.
- No hay dominios HTTP: el trafico HTTPS no expone host/ruta HTTP en texto claro.
- No hay resultados AbuseIPDB/VirusTotal: revisar API keys, timeout y rate
  limit.
- No se generan reportes: crear `LOG_DIR` o `REPORT_DIR` y revisar permisos de
  escritura; confirmar `IDS_DB_PATH`.
- Demasiadas alertas: ajustar `ALERT_COOLDOWN_SECONDS` y
  `ALERT_MAX_PER_MINUTE`.
- Crecimiento de datos: ejecutar `gleipnir maintenance` y revisar
  `EVENT_RETENTION_DAYS`, `MAX_LOG_SIZE_MB` y `MAX_REPORTS_TO_KEEP`.
- Alertas a spam: revisar reputacion del remitente, SPF/DKIM/DMARC del dominio
  y reglas del servidor de correo.
