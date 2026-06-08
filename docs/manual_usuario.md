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

Archivos base recomendados para una instalacion nueva:

```bash
touch data/blacklist.txt
echo "ip,mac,description" > data/whitelist.csv
echo "[ ]" > data/dashboard_users.json
touch data/gleipnir_events.db
chmod 600 data/dashboard_users.json
chmod 600 data/gleipnir_events.db
```

Significado de cada archivo:

- `data/blacklist.txt`: lista negra local. Puede iniciar vacia; despues cada
  linea debe contener una IP externa.
- `data/whitelist.csv`: lista blanca local. El encabezado correcto es
  `ip,mac,description`.
- `ip`: direccion IPv4 o IPv6 autorizada.
- `mac`: direccion MAC autorizada asociada al equipo.
- `description`: descripcion humana del equipo, por ejemplo area, propietario o
  ubicacion.
- `data/dashboard_users.json`: archivo local de cuentas del dashboard. `[ ]`
  es un arreglo JSON vacio; `gleipnir user create` lo actualiza con usuarios y
  `password_hash`.
- `data/gleipnir_events.db`: base SQLite local. Gleipnir crea las tablas cuando
  se inicializa el almacenamiento.

Despues de editar `.env` y crear los archivos base:

```bash
gleipnir user create --username admin --role admin
gleipnir test-config
gleipnir status
```

`gleipnir user create` pide la contrasena de forma interactiva con `getpass` y
no la muestra en pantalla. `gleipnir test-config` y `gleipnir status` deben
ejecutarse despues de completar `.env`; si SMTP, API keys o interfaz no estan
definidos para el entorno, el comando mostrara advertencias o errores claros.

## 4. Configuracion con .env

Copiar la plantilla en el equipo donde se ejecutara Gleipnir:

```bash
cp .env.example .env
chmod 600 .env
```

En Ubuntu Server, si el proyecto se instala en `/opt/gleipnir`, usar la misma
idea desde ese directorio:

```bash
cd /opt/gleipnir
sudo cp .env.example .env
sudo nano .env
sudo chmod 600 .env
```

Si el servicio `systemd` corre como `root`, el archivo puede quedar propiedad de
`root`. Si se ejecuta con un usuario dedicado, ese usuario debe poder leer
`/opt/gleipnir/.env`. No guardar secretos en el archivo `.service`; el servicio
debe leerlos desde `EnvironmentFile=/opt/gleipnir/.env`.

### Uso de valores entre llaves `{...}`

En esta guia, un valor escrito como `{VALOR}` significa "reemplace esto por el
valor real del entorno". Las llaves son un marcador visual; no son obligatorias
dentro del archivo `.env`.

Ejemplo de marcador:

```env
SMTP_HOST={SERVIDOR_SMTP}
```

Ejemplo ya configurado:

```env
SMTP_HOST=smtp.gmail.com
```

Para contrasenas, tokens o claves, usar valores reales solo en el equipo de
despliegue. No pegarlos en documentacion, capturas de pantalla ni repositorios.
Si se edita `.env` mientras los servicios estan activos, reiniciarlos para que
lean la configuracion nueva:

```bash
sudo systemctl restart gleipnir
sudo systemctl restart gleipnir-dashboard
```

### Plantilla base

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

DASHBOARD_AUTH_ENABLED=true
DASHBOARD_SECRET_KEY=<CLAVE_LARGA_ALEATORIA>
DASHBOARD_USERS_FILE=data/dashboard_users.json
DASHBOARD_SESSION_COOKIE_SECURE=false
DASHBOARD_SESSION_TIMEOUT_MINUTES=30
DASHBOARD_PASSWORD_MIN_LENGTH=12
DASHBOARD_LOGIN_MAX_ATTEMPTS=5
DASHBOARD_LOGIN_LOCKOUT_SECONDS=300
```

### Que va en cada variable

| Variable | Obligatoria | Que debe contener |
| --- | --- | --- |
| `SMTP_HOST` | Si | Host o IP del servidor SMTP, por ejemplo `{SERVIDOR_SMTP}`. |
| `SMTP_PORT` | Si | Puerto SMTP numerico. Normalmente `587` para TLS/STARTTLS. |
| `SMTP_USER` | Si | Usuario/cuenta SMTP que enviara alertas, por ejemplo `{CUENTA_ALERTAS}`. |
| `SMTP_PASSWORD` | Si | Contrasena o password de aplicacion de la cuenta SMTP. Es secreto. |
| `ADMIN_EMAIL` | Si | Correo del administrador que recibira alertas del IDS. |
| `WHITELIST_FILE` | Si | Ruta del CSV de lista blanca, por ejemplo `data/whitelist.csv`. |
| `BLACKLIST_FILE` | Si | Ruta del TXT de lista negra, por ejemplo `data/blacklist.txt`. |
| `LOG_DIR` | Si | Directorio donde Gleipnir escribira logs y cache operativo, por ejemplo `logs/`. |
| `REPORT_DIR` | No | Directorio de reportes JSON/CSV. Si se omite, se usa `LOG_DIR`. |
| `IDS_DB_PATH` | No | Ruta de la base SQLite de eventos, por ejemplo `data/gleipnir_events.db`. |
| `ABUSEIPDB_API_KEY` | No | API key de AbuseIPDB para threat intelligence. Dejar vacia si no se usara. |
| `VIRUSTOTAL_API_KEY` | No | API key de VirusTotal. Dejar vacia si no se usara. |
| `THREAT_INTEL_TIMEOUT_SECONDS` | No | Tiempo maximo de espera para APIs externas. Valor recomendado: `10`. |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | No | Tiempo de vida del cache de threat intelligence en segundos. `86400` equivale a 24 horas. |
| `ALERT_COOLDOWN_SECONDS` | No | Segundos para evitar correos repetidos del mismo evento. Valor recomendado: `300`. |
| `ALERT_MAX_PER_MINUTE` | No | Maximo de alertas por correo permitidas por minuto. Valor recomendado: `5`. |
| `GLEIPNIR_INTERFACE` | No | Interfaz esperada para captura live, por ejemplo `{INTERFAZ}` como `wlan0`, `eth0` o `ens33`. |
| `GLEIPNIR_MODE` | No | Modo operativo esperado: `offline`, `replay` o `live`. |
| `HEALTH_LOG_INTERVAL_SECONDS` | No | Intervalo de logs de salud en modo `live --forever`. Valor recomendado: `300`. |
| `EVENT_RETENTION_DAYS` | No | Dias que se conservan eventos en SQLite antes de mantenimiento. |
| `MAX_LOG_SIZE_MB` | No | Tamano maximo esperado para rotacion/validacion de logs, en MB. |
| `MAX_REPORTS_TO_KEEP` | No | Cantidad maxima de reportes generados que se conservaran. |
| `DASHBOARD_AUTH_ENABLED` | No | `true` para exigir login en dashboard; `false` solo para laboratorio local controlado. |
| `DASHBOARD_SECRET_KEY` | Si se activa auth | Clave larga y aleatoria para firmar sesion y tokens CSRF. Es secreto. |
| `DASHBOARD_USERS_FILE` | Si se activa auth | Ruta del JSON local de usuarios del dashboard con `password_hash`, por ejemplo `data/dashboard_users.json`. |
| `DASHBOARD_SESSION_COOKIE_SECURE` | No | `false` en HTTP local; `true` cuando se usa HTTPS con reverse proxy. |
| `DASHBOARD_SESSION_TIMEOUT_MINUTES` | No | Minutos antes de expirar la sesion del dashboard. Valor recomendado: `30`. |
| `DASHBOARD_PASSWORD_MIN_LENGTH` | No | Longitud minima para crear o cambiar contrasenas del dashboard. Valor recomendado: `12`. |
| `DASHBOARD_LOGIN_MAX_ATTEMPTS` | No | Intentos fallidos permitidos antes del bloqueo temporal. Valor recomendado: `5`. |
| `DASHBOARD_LOGIN_LOCKOUT_SECONDS` | No | Duracion del bloqueo temporal de login en segundos. Valor recomendado: `300`. |

Variables booleanas como `DASHBOARD_AUTH_ENABLED` y
`DASHBOARD_SESSION_COOKIE_SECURE` aceptan valores como `true` o `false`.
Variables numericas como `SMTP_PORT`, `EVENT_RETENTION_DAYS` y
`ALERT_MAX_PER_MINUTE` deben contener solo numeros.

### Usuarios del dashboard con hashes

Las contrasenas del dashboard no deben guardarse en `.env`. Tampoco se
encriptan de forma reversible: se almacenan como hashes no reversibles porque el
sistema no debe poder recuperar una contrasena en texto plano. El archivo
indicado por `DASHBOARD_USERS_FILE` debe contener usuarios con estos campos:
`username`, `password_hash`, `role`, `enabled` y `created_at`.

```json
[
  {
    "username": "admin",
    "password_hash": "<HASH_GENERADO>",
    "role": "admin",
    "enabled": true,
    "created_at": "2026-06-07T00:00:00Z"
  },
  {
    "username": "viewer",
    "password_hash": "<HASH_GENERADO>",
    "role": "viewer",
    "enabled": true,
    "created_at": "2026-06-07T00:00:00Z"
  }
]
```

Generar cada hash en Ubuntu:

```bash
python - <<'PY'
from getpass import getpass
from werkzeug.security import generate_password_hash
print(generate_password_hash(getpass("Contrasena del dashboard: ")))
PY
```

Copiar el resultado en `password_hash`. No copiar la contrasena real en el JSON.
No subir `data/dashboard_users.json` al repositorio. Las variables antiguas
`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`, `DASHBOARD_ROLE`,
`DASHBOARD_ADMIN_USERNAME` y `DASHBOARD_ADMIN_PASSWORD` estan deprecadas; si se
mantienen en `.env`, Gleipnir advierte que debe usarse `DASHBOARD_USERS_FILE` y
no las usa por defecto para autenticar.

Tambien se puede administrar el archivo de usuarios desde CLI:

```bash
gleipnir user list
gleipnir user migrate-env
gleipnir user create --username viewer --role viewer
gleipnir user create --username admin --role admin
gleipnir user disable --username viewer
gleipnir user enable --username viewer
gleipnir user change-password --username admin
```

Si un despliegue anterior usaba `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD`,
ejecutar `gleipnir user migrate-env` una sola vez. El comando crea el usuario en
`DASHBOARD_USERS_FILE` con `password_hash`, no imprime la contrasena ni el hash,
no duplica usuarios existentes y no modifica `.env`. Despues de verificar el
acceso, eliminar manualmente `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD`.

Los comandos que asignan contrasena usan `getpass` y piden confirmacion. No se
acepta `--password` para evitar que la contrasena quede guardada en historial de
shell, listados de procesos o registros. Solo se guarda `password_hash`.

Politica minima para crear o cambiar contrasenas del dashboard:

- Longitud minima configurable con `DASHBOARD_PASSWORD_MIN_LENGTH`.
- Al menos una minuscula.
- Al menos una mayuscula.
- Al menos un numero.
- Al menos un simbolo.
- Rechazo de contrasenas comunes: `admin`, `password`, `password123`,
  `12345678`, `gleipnir` y `qwerty`.

Esta politica no se aplica al login; el login solo verifica el hash guardado.

Proteccion contra fuerza bruta:

- `DASHBOARD_LOGIN_MAX_ATTEMPTS` limita intentos fallidos por usuario/IP.
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS` bloquea temporalmente nuevos intentos.
- Los intentos fallidos se auditan como `ADMIN_LOGIN_FAILED`.
- Los bloqueos se auditan como `LOGIN_LOCKED`.
- Los mensajes no revelan si el usuario existe y nunca imprimen contrasenas.

Permisos recomendados en Ubuntu:

```bash
chmod 600 data/dashboard_users.json
```

El archivo `data/dashboard_users.json` ya esta excluido en `.gitignore`; no debe
subirse al repositorio.

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

## 12. Dashboard web seguro

El dashboard permite visualizar eventos desde navegador. Para uso local:

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

Abrir:

```text
http://127.0.0.1:8080
```

Para red local/laboratorio con autenticacion activa:

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

`0.0.0.0` expone el dashboard en todas las interfaces; no usarlo para internet.
Si `DASHBOARD_AUTH_ENABLED=false`, la CLI bloquea `0.0.0.0` salvo con
`--allow-unauthenticated-lan`, opcion no recomendada.

Autenticacion:

- `DASHBOARD_AUTH_ENABLED=true` activa login y sesion.
- `DASHBOARD_USERS_FILE` apunta al JSON local de usuarios con `password_hash`.
- `viewer` puede ver dashboard, eventos, filtros y graficas.
- `admin` puede administrar whitelist/blacklist en `/admin/lists`.
- Los usuarios con `enabled=false` no pueden iniciar sesion.
- `DASHBOARD_SECRET_KEY` firma sesion y tokens CSRF.
- `DASHBOARD_SESSION_TIMEOUT_MINUTES` controla expiracion de sesion.
- `DASHBOARD_SESSION_COOKIE_SECURE=true` debe usarse cuando hay HTTPS.

Proteccion CSRF:

- Protege formularios administrativos de whitelist y blacklist.
- Si el token falta o es invalido, la accion se rechaza con HTTP 400.
- No se guardan tokens CSRF en auditoria.

Cabeceras HTTP:

- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY`.
- `Referrer-Policy: no-referrer`.
- `Cache-Control: no-store` en rutas autenticadas/administrativas.
- CSP basica con `default-src 'self'`.

Auditoria administrativa:

- `ADMIN_LOGIN_SUCCESS`
- `ADMIN_LOGIN_FAILED`
- `ADMIN_LOGOUT`
- `ADMIN_WHITELIST_ADD`
- `ADMIN_WHITELIST_REMOVE`
- `ADMIN_BLACKLIST_ADD`
- `ADMIN_BLACKLIST_REMOVE`

Los eventos guardan timestamp, usuario, accion, IP remota si existe, resultado
y mensaje. Nunca guardan contrasenas, tokens CSRF, API keys ni secretos.

HTTPS:

- Basic Auth y login de formulario no cifran la conexion por si solos.
- Para produccion real usar Nginx o Caddy como reverse proxy TLS.
- Mantener Gleipnir escuchando en `127.0.0.1` detras del proxy.
- Guia: `docs/dashboard_https_reverse_proxy.md`.

Checklist minimo:

- `.env` con permisos `600` y fuera de Git.
- `DASHBOARD_SECRET_KEY` definido.
- Usuario `admin` creado con `gleipnir user create --username admin --role admin`.
- Usuario `viewer` creado si se necesita una cuenta de solo lectura.
- Credenciales antiguas `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD` eliminadas
  del `.env` despues de migrar.
- `data/dashboard_users.json` con permisos `600` y fuera de Git.
- Autenticacion activa si se usa `0.0.0.0`.
- HTTPS si se usa fuera de localhost.
- Firewall restringido.
- Revisar logs/auditoria.

## 13. Alertas SMTP

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

## 14. Politicas de alerta

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

## 15. Threat Intelligence

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

## 16. SQLite

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
- `ADMIN_LOGIN_SUCCESS`
- `ADMIN_LOGIN_FAILED`
- `ADMIN_LOGOUT`
- `ADMIN_WHITELIST_ADD`
- `ADMIN_WHITELIST_REMOVE`
- `ADMIN_BLACKLIST_ADD`
- `ADMIN_BLACKLIST_REMOVE`

## 17. Reportes

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

## 18. Politica de retencion

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

## 19. Pruebas

Cuando las dependencias esten instaladas:

```bash
python -m pytest tests
```

Sin `pytest`, muchos modulos tambien pueden validarse con `unittest`:

```bash
python -m unittest discover -s tests
```

## 20. Troubleshooting basico

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
- Dashboard bloquea `0.0.0.0`: agregar `--allow-lan` solo si es red local
  autorizada y mantener autenticacion activa.
- Login dashboard falla: revisar `DASHBOARD_AUTH_ENABLED`, usuario, rol,
  `DASHBOARD_SECRET_KEY` y timeout de sesion.
- Administracion web rechaza cambios: verificar que el usuario tenga rol
  `admin` y que el formulario tenga token CSRF valido.
