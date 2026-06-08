# Gleipnir: IDS Institucional

Gleipnir es un proyecto defensivo y educativo para construir un IDS
institucional orientado a Ubuntu 24.04.4 LTS.

El objetivo del sistema sera monitorear una red institucional propia para:

- Validar equipos autorizados mediante listas blancas de IP/MAC.
- Registrar dominios observados en trafico DNS/HTTP.
- Comparar conexiones externas contra listas negras e inteligencia de amenazas.
- Enviar alertas al administrador mediante SMTP configurado con variables de
  entorno.
- Documentar arquitectura, operacion, proteccion de credenciales y analisis
  juridico mexicano.

## Estado actual - version 2.0

Este repositorio contiene modulos defensivos para configuracion segura, logging,
listas blancas/negras, parsing offline, replay, captura live, deteccion,
monitoreo DNS/HTTP, politicas de alerta, almacenamiento SQLite, inteligencia de
amenazas con cache, reportes filtrados, healthcheck, mantenimiento de retencion,
ejecucion 24/7 con systemd, dashboard 24/7 y CLI.

## Estructura base

- `src/`: codigo fuente del IDS.
- `tests/`: pruebas automatizadas.
- `docs/`: documentacion del proyecto y manual de usuario.
- `data/`: listas locales y base SQLite operativa si `IDS_DB_PATH` apunta ahi.
- `logs/`: bitacoras y reportes generados durante la ejecucion.

## Seguridad

No se deben incluir credenciales reales en el repositorio. La configuracion
sensible se manejara mediante un archivo `.env` local basado en `.env.example`.
No hay contrasenas ni API keys hardcodeadas.

## Instalacion rapida en Ubuntu 24.04.4 LTS

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev tcpdump whois git
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
gleipnir --help
cp .env.example .env
chmod 600 .env
mkdir -p data logs logs/reports
touch data/whitelist.csv
touch data/blacklist.txt
touch data/dashboard_users.json
touch data/gleipnir_events.db
chmod 600 data/dashboard_users.json
gleipnir status #Debe aparecer todo en OK
gleipnir user create --username admin --role admin
```

Editar `.env` antes de ejecutar el IDS. No guardar credenciales reales en el
repositorio.

Variables operativas principales:

- `WHITELIST_FILE=data/whitelist.csv`
- `BLACKLIST_FILE=data/blacklist.txt`
- `LOG_DIR=logs/`
- `REPORT_DIR=logs/reports/`
- `IDS_DB_PATH=data/gleipnir_events.db`
- `ALERT_COOLDOWN_SECONDS=300`
- `ALERT_MAX_PER_MINUTE=5`
- `GLEIPNIR_INTERFACE=`: interfaz esperada para validacion con `gleipnir status`.
- `GLEIPNIR_MODE=live`: modo operativo esperado para despliegue.
- `HEALTH_LOG_INTERVAL_SECONDS=300`: intervalo de logs periodicos en modo
  `live --forever`.
- `EVENT_RETENTION_DAYS=30`: dias de eventos SQLite que se conservan.
- `MAX_LOG_SIZE_MB=50`: tamano maximo por archivo de log antes de rotar.
- `MAX_REPORTS_TO_KEEP=20`: cantidad maxima de archivos de reporte generados.
- `DASHBOARD_AUTH_ENABLED=true`: protege el dashboard con login y sesion local.
- `DASHBOARD_SECRET_KEY=`: clave local larga para firmar sesion y proteger
  formularios administrativos contra CSRF.
- `DASHBOARD_USERS_FILE=data/dashboard_users.json`: archivo local de usuarios
  del dashboard con hashes de contrasena no reversibles.
- `DASHBOARD_SESSION_COOKIE_SECURE=false`: cambiar a `true` si se usa HTTPS.
- `DASHBOARD_SESSION_TIMEOUT_MINUTES=30`: minutos antes de expirar la sesion
  web.
- `DASHBOARD_PASSWORD_MIN_LENGTH=12`: longitud minima para crear o cambiar
  contrasenas del dashboard.
- `DASHBOARD_LOGIN_MAX_ATTEMPTS=5`: intentos fallidos antes del bloqueo
  temporal.
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS=300`: duracion del bloqueo temporal de
  login en segundos.

## Captura live

La captura en vivo esta destinada solo a redes y dispositivos propios, con fines
defensivos y educativos. En Ubuntu 24.04.4 LTS puede requerir ejecutar el IDS
con `sudo` o asignar capacidades de captura al interprete/binario autorizado por
el administrador del sistema.

Ejemplo:

```bash
sudo gleipnir live --interface wlan0
```

Para ejecucion continua:

```bash
sudo gleipnir live --interface wlan0 --forever
```

`--forever` ejecuta ciclos supervisados de captura, reintenta errores
recuperables, mantiene contadores acumulados y emite logs periodicos
`LIVE_CAPTURE_HEALTH` segun `HEALTH_LOG_INTERVAL_SECONDS`.

## Servicio systemd

El repositorio incluye plantillas de servicio en `deploy/systemd/`.

Para la captura live, `deploy/systemd/gleipnir.service` usa `/opt/gleipnir`,
carga `/opt/gleipnir/.env` y ejecuta:

```bash
/opt/gleipnir/.venv/bin/gleipnir live --interface <INTERFAZ> --forever
```

Antes de copiar el servicio a `/etc/systemd/system/`, reemplazar `<INTERFAZ>`
por la interfaz autorizada y validar con `gleipnir status`.

Para el dashboard web 24/7, `deploy/systemd/gleipnir-dashboard.service` ejecuta:

```bash
/opt/gleipnir/.venv/bin/gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

Este servicio tambien carga `/opt/gleipnir/.env`. Al exponer el dashboard en red
local con `0.0.0.0`, mantener `DASHBOARD_AUTH_ENABLED=true`, definir
`DASHBOARD_SECRET_KEY` y crear `DASHBOARD_USERS_FILE` con usuarios `viewer` o
`admin` y `password_hash`. Ver `docs/dashboard_service.md`.

## CLI

Despues de instalar el proyecto en modo editable con `pip install -e .`, usar:

```bash
gleipnir --help
gleipnir test-config
gleipnir status
gleipnir maintenance
gleipnir dashboard --host 127.0.0.1 --port 8080
gleipnir offline --pcap archivo.pcap
gleipnir replay --pcap archivo.pcap --delay 1
sudo gleipnir live --interface wlan0
sudo gleipnir live --interface wlan0 --forever
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

## Dashboard Web

El dashboard local permite visualizar eventos del IDS desde navegador en modo
solo lectura:

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

En Ubuntu Desktop se abre manualmente:

```text
http://127.0.0.1:8080
```

En Ubuntu Server, para acceso desde otro equipo de la misma red:

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

Luego acceder desde navegador con:

```text
http://<IP_DEL_SERVIDOR>:8080
```

Usar `0.0.0.0` expone el dashboard en todas las interfaces del servidor. La CLI
rechaza esa ejecucion si no se agrega `--allow-lan`. Hacerlo solo en redes
locales o laboratorios controlados y no exponerlo a internet. El dashboard no
abre navegador automaticamente, no muestra secretos del `.env`. La vista
principal y `/events` aceptan filtros por tipo, severidad, IP origen/destino,
MAC origen, dominio, protocolo y fechas. La vista incluye graficas simples sin
internet: eventos por tipo, severidad, hora, top dominios, top IPs externas y
alertas enviadas/suprimidas.

Si `DASHBOARD_AUTH_ENABLED=false`, la CLI bloquea `--host 0.0.0.0` incluso con
`--allow-lan`. Para una demo muy controlada puede usarse
`--allow-unauthenticated-lan`, pero no se recomienda.

Para proteger el dashboard, configurar en `.env`:

```bash
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_SECRET_KEY=<CLAVE_LARGA_ALEATORIA>
DASHBOARD_USERS_FILE=data/dashboard_users.json
DASHBOARD_SESSION_COOKIE_SECURE=false
DASHBOARD_SESSION_TIMEOUT_MINUTES=30
DASHBOARD_PASSWORD_MIN_LENGTH=12
DASHBOARD_LOGIN_MAX_ATTEMPTS=5
DASHBOARD_LOGIN_LOCKOUT_SECONDS=300
```

Los usuarios ya no se guardan en `.env`. Se guardan en el archivo indicado por
`DASHBOARD_USERS_FILE`, usando hashes seguros no reversibles. Las contrasenas
no se encriptan de forma reversible porque no deben poder recuperarse en texto
plano; Gleipnir solo necesita verificar que la contrasena ingresada produce un
hash valido.

```json
[
  {
    "username": "admin",
    "password_hash": "<HASH_GENERADO>",
    "role": "admin",
    "enabled": true,
    "created_at": "2026-06-07T00:00:00Z"
  }
]
```

Para generar un hash sin mostrar la contrasena en pantalla:

```bash
python - <<'PY'
from getpass import getpass
from werkzeug.security import generate_password_hash
print(generate_password_hash(getpass("Contrasena del dashboard: ")))
PY
```

No versionar `data/dashboard_users.json`. Las variables antiguas
`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`, `DASHBOARD_ROLE`,
`DASHBOARD_ADMIN_USERNAME` y `DASHBOARD_ADMIN_PASSWORD` estan deprecadas; si
siguen presentes, Gleipnir muestra advertencia y no las usa por defecto para
autenticar. No guardar credenciales del dashboard en texto plano dentro de
`.env`.

Tambien se pueden administrar usuarios sin editar JSON a mano:

```bash
gleipnir user list
gleipnir user migrate-env
gleipnir user create --username viewer --role viewer
gleipnir user create --username admin --role admin
gleipnir user disable --username viewer
gleipnir user enable --username viewer
gleipnir user change-password --username admin
```

Si un despliegue antiguo todavia tiene `DASHBOARD_USERNAME` y
`DASHBOARD_PASSWORD` en `.env`, ejecutar una sola vez:

```bash
gleipnir user migrate-env
```

El comando lee `DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD` y, si existe,
`DASHBOARD_ROLE`; crea el usuario equivalente en `DASHBOARD_USERS_FILE` con
`password_hash`; y no imprime contrasena ni hash. Si el usuario ya existe, no
lo duplica. Al terminar, no modifica `.env`: el operador debe eliminar
manualmente `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD`.

Los comandos `create` y `change-password` solicitan la contrasena con `getpass`
y confirmacion. No existe opcion `--password` para evitar que la contrasena
quede visible en historial de shell, procesos o logs. Solo se guarda
`password_hash` en `DASHBOARD_USERS_FILE`.

La politica de contrasenas se aplica al crear usuarios y al cambiar contrasena:
longitud minima `DASHBOARD_PASSWORD_MIN_LENGTH` (12 por defecto), al menos una
minuscula, una mayuscula, un numero y un simbolo, y rechazo de contrasenas
comunes como `admin`, `password`, `password123`, `12345678`, `gleipnir` y
`qwerty`.

Proteccion contra fuerza bruta: `DASHBOARD_LOGIN_MAX_ATTEMPTS` define el maximo
de intentos fallidos y `DASHBOARD_LOGIN_LOCKOUT_SECONDS` el bloqueo temporal.
Los fallos de login se auditan como `ADMIN_LOGIN_FAILED` y los bloqueos como
`LOGIN_LOCKED`, sin guardar contrasenas ni hashes.

En Ubuntu se recomienda proteger el archivo local de usuarios:

```bash
chmod 600 data/dashboard_users.json
```

Si `DASHBOARD_AUTH_ENABLED=false`, el dashboard permite acceso sin login. Al
usar `--host 0.0.0.0`, mantener la autenticacion activa. Con autenticacion
activa, el dashboard ofrece `/login` y `/logout`, usa sesion Flask con
expiracion y cookies `HttpOnly` con `SameSite=Lax`. `DASHBOARD_SESSION_COOKIE_SECURE`
debe cambiarse a `true` cuando el dashboard este detras de HTTPS.

El dashboard tambien acepta HTTP Basic Auth para compatibilidad local, pero
Basic Auth no cifra credenciales por si solo. Usarlo solo en `localhost` o una
red local confiable. Si se expone fuera del equipo, usar HTTPS mediante reverse
proxy y no publicarlo en internet. Para produccion real se requeriria
autenticacion mas robusta. Ver `docs/dashboard_https_reverse_proxy.md` para una
guia conceptual con Nginx o Caddy y `docs/security.md` para el checklist de
despliegue seguro.

Con `DASHBOARD_AUTH_ENABLED=true`, tambien queda disponible una seccion
administrativa opcional:

```text
http://<IP_DEL_SERVIDOR>:8080/admin/lists
```

Desde ahi se puede listar, agregar, eliminar y validar whitelist y blacklist
usando los archivos configurados en `WHITELIST_FILE` y `BLACKLIST_FILE`. Esta
seccion no esta disponible cuando la autenticacion esta desactivada y requiere
rol `admin`. Un usuario `viewer` puede ver el dashboard, eventos, filtros y
graficas, pero recibe acceso denegado en `/admin/lists`. Las vistas de eventos
siguen siendo de solo lectura. Las acciones administrativas se registran en logs
y, si SQLite esta disponible, como eventos `ADMIN_LIST_ACTION`. Todos los
formularios administrativos usan token CSRF firmado con `DASHBOARD_SECRET_KEY`.
El dashboard agrega cabeceras HTTP defensivas (`X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Cache-Control` y CSP basica) y registra
auditoria administrativa (`ADMIN_LOGIN_*`, `ADMIN_LOGOUT`,
`ADMIN_WHITELIST_*`, `ADMIN_BLACKLIST_*`) sin guardar contrasenas, tokens CSRF
ni secretos.

Checklist minimo del dashboard:

- `.env` local fuera de Git.
- `DASHBOARD_SECRET_KEY` definido.
- Usuario `admin` creado con `gleipnir user create --username admin --role admin`.
- Usuario `viewer` creado si se requiere una cuenta de solo lectura.
- Credenciales antiguas `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD` eliminadas
  del `.env` despues de `gleipnir user migrate-env`.
- `data/dashboard_users.json` fuera de Git y con permisos `600` en Ubuntu.
- `DASHBOARD_AUTH_ENABLED=true` al usar `0.0.0.0`.
- HTTPS con reverse proxy si se usa fuera de localhost.
- Firewall o segmentacion restringiendo acceso.
- Revisar logs y eventos de auditoria.

Para dejar el dashboard activo 24/7 en Ubuntu Server 24.04 LTS, instalar el
servicio:

```bash
sudo cp /opt/gleipnir/deploy/systemd/gleipnir-dashboard.service /etc/systemd/system/gleipnir-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable gleipnir-dashboard
sudo systemctl start gleipnir-dashboard
sudo systemctl status gleipnir-dashboard
journalctl -u gleipnir-dashboard -f
```

Luego acceder desde un navegador de la misma red:

```text
http://<IP_DEL_SERVIDOR>:8080
```

No ejecutar este servicio sin autenticacion cuando se expone con
`--host 0.0.0.0 --allow-lan`.

`gleipnir replay` y `gleipnir live` usan el orquestador central `IDSEngine`,
que coordina configuracion, logging, whitelist, blacklist, deteccion DNS/HTTP,
threat intelligence, politicas de alerta y persistencia SQLite.

Para ejecucion 24/7 con systemd, usar `gleipnir live --interface <INTERFAZ>
--forever`. Este modo reinicia ciclos de captura ante errores recuperables,
mantiene contadores acumulados y escribe logs de salud segun
`HEALTH_LOG_INTERVAL_SECONDS`.

El comando `report` genera archivos JSON y CSV en `REPORT_DIR` si esta definido;
si no, usa `LOG_DIR`. Los datos acumulados se leen desde la base SQLite local
configurada con `IDS_DB_PATH`, por defecto `data/gleipnir_events.db`.

## Healthcheck

El comando `gleipnir status` valida el estado local del IDS antes de operar o
antes de habilitarlo como servicio 24/7:

```bash
gleipnir status
```

Verifica configuracion, existencia de whitelist/blacklist, escritura en
`LOG_DIR`, acceso a `REPORT_DIR` si existe, base SQLite si ya fue creada,
disponibilidad SMTP mediante una prueba `NOOP` sin autenticarse ni enviar correo,
y disponibilidad de `GLEIPNIR_INTERFACE` cuando se define en `.env`.

La salida usa `OK`, `WARNING` y `ERROR`. El comando regresa codigo `0` cuando no
hay errores criticos y `1` cuando detecta un `ERROR`.

Ejemplo:

```text
Gleipnir status
OK      | configuration | Configuration loaded successfully.
OK      | whitelist     | File exists: data/whitelist.csv
OK      | blacklist     | File exists: data/blacklist.txt
OK      | log_dir       | Directory is writable: logs
WARNING | sqlite        | Database does not exist yet: data/gleipnir_events.db
OK      | smtp          | SMTP endpoint is reachable: smtp.example.org:587
OK      | interface     | Configured interface is available: wlan0
```

Filtros disponibles para reportes:

- `--format both|json|csv`: controla si se exportan ambos formatos o solo uno.
- `--type EVENT_TYPE`: filtra eventos como `UNAUTHORIZED_DEVICE`,
  `BLACKLISTED_EXTERNAL_IP`, `DNS_EVENT`, `HTTP_EVENT`, `ALERT_SENT` o
  `ALERT_SUPPRESSED`.
- `--since YYYY-MM-DD` y `--until YYYY-MM-DD`: filtran por rango de fechas.
- `--source-ip IP`: filtra por IP origen.
- `--domain dominio`: filtra dominios DNS/HTTP por coincidencia parcial.
- `--severity high|medium|low|info`: filtra severidad; tambien acepta
  `alta`, `media` y `baja`.

## Politicas de alerta

Para evitar correos repetidos, el IDS aplica una politica antes de llamar al
envio SMTP. Las alertas repetidas se agrupan por evento y origen/destino, se
registran en logs y SQLite, y pueden quedar como `ALERT_SUPPRESSED` cuando no
se envia correo.

Variables configurables en `.env`:

```bash
ALERT_COOLDOWN_SECONDS=300
ALERT_MAX_PER_MINUTE=5
```

Las severidades normalizadas son `low`, `medium`, `high` y `critical`. Los
eventos criticos no se bloquean por cooldown ni por limite por minuto.

## Retencion y mantenimiento

Para evitar crecimiento ilimitado durante ejecucion 24/7:

```bash
gleipnir maintenance
```

El comando aplica estas politicas:

- Elimina de SQLite eventos con `timestamp` anterior a `EVENT_RETENTION_DAYS`.
- Conserva solo los ultimos `MAX_REPORTS_TO_KEEP` archivos de reporte
  `gleipnir_report_*.json` o `gleipnir_report_*.csv`.
- Valida que el logger use rotacion por tamano con `MAX_LOG_SIZE_MB`.

No borra eventos recientes ni archivos ajenos al patron de reportes de
Gleipnir. La limpieza se registra en logs y muestra un resumen en consola.

## Threat Intelligence

Gleipnir consulta AbuseIPDB, VirusTotal y Whois solo cuando el flujo normal del
IDS genera un evento `BLACKLISTED_EXTERNAL_IP`. No consulta servicios externos
para todo el trafico. Las API keys se leen desde `.env` y los resultados se
guardan en cache local dentro de `LOG_DIR` para evitar consultas repetidas.

Si no hay API key, timeout, rate limit o error de red, el IDS sigue funcionando
y registra el resultado estructurado sin imprimir secretos.

## Administracion de listas

Los comandos administrativos usan las rutas configuradas en `.env`:
`WHITELIST_FILE` y `BLACKLIST_FILE`.

Whitelist:

```bash
gleipnir whitelist list
gleipnir whitelist add --ip 192.168.1.10 --mac AA:BB:CC:DD:EE:FF --description "Laptop laboratorio"
gleipnir whitelist remove --ip 192.168.1.10
gleipnir whitelist validate
```

Blacklist:

```bash
gleipnir blacklist list
gleipnir blacklist add --ip 8.8.8.8 --reason "IP externa reportada como peligrosa"
gleipnir blacklist remove --ip 8.8.8.8
gleipnir blacklist validate
```

## Documentacion

- `docs/manual_usuario.md`: instalacion, operacion y troubleshooting.
- `docs/arquitectura.md`: arquitectura modular y flujo del sistema.
- `docs/modelo_osi.md`: relacion de Gleipnir con capas OSI.
- `docs/credenciales.md`: proteccion de secretos y datos operativos.
- `docs/analisis_juridico_mexico.md`: consideraciones legales mexicanas.
- `docs/dashboard.md`: dashboard web local con vistas de eventos de solo
  lectura y administracion opcional de listas.
- `docs/dashboard_service.md`: despliegue 24/7 del dashboard con systemd.
- `docs/dashboard_https_reverse_proxy.md`: despliegue conceptual con HTTPS,
  Nginx o Caddy como reverse proxy.
- `docs/security.md`: medidas de seguridad del dashboard, riesgos mitigados y
  checklist de despliegue seguro.
