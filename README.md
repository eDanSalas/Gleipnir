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
sudo apt install -y python3 python3-pip python3-venv libpcap-dev tcpdump whois
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
gleipnir --help
cp .env.example .env
chmod 600 .env
mkdir -p data logs logs/reports
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
- `DASHBOARD_AUTH_ENABLED=true`: protege el dashboard con HTTP Basic Auth.
- `DASHBOARD_USERNAME=`: usuario local para el dashboard.
- `DASHBOARD_PASSWORD=`: contrasena local del dashboard, nunca guardarla en
  codigo.

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
/opt/gleipnir/.venv/bin/gleipnir dashboard --host 0.0.0.0 --port 8080
```

Este servicio tambien carga `/opt/gleipnir/.env`. Al exponer el dashboard en red
local con `0.0.0.0`, mantener `DASHBOARD_AUTH_ENABLED=true` y configurar
`DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD`. Ver
`docs/dashboard_service.md`.

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
gleipnir dashboard --host 0.0.0.0 --port 8080
```

Luego acceder desde navegador con:

```text
http://<IP_DEL_SERVIDOR>:8080
```

Usar `0.0.0.0` expone el dashboard en la red local. Hacerlo solo en entornos
controlados. El dashboard no abre navegador automaticamente, no muestra secretos
del `.env`. La vista principal y `/events` aceptan filtros por tipo, severidad,
IP origen/destino, MAC origen, dominio, protocolo y fechas. La vista incluye
graficas simples sin internet: eventos por tipo, severidad, hora, top dominios,
top IPs externas y alertas enviadas/suprimidas.

Para proteger el dashboard, configurar en `.env`:

```bash
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=admin-local
DASHBOARD_PASSWORD=cambiar-esta-contrasena
```

Si `DASHBOARD_AUTH_ENABLED=false`, el dashboard permite acceso sin login. Al
usar `--host 0.0.0.0`, mantener la autenticacion activa. Esta proteccion usa
HTTP Basic Auth para un entorno local/laboratorio; no exponer el dashboard a
internet. Para produccion real se requeriria HTTPS y autenticacion mas robusta.

Con `DASHBOARD_AUTH_ENABLED=true`, tambien queda disponible una seccion
administrativa opcional:

```text
http://<IP_DEL_SERVIDOR>:8080/admin/lists
```

Desde ahi se puede listar, agregar, eliminar y validar whitelist y blacklist
usando los archivos configurados en `WHITELIST_FILE` y `BLACKLIST_FILE`. Esta
seccion no esta disponible cuando la autenticacion esta desactivada. Las vistas
de eventos siguen siendo de solo lectura. Las acciones administrativas se
registran en logs y, si SQLite esta disponible, como eventos
`ADMIN_LIST_ACTION`.

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
`--host 0.0.0.0`.

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
