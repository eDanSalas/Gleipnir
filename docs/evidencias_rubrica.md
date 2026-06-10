# Matriz de evidencias contra la rubrica

Este documento resume como demostrar que Gleipnir IDS cumple los requisitos
funcionales principales de la rubrica academica. El proyecto es defensivo,
educativo y esta pensado para redes propias o institucionales autorizadas.

## Matriz de cumplimiento

| Requisito de la rubrica | Modulo del sistema | Archivo(s) involucrados | Comando para demostrarlo | Prueba automatizada relacionada | Evidencia esperada | Estado |
|---|---|---|---|---|---|---|
| 1. Modulo de Listas Blancas Capa 2 y 3: leer IP/MAC autorizadas, validar formato y detectar/permitir equipos autorizados/no autorizados. | Whitelist + detector + capa IPS opcional | `src/whitelist.py`, `src/detector.py`, `src/runtime/engine.py`, `src/firewall.py`, `data/whitelist.csv` | `gleipnir whitelist validate`, `gleipnir whitelist list`, `gleipnir ips dry-run` | `python -m pytest tests/test_whitelist.py tests/test_detector.py tests/test_firewall.py tests/test_ips_engine.py tests/test_end_to_end_rubric.py` | CSV `ip,mac,description` validado; equipo registrado genera `AUTHORIZED_DEVICE`; no registrado genera `UNAUTHORIZED_DEVICE`. En modo IDS solo se observa; en modo IPS opcional (`allow_registered`/`block_unregistered`) se generan reglas nftables que permiten/bloquean. | Cumple (IDS observa; permitir/bloquear en IPS opcional) |
| 2. Correo inmediato al administrador ante IP/MAC no autorizada. | Detector + mailer + politica de alertas | `src/detector.py`, `src/mailer.py`, `src/alert_policy.py`, `src/runtime/engine.py` | Demo segura con prueba: `python -m pytest tests/test_end_to_end_rubric.py` | `tests/test_detector.py`, `tests/test_mailer.py`, `tests/test_runtime_engine.py`, `tests/test_end_to_end_rubric.py` | El mock de SMTP recibe un correo con asunto `UNAUTHORIZED_DEVICE` dirigido al administrador. No se envia correo real durante pruebas. | Cumple |
| 3. Configuracion facil del correo del administrador (identificacion, autenticacion y autorizacion). | Configuracion segura + CLI + Dashboard admin | `src/config.py`, `src/cli.py`, `src/dashboard/app.py`, `.env.example`, `docs/manual_usuario.md` | `gleipnir admin-email show`, `gleipnir admin-email set --email nuevo@example.org`, o seccion *Correo del administrador* en `/admin/lists` (rol admin) | `python -m pytest tests/test_config.py tests/test_cli.py tests/test_dashboard.py tests/test_runtime_engine.py` | Cambiar `ADMIN_EMAIL` cambia el destinatario sin modificar codigo; via CLI valida el formato y reescribe `.env`; via Dashboard requiere login + rol admin + CSRF y queda auditado. | Cumple |
| 4. Monitoreo de sitios mediante DNS/HTTP. | Monitor DNS/HTTP | `src/dns_http_monitor.py`, `src/sniffer.py`, `src/runtime/engine.py` | `gleipnir replay --pcap archivo.pcap --delay 1` o prueba sintetica `python -m pytest tests/test_dns_http_monitor.py`<br>`gleipnir report --type DNS_EVENT` &nbsp;&nbsp;# consultas DNS registradas<br>`gleipnir report --type HTTP_EVENT` &nbsp;&nbsp;# peticiones HTTP en claro<br>`gleipnir report --domain ejemplo.com` &nbsp;&nbsp;# filtrar por un dominio<br>`.venv/bin/python -m pytest tests/test_dns_http_monitor.py tests/test_end_to_end_rubric.py` | `tests/test_dns_http_monitor.py`, `tests/test_replay.py`, `tests/test_end_to_end_rubric.py` | Se extrae dominio DNS `ejemplo.com`, tipo de consulta `A`, Host HTTP `ejemplo.com`, metodo `GET` y ruta `/` cuando el trafico HTTP esta en claro. | Cumple |
| 5. Reporte o bitacora de dominios visitados. | SQLite + reportes + dashboard | `src/storage.py`, `src/reports.py`, `src/dashboard/app.py`, `src/dns_http_monitor.py` | `gleipnir report --domain ejemplo.com --format json` | `tests/test_storage.py`, `tests/test_reports.py`, `tests/test_dashboard_filters.py`, `tests/test_end_to_end_rubric.py` | Los eventos `DNS_EVENT` y `HTTP_EVENT` quedan en SQLite y reportes; el dominio/host aparece como `ejemplo.com`. | Cumple |
| 6. Deteccion de conexiones hacia IPs en blacklist (origen y destino). | Blacklist + detector de IP externa | `src/blacklist.py`, `src/detector.py`, `src/runtime/engine.py`, `data/blacklist.txt` | `gleipnir blacklist validate` y `gleipnir blacklist list` | `tests/test_blacklist.py`, `tests/test_detector.py`, `tests/test_runtime_engine.py`, `tests/test_end_to_end_rubric.py` | Se revisa `ip_destino` (`BLACKLISTED_EXTERNAL_IP_OUTBOUND`) e `ip_origen` (`BLACKLISTED_EXTERNAL_IP_INBOUND`); con `BLACKLIST_CHECK_PRIVATE=true` tambien IPs privadas (`BLACKLISTED_PRIVATE_IP`). Cada evento incluye direccion, riesgo, severidad y accion. | Cumple (revisa origen y destino, global/privado configurable) |
| 7. Alerta de Emergencia con tipo de riesgo. | Detector de IP peligrosa + mailer | `src/detector.py`, `src/alert_policy.py`, `src/mailer.py` | Demo segura con prueba: `python -m pytest tests/test_end_to_end_rubric.py` | `tests/test_detector.py`, `tests/test_runtime_engine.py`, `tests/test_end_to_end_rubric.py` | Se genera correo con asunto `ALERTA DE EMERGENCIA - IP peligrosa detectada` e incluye IP peligrosa, IP origen, timestamp, protocolo, severidad y riesgo `Botnet`. | Cumple |
| 8. Automatizacion forense Abuse/Whois. | Threat Intelligence | `src/threat_intel.py`, `src/runtime/engine.py` | `python -m pytest tests/test_threat_intel.py tests/test_runtime_engine.py` | `tests/test_threat_intel.py`, `tests/test_runtime_engine.py`, `tests/test_end_to_end_rubric.py` | Solo se consulta reputacion cuando existe `BLACKLISTED_EXTERNAL_IP`; AbuseIPDB, VirusTotal y Whois estan mockeados en pruebas; hay cache para evitar consultas repetidas. | Cumple |
| 9. Envio de datos de abuso al administrador. | Orquestador + reporte forense por correo | `src/runtime/engine.py`, `src/threat_intel.py`, `src/mailer.py` | Demo segura con prueba: `python -m pytest tests/test_end_to_end_rubric.py` | `tests/test_runtime_engine.py`, `tests/test_end_to_end_rubric.py` | El correo forense incluye IP peligrosa, riesgo, AbuseIPDB, VirusTotal, Whois y contacto de abuso simulado `abuse@example.net`. | Cumple |
| 10. Uso de `.env` y proteccion de credenciales. | Configuracion, redaccion y documentacion segura | `src/config.py`, `src/storage.py`, `src/reports.py`, `.env.example`, `docs/credenciales.md`, `docs/security.md` | `gleipnir test-config` y `gleipnir status` | `tests/test_config.py`, `tests/test_storage.py`, `tests/test_reports.py`, `tests/test_status.py` | Secretos como contrasenas SMTP, API keys, tokens y secret keys no se hardcodean y se redactan en diagnosticos/reportes. | Cumple |
| 11. Modo offline/replay/live. | Sniffer, replay y CLI | `src/sniffer.py`, `src/replay.py`, `src/cli.py`, `src/runtime/engine.py` | `gleipnir offline --pcap archivo.pcap`, `gleipnir replay --pcap archivo.pcap --delay 1`, `sudo .venv/bin/gleipnir live --interface ens33 --packet-count 100` | `tests/test_sniffer.py`, `tests/test_replay.py`, `tests/test_live_sniffer.py`, `tests/test_cli.py` | Offline procesa PCAP sin interfaz; replay simula trafico; live usa Scapy y requiere permisos de captura en Ubuntu. | Cumple |
| 12. Dashboard local si aplica. | Dashboard web local | `src/dashboard/app.py`, `src/dashboard/auth.py`, `src/storage.py`, `src/cli.py`, `docs/dashboard.md` | `gleipnir dashboard --host 127.0.0.1 --port 8080` | `tests/test_dashboard.py`, `tests/test_dashboard_auth.py`, `tests/test_dashboard_filters.py` | Vista local de eventos, filtros, graficas, detalle de eventos y administracion protegida de listas cuando la autenticacion esta activa. | Cumple |
| 13. Capa opcional IPS/Firewall defensiva (tipo profesor) administrable por CLI y Dashboard. | Firewall nftables + engine + config IPS + dashboard | `src/firewall.py`, `src/ips_config.py`, `src/runtime/engine.py`, `src/cli.py`, `src/dashboard/app.py`, `docs/ips_firewall.md` | `gleipnir ips config show`, `gleipnir ips enable`, `gleipnir ips dry-run`, `sudo .venv/bin/gleipnir ips apply`, o `/admin/ips` (rol admin) | `tests/test_firewall.py`, `tests/test_ips_config.py`, `tests/test_ips_engine.py`, `tests/test_cli.py`, `tests/test_dashboard.py` | IDS pasivo por defecto; config operativa en `data/ips_config.json` (CLI/dashboard, no `.env`); dry-run simula; apply requiere `ips_enabled=true`+`dry_run=false`+root; remove borra solo `table inet gleipnir`; dashboard con CSRF y auditoria `ADMIN_IPS_*`, sin contrasenas sudo. | Cumple (opcional) |
| 14. Bloqueo defensivo opcional y evidencia de accion. | Engine IPS + storage | `src/firewall.py`, `src/runtime/engine.py`, `src/storage.py` | `gleipnir report --type IPS_BLOCKED_BLACKLISTED_IP` | `tests/test_ips_engine.py` | Eventos `IPS_BLOCKED_BLACKLISTED_IP` e `IPS_BLOCKED_UNREGISTERED_DEVICE` con accion `detected`/`alerted`/`blocked`/`dry_run_block`; sin MAC bajo politica strict solo alerta. | Cumple (opcional) |

## Comandos de demo recomendados

### 1. Preparar entorno

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
gleipnir --help
```

### 2. Crear archivos base de datos locales

```bash
mkdir -p data logs logs/reports
touch data/blacklist.txt
echo "ip,mac,description" > data/whitelist.csv
echo "[ ]" > data/dashboard_users.json
touch data/gleipnir_events.db
chmod 600 data/dashboard_users.json
chmod 600 data/gleipnir_events.db
```

El encabezado correcto de la whitelist es:

```csv
ip,mac,description
```

El formato recomendado de blacklist con tipo de riesgo es:

```text
203.0.113.50,Botnet
198.51.100.25,Malware
192.0.2.10,Virus
```

Tambien se acepta una IP por linea; en ese caso el riesgo se interpreta como
`Unknown`.

### 3. Validar configuracion y salud

```bash
gleipnir test-config
gleipnir status
```

### 4. Administrar listas

```bash
gleipnir whitelist add --ip 192.168.1.10 --mac aa:bb:cc:dd:ee:ff --description "Laptop autorizada"
gleipnir whitelist validate
gleipnir whitelist list

gleipnir blacklist add --ip 203.0.113.50 --reason "Botnet"
gleipnir blacklist validate
gleipnir blacklist list

gleipnir admin-email show
gleipnir admin-email set --email nuevo-admin@example.org
```

### 5. Probar modos operativos

```bash
gleipnir offline --pcap archivo.pcap
gleipnir replay --pcap archivo.pcap --delay 1
sudo .venv/bin/gleipnir live --interface ens33 --packet-count 100
sudo .venv/bin/gleipnir live --interface ens33 --debug-packets --packet-count 20 --use-pcap
```

Para ejecucion 24/7 con systemd:

```bash
sudo .venv/bin/gleipnir live --interface ens33 --forever
```

### 6. Generar reportes

```bash
gleipnir report
gleipnir report --format json
gleipnir report --format csv
gleipnir report --type UNAUTHORIZED_DEVICE
gleipnir report --type BLACKLISTED_EXTERNAL_IP
gleipnir report --domain ejemplo.com
gleipnir report --severity high
```

### 7. Dashboard local

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

Para exponerlo solo en una red local/laboratorio controlada:

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

No se recomienda usar `0.0.0.0` sin autenticacion ni exponer el dashboard a
internet.

### 8. Capa opcional IPS/Firewall (defensiva)

Gleipnir es IDS pasivo por defecto. La capa IPS es **opcional** y solo para red
propia/laboratorio. Ver `docs/ips_firewall.md`.

```bash
gleipnir ips status            # estado, backend y disponibilidad de nft
gleipnir ips config show       # configuracion operativa (data/ips_config.json)
gleipnir ips enable            # ips_enabled=true (no aplica reglas)
gleipnir ips dry-run-enable    # modo seguro
gleipnir ips dry-run           # muestra reglas nftables SIN aplicarlas
gleipnir ips policy allowlist --mode allow_registered
gleipnir ips dry-run-disable   # permite aplicar reglas reales

# Aplicar/remover en laboratorio (ips_enabled=true, dry_run=false, root):
sudo .venv/bin/gleipnir ips apply
sudo .venv/bin/gleipnir ips remove
```

La configuracion operativa tambien se administra desde el dashboard en
`/admin/ips` (solo rol admin; no edita `.env` ni pide contrasenas sudo).

## Comandos pytest

Prueba integral de la rubrica:

```bash
python -m pytest tests/test_end_to_end_rubric.py
```

Pruebas por modulo:

```bash
python -m pytest tests/test_whitelist.py tests/test_detector.py
python -m pytest tests/test_dns_http_monitor.py tests/test_reports.py
python -m pytest tests/test_blacklist.py tests/test_threat_intel.py
python -m pytest tests/test_runtime_engine.py
python -m pytest tests/test_sniffer.py tests/test_replay.py tests/test_live_sniffer.py
python -m pytest tests/test_dashboard.py tests/test_dashboard_auth.py tests/test_dashboard_filters.py
```

Suite completa:

```bash
python -m pytest
```

## Limitaciones honestas

- El monitoreo HTTP solo extrae Host, metodo y ruta cuando HTTP esta en texto
  claro. HTTPS cifra el contenido y no se implementa inspeccion TLS.
- AbuseIPDB y VirusTotal requieren API keys configuradas en `.env`; si faltan,
  el IDS continua funcionando y registra resultados omitidos.
- Whois depende del comando/servicio disponible y de que el proveedor publique
  datos utiles de organizacion o contacto de abuso.
- Las pruebas automatizadas no envian correos reales ni llaman a internet; usan
  mocks para SMTP y threat intelligence.
- La captura live requiere permisos de captura en Ubuntu, por ejemplo ejecutar
  con `sudo` o capacidades equivalentes autorizadas.
- `203.0.113.50` pertenece a un bloque reservado para documentacion; en pruebas
  puede usarse como IP simulada para evitar usar infraestructura real.
- El dashboard Flask no debe exponerse directamente a internet. Para un entorno
  real se recomienda reverse proxy con HTTPS y restricciones de firewall.
- No hay MFA ni gestion avanzada de identidades; las cuentas del dashboard usan
  hashes de contrasena y roles basicos `viewer`/`admin`.
- La capa IPS/Firewall es opcional y esta desactivada por defecto. Aplicar reglas
  reales requiere `nft`, `IPS_ENABLED=true`, `IPS_DRY_RUN=false` y sudo/root. El
  hook nftables es `forward` (gateway/laboratorio) y la coincidencia por MAC solo
  es fiable en el mismo segmento Ethernet (ver `docs/ips_firewall.md`).

## Consideraciones legales y eticas

- Usar Gleipnir IDS solo en redes propias, laboratorios o infraestructura donde
  exista autorizacion expresa de monitoreo.
- Informar a los usuarios de la red cuando aplique una politica institucional de
  monitoreo.
- No capturar, divulgar ni almacenar contenido sensible que no sea necesario
  para la finalidad defensiva.
- Proteger `.env`, `data/dashboard_users.json`, logs, reportes y SQLite con
  permisos adecuados.
- No usar el sistema para ataques, evasion, explotacion, spoofing ni vigilancia
  no autorizada.
- Para Mexico, revisar `docs/analisis_juridico_mexico.md` y adaptar politicas
  internas de privacidad, bitacoras y tratamiento de datos personales.

## Estado general

La matriz no identifica requisitos funcionales pendientes de la rubrica
principal. Las limitaciones anteriores son restricciones tecnicas y de alcance
defensivo, no incumplimientos de la rubrica.
