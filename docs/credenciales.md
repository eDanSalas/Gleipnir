# Proteccion de Credenciales

## Objetivo

Este documento define como Gleipnir maneja secretos y configuraciones sensibles.

## Principios

- No hardcodear contrasenas.
- No subir `.env` al repositorio.
- No imprimir secretos en consola, logs ni reportes.
- Usar variables de entorno mediante `.env`.
- Rotar credenciales si se sospecha exposicion.

## Archivo .env

Crear a partir de la plantilla:

```bash
cp .env.example .env
chmod 600 .env
```

Variables sensibles:

- `SMTP_PASSWORD`
- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY`

Variables operativas no secretas:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `ADMIN_EMAIL`
- `WHITELIST_FILE`
- `BLACKLIST_FILE`
- `LOG_DIR`
- `REPORT_DIR`
- `IDS_DB_PATH`
- `THREAT_INTEL_TIMEOUT_SECONDS`
- `THREAT_INTEL_CACHE_TTL_SECONDS`
- `ALERT_COOLDOWN_SECONDS`
- `ALERT_MAX_PER_MINUTE`
- `GLEIPNIR_INTERFACE`
- `GLEIPNIR_MODE`
- `HEALTH_LOG_INTERVAL_SECONDS`
- `EVENT_RETENTION_DAYS`
- `MAX_LOG_SIZE_MB`
- `MAX_REPORTS_TO_KEEP`

## Redaccion en el codigo

`src/config.py` evita exponer secretos en `repr` y ofrece
`as_redacted_dict()`.

`src/logger.py` redacta patrones asociados a:

- password
- passwd
- pwd
- api_key
- token
- secret

`src/reports.py` redacta claves sensibles antes de escribir JSON o CSV.

`src/storage.py` sanitiza `raw_json` antes de guardarlo en SQLite para evitar
persistir contrasenas, API keys, tokens o secretos.

`src/status.py` no envia correos reales. La verificacion SMTP usa una prueba de
disponibilidad y no imprime `SMTP_PASSWORD` ni API keys.

`src/maintenance.py` aplica retencion sobre rutas configuradas y registra
conteos de eliminacion, no secretos.

## Permisos recomendados

En Linux:

```bash
chmod 600 .env
chmod 700 logs
chmod 700 logs/reports
chmod 700 data
```

Si varias personas administran el IDS, usar un grupo del sistema con permisos
limitados en lugar de hacer el archivo publico.

## Buenas practicas SMTP

- Usar password de aplicacion si el proveedor lo permite.
- No reutilizar la contrasena personal del administrador.
- Limitar la cuenta SMTP a envio de alertas.
- Revisar SPF, DKIM y DMARC del dominio para reducir spam.

## Buenas practicas API

- Crear API keys especificas para el proyecto.
- No compartir las llaves en capturas de pantalla.
- No copiarlas a issues, commits, chats ni reportes.
- Configurar limites de uso y revisar consumo.
- Rotarlas al terminar la entrega academica si se usaron llaves reales.

## Cache de threat intelligence

El cache se guarda en `LOG_DIR/threat_intel_cache.json`. Puede contener IPs,
resultados y metadatos de reputacion. No debe contener API keys. Aun asi debe
tratarse como informacion operativa sensible.

## SQLite

La base configurada en `IDS_DB_PATH`, por defecto `data/gleipnir_events.db`,
contiene eventos acumulados del IDS:

- IPs y MACs observadas.
- Dominios DNS/HTTP.
- IPs externas en blacklist.
- Resultados de threat intelligence.
- Alertas enviadas o suprimidas.

No debe contener secretos, pero si puede contener datos operativos que permitan
identificar equipos o usuarios. Debe protegerse con permisos de sistema y no
versionarse.

## Reportes

Los reportes pueden incluir:

- IPs internas.
- MACs.
- Dominios consultados.
- IPs externas.
- Resultados de reputacion.

Estos datos pueden identificar usuarios o equipos. Deben conservarse con acceso
limitado y por el tiempo necesario para fines de seguridad.

## systemd

El servicio `deploy/systemd/gleipnir.service` debe mantener las credenciales
fuera del unit file. La plantilla usa:

```ini
EnvironmentFile=/opt/gleipnir/.env
```

El archivo `.env` debe tener permisos restrictivos y no debe versionarse. La
interfaz de red puede definirse con `GLEIPNIR_INTERFACE`, pero esa variable no
es secreta.

## Retencion

Las variables `EVENT_RETENTION_DAYS`, `MAX_LOG_SIZE_MB` y
`MAX_REPORTS_TO_KEEP` reducen la acumulacion de metadatos. `gleipnir
maintenance` elimina eventos antiguos, conserva reportes recientes y valida la
rotacion de logs. La retencion no sustituye permisos de sistema ni politicas
internas de acceso.

## Politicas de alerta

`ALERT_COOLDOWN_SECONDS` y `ALERT_MAX_PER_MINUTE` no son secretos. Controlan el
volumen de correos para evitar alertas repetidas. Las decisiones se registran
como `ALERT_SENT` o `ALERT_SUPPRESSED` y no deben incluir credenciales.
