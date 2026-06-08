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
- `DASHBOARD_SECRET_KEY`

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
- `DASHBOARD_AUTH_ENABLED`
- `DASHBOARD_USERS_FILE`
- `DASHBOARD_SESSION_COOKIE_SECURE`
- `DASHBOARD_SESSION_TIMEOUT_MINUTES`
- `DASHBOARD_PASSWORD_MIN_LENGTH`
- `DASHBOARD_LOGIN_MAX_ATTEMPTS`
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS`

## Credenciales del dashboard

El dashboard usa `.env` para activar autenticacion, definir la clave de sesion y
apuntar al archivo local de usuarios:

```env
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_SECRET_KEY=<CLAVE_LARGA_ALEATORIA>
DASHBOARD_USERS_FILE=data/dashboard_users.json
DASHBOARD_SESSION_COOKIE_SECURE=false
DASHBOARD_SESSION_TIMEOUT_MINUTES=30
DASHBOARD_PASSWORD_MIN_LENGTH=12
DASHBOARD_LOGIN_MAX_ATTEMPTS=5
DASHBOARD_LOGIN_LOCKOUT_SECONDS=300
```

`DASHBOARD_SECRET_KEY` firma la sesion Flask y los tokens CSRF. Debe ser largo,
aleatorio y distinto por entorno. No debe guardarse en Git ni compartirse en
capturas de pantalla.

Las contrasenas de usuarios del dashboard no se guardan en `.env`. No se
encriptan de forma reversible: se almacenan como hashes no reversibles con
Werkzeug para que no puedan recuperarse en texto plano. `DASHBOARD_USERS_FILE`
apunta al archivo local de cuentas, por defecto `data/dashboard_users.json`, con
los campos `username`, `password_hash`, `role`, `enabled` y `created_at`:

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

El hash no permite recuperar la contrasena original; solo permite verificarla.
No subir `data/dashboard_users.json` al repositorio. Las variables antiguas
`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`, `DASHBOARD_ROLE`,
`DASHBOARD_ADMIN_USERNAME` y `DASHBOARD_ADMIN_PASSWORD` estan deprecadas y no se
usan por defecto para autenticar.

Administracion segura de cuentas:

```bash
gleipnir user list
gleipnir user migrate-env
gleipnir user create --username viewer --role viewer
gleipnir user create --username admin --role admin
gleipnir user disable --username viewer
gleipnir user enable --username viewer
gleipnir user change-password --username admin
```

`create` y `change-password` solicitan la contrasena con `getpass`; no aceptan
`--password` para evitar que quede en historial de shell o listados de procesos.
`migrate-env` permite convertir temporalmente `DASHBOARD_USERNAME` y
`DASHBOARD_PASSWORD` en una cuenta con `password_hash`; despues de migrar, esas
variables deben eliminarse manualmente del `.env`.

Politica minima de contrasenas:

- Longitud minima definida por `DASHBOARD_PASSWORD_MIN_LENGTH`, recomendado `12`.
- Al menos una minuscula.
- Al menos una mayuscula.
- Al menos un numero.
- Al menos un simbolo.
- Rechazo de contrasenas comunes como `admin`, `password`, `password123`,
  `12345678`, `gleipnir` y `qwerty`.

Proteccion contra fuerza bruta:

- `DASHBOARD_LOGIN_MAX_ATTEMPTS` limita intentos fallidos.
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS` define el bloqueo temporal.
- Los fallos se auditan como `ADMIN_LOGIN_FAILED`.
- Los bloqueos se auditan como `LOGIN_LOCKED`.
- No se revela si el usuario existe y no se imprimen contrasenas ni hashes.

Roles:

- `viewer`: visualizacion de dashboard y eventos.
- `admin`: visualizacion y administracion de whitelist/blacklist.

Si el dashboard se publica en red local con `0.0.0.0 --allow-lan`, mantener
`DASHBOARD_AUTH_ENABLED=true`. Si se usa HTTPS mediante reverse proxy, cambiar
`DASHBOARD_SESSION_COOKIE_SECURE=true`.

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

La auditoria administrativa del dashboard guarda eventos `ADMIN_*` con usuario,
accion, IP remota, resultado y mensaje. No debe incluir contrasenas, tokens CSRF
ni secretos. Si SQLite no esta disponible, la auditoria cae al logger con la
misma regla de no registrar secretos.

`src/status.py` no envia correos reales. La verificacion SMTP usa una prueba de
disponibilidad y no imprime `SMTP_PASSWORD` ni API keys.

`src/maintenance.py` aplica retencion sobre rutas configuradas y registra
conteos de eliminacion, no secretos.

## Permisos recomendados

En Linux:

```bash
chmod 600 .env
chmod 600 data/dashboard_users.json
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
- Auditoria administrativa del dashboard.

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

## Checklist de credenciales

- `.env` no versionado.
- `.env` con permisos `600`.
- `DASHBOARD_SECRET_KEY` definido si `DASHBOARD_AUTH_ENABLED=true`.
- Usuario `admin` creado con `gleipnir user create --username admin --role admin`.
- Usuario `viewer` creado si se requiere visualizacion separada.
- Credenciales antiguas `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD` eliminadas
  del `.env` despues de `gleipnir user migrate-env`.
- `DASHBOARD_USERS_FILE` creado localmente con `password_hash`, no contrasenas
  en texto plano.
- `data/dashboard_users.json` con permisos `600` y excluido de Git.
- Contrasenas reales solo en el equipo de despliegue y nunca en Git.
- HTTPS/reverse proxy si el dashboard se expone fuera de localhost.
- No exponer el dashboard a internet.
- No publicar logs, reportes, SQLite ni capturas de pantalla con datos
  sensibles.
- Rotar passwords/API keys al terminar la demo si se usaron valores reales.
