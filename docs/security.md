# Seguridad del dashboard web

Este documento resume las medidas de seguridad actuales del dashboard de
Gleipnir IDS y las recomendaciones de despliegue. El proyecto es defensivo y
educativo; no debe exponerse como servicio publico de internet.

## 1. Autenticacion del dashboard

La autenticacion se controla desde `.env`:

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

Activar autenticacion:

```env
DASHBOARD_AUTH_ENABLED=true
```

Desactivar autenticacion:

```env
DASHBOARD_AUTH_ENABLED=false
```

No se recomienda desactivar autenticacion salvo en laboratorio local controlado.
La CLI bloquea `--host 0.0.0.0` cuando `DASHBOARD_AUTH_ENABLED=false`, salvo que
se agregue tambien `--allow-unauthenticated-lan`, opcion no recomendada.

Roles:

- `viewer`: puede ver dashboard, eventos, filtros, graficas y detalles de
  eventos. No puede modificar whitelist ni blacklist.
- `admin`: puede hacer todo lo anterior y administrar whitelist/blacklist desde
  `/admin/lists`.

Los usuarios se definen en `DASHBOARD_USERS_FILE`, por defecto
`data/dashboard_users.json`. Ese archivo debe guardar `password_hash`, no
contrasenas en texto plano:

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

Los hashes son no reversibles. Las contrasenas no se encriptan porque no deben
poder recuperarse en texto plano; Gleipnir verifica la contrasena con Werkzeug y
no desencripta nada. Si un usuario tiene `enabled=false`, no puede iniciar
sesion.

Variables actuales relacionadas con cuentas y sesion:

- `DASHBOARD_AUTH_ENABLED`
- `DASHBOARD_SECRET_KEY`
- `DASHBOARD_USERS_FILE`
- `DASHBOARD_SESSION_TIMEOUT_MINUTES`
- `DASHBOARD_SESSION_COOKIE_SECURE`
- `DASHBOARD_PASSWORD_MIN_LENGTH`
- `DASHBOARD_LOGIN_MAX_ATTEMPTS`
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS`

Las variables antiguas `DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`,
`DASHBOARD_ROLE`, `DASHBOARD_ADMIN_USERNAME` y `DASHBOARD_ADMIN_PASSWORD` estan
deprecadas; si aparecen en `.env`, se advierte al operador y no se usan por
defecto para autenticar.

Para migrar un despliegue antiguo sin dejar la contrasena en texto plano:

```bash
gleipnir user migrate-env
```

El comando lee temporalmente `DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD` y
`DASHBOARD_ROLE` si existe, crea la cuenta equivalente en
`DASHBOARD_USERS_FILE` con `password_hash`, evita duplicados y no imprime
contrasenas ni hashes. No modifica `.env`; despues de verificar la migracion,
el operador debe eliminar manualmente `DASHBOARD_USERNAME` y
`DASHBOARD_PASSWORD`.

El archivo `data/dashboard_users.json` contiene hashes y metadatos de cuentas,
por lo que debe ser accesible solo para el usuario del servicio. En Ubuntu
24.04 LTS se recomienda:

```bash
chmod 600 data/dashboard_users.json
```

Al crear o reescribir el archivo, Gleipnir intenta aplicar permisos `600`. Si el
archivo existe con permisos inseguros, `gleipnir status`, `gleipnir user list` y
`gleipnir dashboard` muestran advertencia. En Windows no se fuerza el modelo
POSIX, pero el despliegue objetivo documentado es Ubuntu 24.04 LTS.

Comandos de administracion:

```bash
gleipnir user list
gleipnir user migrate-env
gleipnir user create --username viewer --role viewer
gleipnir user create --username admin --role admin
gleipnir user disable --username viewer
gleipnir user enable --username viewer
gleipnir user change-password --username admin
```

Politica de contrasenas:

- Longitud minima `DASHBOARD_PASSWORD_MIN_LENGTH`, recomendado `12`.
- Al menos una minuscula, una mayuscula, un numero y un simbolo.
- Rechazo de contrasenas comunes: `admin`, `password`, `password123`,
  `12345678`, `gleipnir` y `qwerty`.
- La politica se aplica al crear o cambiar contrasena, no al login.

Proteccion contra fuerza bruta:

- `DASHBOARD_LOGIN_MAX_ATTEMPTS` limita intentos fallidos por usuario/IP.
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS` aplica bloqueo temporal.
- Intentos fallidos: auditoria `ADMIN_LOGIN_FAILED`.
- Bloqueos temporales: auditoria `LOGIN_LOCKED`.
- Mensajes genericos para no revelar si el usuario existe.

## 2. Proteccion CSRF

Los formularios administrativos usan token CSRF firmado con
`DASHBOARD_SECRET_KEY`. Esto protege acciones que modifican datos:

- Agregar entrada a whitelist.
- Eliminar entrada de whitelist.
- Agregar entrada a blacklist.
- Eliminar entrada de blacklist.
- Validar listas desde formularios administrativos.

Si el token falta o es invalido, la accion se rechaza con error HTTP 400 y no se
modifica el archivo de lista. La proteccion es necesaria porque evita que un
navegador autenticado ejecute cambios administrativos mediante solicitudes
forzadas desde otra pagina.

## 3. Exposicion segura del dashboard

El host por defecto es seguro para uso local:

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

Para red local/laboratorio se requiere permiso explicito:

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

Riesgos mitigados:

- Evita publicar accidentalmente el dashboard en todas las interfaces.
- Obliga al operador a reconocer que `0.0.0.0` expone el servicio en red.
- Bloquea exposicion sin autenticacion salvo excepcion explicita.

No abrir puertos publicos automaticamente, no modificar firewall desde
Gleipnir, no exponer el dashboard a internet y no ejecutar `0.0.0.0` sin una
red controlada.

## 4. HTTPS y reverse proxy

HTTP Basic Auth y el login por formulario no cifran la conexion por si solos. Si
se usa HTTP, las credenciales y datos del dashboard dependen de la red para no
ser interceptados.

Para un entorno real:

- Mantener Flask/Gleipnir escuchando en `127.0.0.1`.
- Usar Nginx o Caddy como reverse proxy.
- Terminar TLS en el reverse proxy.
- Exponer solo el proxy, no Flask directamente.
- Cambiar `DASHBOARD_SESSION_COOKIE_SECURE=true` cuando se acceda por HTTPS.

Guia especifica: `docs/dashboard_https_reverse_proxy.md`.

## 5. Cabeceras HTTP de seguridad

El dashboard agrega cabeceras defensivas:

- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY`.
- `Referrer-Policy: no-referrer`.
- `Content-Security-Policy` basica.
- `Cache-Control: no-store` en rutas autenticadas o administrativas.

CSP aplicada:

```text
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
connect-src 'self';
base-uri 'self';
form-action 'self';
frame-ancestors 'none'
```

`style-src 'unsafe-inline'` se mantiene porque el dashboard usa estilos CSS
inline. El dashboard no depende obligatoriamente de internet ni CDN externos.

## 6. Auditoria administrativa

El dashboard registra eventos administrativos:

- `ADMIN_WHITELIST_ADD`
- `ADMIN_WHITELIST_REMOVE`
- `ADMIN_BLACKLIST_ADD`
- `ADMIN_BLACKLIST_REMOVE`
- `ADMIN_LOGIN_SUCCESS`
- `ADMIN_LOGIN_FAILED`
- `LOGIN_LOCKED`
- `ADMIN_LOGOUT`

Cada evento incluye:

- `timestamp`.
- Usuario.
- Accion.
- IP remota si esta disponible.
- Resultado.
- Mensaje.

Nunca se guardan contrasenas, tokens CSRF, API keys ni secretos del `.env`.
Cuando SQLite esta disponible, los eventos se guardan en `IDS_DB_PATH`; si no,
se registran mediante `logger.py`.

## 7. Limitaciones conocidas

- No exponer el dashboard a internet.
- No usar sin HTTPS fuera de laboratorio o red local confiable.
- No hay MFA.
- No hay recuperacion automatica de contrasena.
- No hay gestion avanzada de usuarios.
- No hay OAuth ni integracion con directorio corporativo.
- Flask no implementa TLS dentro del proyecto; usar reverse proxy.
- El sistema es educativo/defensivo y requiere autorizacion institucional.
- La capa IPS/Firewall (`docs/ips_firewall.md`) es OPCIONAL y esta desactivada
  por defecto. Su configuracion operativa vive en `data/ips_config.json`
  (`ips_enabled=false`, `dry_run=true`, `auto_apply=false` por defecto); `.env`
  solo guarda valores base. Solo modifica trafico con `ips_enabled=true` y
  `dry_run=false`, requiere `nft` y privilegios root, y unicamente gestiona su
  propia tabla `inet gleipnir` (nunca hace flush global). Usa `gleipnir ips
  dry-run` antes de aplicar y nunca la apliques en redes ajenas.
- La administracion del IPS desde el dashboard (`/admin/ips`) requiere rol admin,
  autenticacion y CSRF, registra auditoria `ADMIN_IPS_*`, **no** edita `.env` y
  **no** pide ni almacena contrasenas sudo. Aplicar reglas reales desde el
  dashboard solo se intenta si `auto_apply=true` y el proceso tiene permisos root;
  de lo contrario se indica usar la CLI con sudo. Se recomienda aplicar reglas
  reales desde terminal con `sudo .venv/bin/gleipnir ips apply`.

## 8. Checklist de despliegue seguro

- `.env` creado localmente y no versionado en Git.
- `DASHBOARD_SECRET_KEY` definido con valor largo y aleatorio.
- `DASHBOARD_AUTH_ENABLED=true` si se usa `0.0.0.0`.
- Usuario `admin` creado con `gleipnir user create --username admin --role admin`.
- Usuario `viewer` creado si se requiere cuenta de solo lectura.
- Credenciales antiguas `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD` eliminadas
  del `.env` despues de `gleipnir user migrate-env`.
- `DASHBOARD_USERS_FILE` creado con usuarios habilitados y hashes no reversibles.
- `data/dashboard_users.json` con permisos `600` en Ubuntu y fuera de Git.
- Usuario con rol `viewer` para visualizacion y usuario `admin` separado si se
  administran listas desde navegador.
- `gleipnir dashboard --host 127.0.0.1 --port 8080` para uso local.
- `gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan` solo en red local.
- HTTPS con Nginx/Caddy si se usa fuera de localhost.
- `DASHBOARD_SESSION_COOKIE_SECURE=true` cuando haya HTTPS.
- Firewall o segmentacion restringiendo acceso al puerto del proxy.
- Logs, SQLite y reportes con permisos restrictivos.
- Revisar eventos `ADMIN_*` y logs de auditoria.
- Ejecutar `gleipnir status` y `gleipnir test-config` antes de la demo.
