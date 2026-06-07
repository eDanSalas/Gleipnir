# Seguridad del dashboard web

Este documento resume las medidas de seguridad actuales del dashboard de
Gleipnir IDS y las recomendaciones de despliegue. El proyecto es defensivo y
educativo; no debe exponerse como servicio publico de internet.

## 1. Autenticacion del dashboard

La autenticacion se controla desde `.env`:

```env
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=viewer-local
DASHBOARD_PASSWORD=<CONTRASENA_VIEWER>
DASHBOARD_ROLE=viewer
DASHBOARD_ADMIN_USERNAME=admin-local
DASHBOARD_ADMIN_PASSWORD=<CONTRASENA_ADMIN>
DASHBOARD_SECRET_KEY=<CLAVE_LARGA_ALEATORIA>
DASHBOARD_SESSION_COOKIE_SECURE=false
DASHBOARD_SESSION_TIMEOUT_MINUTES=30
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

Si solo se configura `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD`, el permiso de
ese usuario se define con `DASHBOARD_ROLE`. Si se configuran
`DASHBOARD_ADMIN_USERNAME` y `DASHBOARD_ADMIN_PASSWORD`, esas credenciales
siempre tienen rol `admin`.

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
- No hay gestion avanzada de usuarios.
- No hay OAuth ni integracion con directorio corporativo.
- Flask no implementa TLS dentro del proyecto; usar reverse proxy.
- El sistema es educativo/defensivo y requiere autorizacion institucional.

## 8. Checklist de despliegue seguro

- `.env` creado localmente y no versionado en Git.
- `DASHBOARD_SECRET_KEY` definido con valor largo y aleatorio.
- `DASHBOARD_AUTH_ENABLED=true` si se usa `0.0.0.0`.
- `DASHBOARD_ROLE=viewer` para usuarios de solo visualizacion.
- Usuario `admin` separado si se administran listas desde navegador.
- `gleipnir dashboard --host 127.0.0.1 --port 8080` para uso local.
- `gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan` solo en red local.
- HTTPS con Nginx/Caddy si se usa fuera de localhost.
- `DASHBOARD_SESSION_COOKIE_SECURE=true` cuando haya HTTPS.
- Firewall o segmentacion restringiendo acceso al puerto del proxy.
- Logs, SQLite y reportes con permisos restrictivos.
- Revisar eventos `ADMIN_*` y logs de auditoria.
- Ejecutar `gleipnir status` y `gleipnir test-config` antes de la demo.
