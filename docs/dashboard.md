# Dashboard Web Local

## Objetivo

Gleipnir incluye un dashboard web local de solo lectura para visualizar eventos
almacenados en SQLite desde un navegador. Las vistas de eventos no modifican
datos. Opcionalmente, el dashboard incluye una seccion administrativa protegida
para gestionar whitelist y blacklist.

El servidor HTTP no abre ventanas graficas y no depende de entorno de
escritorio. Funciona tanto en Ubuntu Desktop como en Ubuntu Server 24.04 LTS.

## 1. Iniciar dashboard local

En el equipo donde corre Gleipnir:

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

Abrir en un navegador del mismo equipo:

```text
http://127.0.0.1:8080
```

`127.0.0.1` es el valor por defecto y es la opcion recomendada cuando solo se
necesita acceso local.

Si `DASHBOARD_AUTH_ENABLED=true`, abrir `/login` para iniciar sesion antes de
usar el panel.

## 2. Acceso desde otro equipo de la misma red

Para permitir acceso desde otro equipo de la red local:

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

Usar `0.0.0.0` expone el dashboard en las interfaces de red del servidor. Debe
usarse solo en redes locales controladas, laboratorios o infraestructura
institucional autorizada. La CLI rechaza `--host 0.0.0.0` si no se incluye
`--allow-lan`.

Cuando se use `--host 0.0.0.0`, se recomienda mantener la autenticacion activa
en `.env`.

Si `DASHBOARD_AUTH_ENABLED=false`, `--host 0.0.0.0` queda bloqueado aun con
`--allow-lan`. La opcion `--allow-unauthenticated-lan` existe solo para demos
controladas y no se recomienda.

## 3. Obtener la IP del servidor en Ubuntu

En Ubuntu Desktop o Ubuntu Server:

```bash
ip addr
```

Identificar la IP de la interfaz de red autorizada. Por ejemplo:

```text
192.168.1.50
```

## 4. Acceder desde navegador

Desde otro equipo de la misma red:

```text
http://<IP_DEL_SERVIDOR>:8080
```

Ejemplo:

```text
http://192.168.1.50:8080
```

Gleipnir no intenta detectar IP publica y no abre el navegador
automaticamente.

## 5. Rutas disponibles

- `/`: vista principal HTML con resumen y ultimos 50 eventos.
- `/health`: estado basico en JSON.
- `/events`: resumen y ultimos eventos en JSON.
- `/events/<event_id>`: detalle HTML de un evento individual.
- `/admin/lists`: administracion opcional de whitelist y blacklist.
- `/admin/ips`: administracion opcional de la capa IPS/Firewall (solo rol admin).

Con autenticacion activa, todas estas rutas solicitan credenciales. Las rutas
`/admin/lists` y `/admin/ips` solo estan disponibles cuando
`DASHBOARD_AUTH_ENABLED=true` y requieren rol admin.

La pagina `/admin/ips` permite ver el estado del IPS, cambiar la configuracion
operativa (guardada en `data/ips_config.json`, con CSRF y auditoria
`ADMIN_IPS_*`), ejecutar dry-run y, solo si `auto_apply=true` y el proceso tiene
permisos root, aplicar/remover reglas. El dashboard **no** edita `.env` ni pide o
almacena contrasenas sudo; para aplicar reglas reales se recomienda
`sudo .venv/bin/gleipnir ips apply` desde terminal. Ver `docs/ips_firewall.md`.

## 6. Autenticacion del dashboard

El dashboard usa autenticacion local configurable por `.env`. No hay
credenciales hardcodeadas en el codigo. Con autenticacion activa, el navegador
puede entrar por `/login` y cerrar sesion con `/logout`. La sesion Flask expira
automaticamente, usa cookies `HttpOnly`, `SameSite=Lax` y puede marcar cookies
`Secure` cuando el despliegue este detras de HTTPS.

Activar autenticacion:

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

Desactivar autenticacion:

```env
DASHBOARD_AUTH_ENABLED=false
DASHBOARD_SECRET_KEY=
DASHBOARD_USERS_FILE=data/dashboard_users.json
DASHBOARD_SESSION_COOKIE_SECURE=false
DASHBOARD_SESSION_TIMEOUT_MINUTES=30
DASHBOARD_PASSWORD_MIN_LENGTH=12
DASHBOARD_LOGIN_MAX_ATTEMPTS=5
DASHBOARD_LOGIN_LOCKOUT_SECONDS=300
```

Con la autenticacion activa, las contrasenas de usuarios no se guardan en `.env`.
Los usuarios se cargan desde `DASHBOARD_USERS_FILE`, por defecto
`data/dashboard_users.json`, y cada entrada debe contener un `password_hash`
seguro no reversible. Las contrasenas no se encriptan porque el cifrado
reversible permitiria recuperarlas en texto plano si se obtiene la llave. En su
lugar, Gleipnir verifica con Werkzeug que la contrasena ingresada corresponda al
hash guardado; no desencripta nada ni devuelve hashes en vistas del dashboard.

Variables que deben permanecer en `.env` para cuentas y sesiones:

- `DASHBOARD_AUTH_ENABLED`
- `DASHBOARD_SECRET_KEY`
- `DASHBOARD_USERS_FILE`
- `DASHBOARD_SESSION_TIMEOUT_MINUTES`
- `DASHBOARD_SESSION_COOKIE_SECURE`
- `DASHBOARD_PASSWORD_MIN_LENGTH`
- `DASHBOARD_LOGIN_MAX_ATTEMPTS`
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS`

Las cuentas ya no deben definirse con `DASHBOARD_USERNAME` ni
`DASHBOARD_PASSWORD`.

Formato del archivo de usuarios:

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

Para generar un hash:

```bash
python - <<'PY'
from getpass import getpass
from werkzeug.security import generate_password_hash
print(generate_password_hash(getpass("Contrasena del dashboard: ")))
PY
```

`data/dashboard_users.json` no debe versionarse. Las variables antiguas
`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`, `DASHBOARD_ROLE`,
`DASHBOARD_ADMIN_USERNAME` y `DASHBOARD_ADMIN_PASSWORD` estan deprecadas; si
existen en `.env`, Gleipnir muestra una advertencia clara y no las usa por
defecto para autenticar.

Administracion segura desde CLI:

```bash
gleipnir user list
gleipnir user migrate-env
gleipnir user create --username viewer --role viewer
gleipnir user create --username admin --role admin
gleipnir user disable --username viewer
gleipnir user enable --username viewer
gleipnir user change-password --username admin
```

Migracion desde variables antiguas:

```bash
gleipnir user migrate-env
```

Este comando facilita la transicion desde `DASHBOARD_USERNAME` y
`DASHBOARD_PASSWORD` hacia `DASHBOARD_USERS_FILE`. Lee las variables antiguas y
`DASHBOARD_ROLE` si existe, crea un usuario equivalente con `password_hash`, y
no imprime contrasena ni hash. Si el usuario ya existe, no lo duplica. Gleipnir
no edita `.env` automaticamente para evitar borrar datos sin consentimiento; al
finalizar, eliminar manualmente `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD`.

`create` y `change-password` usan `getpass`, por lo que la contrasena no se
muestra en pantalla. No hay opcion `--password` y no debe agregarse: pasar
contrasenas por argumentos puede dejarlas en historial de shell, listados de
procesos o registros operativos. El comando valida rol, evita duplicados,
aplica la politica de contrasenas y escribe solo `password_hash`.

Permisos recomendados para Ubuntu 24.04 LTS:

```bash
chmod 600 data/dashboard_users.json
```

Cuando Gleipnir crea o reescribe `dashboard_users.json`, intenta aplicar permisos
`600` en sistemas compatibles con permisos POSIX. `gleipnir status`,
`gleipnir user list` y `gleipnir dashboard` revisan el archivo y muestran una
advertencia si detectan permisos inseguros. En Windows no se fuerza esta
validacion POSIX; el despliegue objetivo sigue siendo Ubuntu 24.04 LTS.

Politica minima aplicada al crear usuarios o cambiar contrasena:

- Longitud minima configurable con `DASHBOARD_PASSWORD_MIN_LENGTH`, por defecto
  `12`.
- Al menos una letra minuscula.
- Al menos una letra mayuscula.
- Al menos un numero.
- Al menos un simbolo.
- Rechazo de contrasenas comunes como `admin`, `password`, `password123`,
  `12345678`, `gleipnir` y `qwerty`.

La politica no se aplica durante login; en login solo se verifica el hash
guardado. Los errores indican que regla fallo, pero no imprimen la contrasena.

Proteccion basica contra fuerza bruta:

- `DASHBOARD_LOGIN_MAX_ATTEMPTS=5`: intentos fallidos permitidos antes del
  bloqueo temporal.
- `DASHBOARD_LOGIN_LOCKOUT_SECONDS=300`: duracion del bloqueo en segundos.
- Los fallos se cuentan por usuario y por IP remota cuando Flask la reporta.
- Si se alcanza el limite, el login se bloquea temporalmente para ese usuario/IP
  y se registra auditoria `LOGIN_LOCKED`.
- Cada intento fallido se registra como `ADMIN_LOGIN_FAILED`.
- El mensaje mostrado sigue siendo generico para no revelar si el usuario existe.
- No se imprimen contrasenas ni hashes.

En esta version el contador vive en memoria del proceso Flask. En despliegues
multi-proceso o balanceados se requeriria persistencia compartida, por ejemplo
una base central o cache compartido.

Ademas, se habilita `/admin/lists` para administracion manual de listas. Si
`DASHBOARD_AUTH_ENABLED=true`, `DASHBOARD_SECRET_KEY` tambien es obligatorio
para firmar la sesion Flask y proteger formularios administrativos contra CSRF.

`DASHBOARD_SESSION_TIMEOUT_MINUTES` define los minutos de vida de la sesion web.
`DASHBOARD_SESSION_COOKIE_SECURE=false` permite uso local por HTTP; cambiarlo a
`true` cuando se use HTTPS mediante reverse proxy.

Roles disponibles:

- `viewer`: puede abrir el dashboard, ver eventos, usar filtros y ver graficas.
  No puede administrar whitelist ni blacklist.
- `admin`: puede hacer lo anterior y tambien administrar whitelist y blacklist
  en `/admin/lists`.

El rol se define por usuario dentro de `dashboard_users.json`. Los usuarios con
`enabled=false` no pueden iniciar sesion aunque su contrasena sea correcta.

Limitaciones:

- El dashboard mantiene compatibilidad con HTTP Basic Auth para accesos locales
  o pruebas, pero Basic Auth no cifra credenciales por si solo.
- No exponer el dashboard a internet.
- Usar solo en red local, laboratorio o infraestructura institucional
  autorizada.
- Si se expone fuera del equipo, usar HTTPS con reverse proxy.
- No hay MFA.
- No hay recuperacion automatica de contrasena.
- Para produccion real se requeriria autenticacion mas robusta.

Para un despliegue con HTTPS, consultar
`docs/dashboard_https_reverse_proxy.md`. La recomendacion es mantener Gleipnir
escuchando en `127.0.0.1` y exponer solo Nginx o Caddy como reverse proxy TLS.

Resumen completo de seguridad y checklist: `docs/security.md`.

## 7. Administracion opcional de listas

La seccion `/admin/lists` permite administrar manualmente whitelist y blacklist
desde el navegador. Esta seccion no esta disponible si
`DASHBOARD_AUTH_ENABLED=false`; en ese caso el dashboard conserva solo vistas de
eventos.

Operaciones disponibles:

- Listar whitelist.
- Agregar entrada a whitelist con IP, MAC y descripcion.
- Eliminar entrada de whitelist por IP.
- Validar whitelist.
- Listar blacklist.
- Agregar entrada a blacklist con IP y motivo.
- Eliminar entrada de blacklist por IP.
- Validar blacklist.

Las rutas de archivos usadas son las mismas configuradas en `.env`:

```env
WHITELIST_FILE=data/whitelist.csv
BLACKLIST_FILE=data/blacklist.txt
```

Seguridad de la seccion administrativa:

- Solo funciona con `DASHBOARD_AUTH_ENABLED=true`.
- Requiere sesion autenticada con rol `admin`.
- Un usuario `viewer` recibe una pagina 403 de acceso denegado.
- Valida formato de IP y MAC usando la misma logica de los modulos
  `whitelist.py` y `blacklist.py`.
- Evita duplicados.
- No ejecuta comandos del sistema.
- No permite modificar eventos, reportes ni configuracion del IDS.
- Rechaza POST administrativos sin token CSRF valido.
- Registra acciones administrativas en logs y, si SQLite esta disponible, como
  eventos `ADMIN_LIST_ACTION`.
- Registra auditoria especifica de acciones administrativas en SQLite, sin
  contrasenas, tokens CSRF ni secretos.

Las vistas de eventos (`/`, `/events` y `/events/<event_id>`) permanecen de solo
lectura.

## 8. Detalle de eventos

Desde la tabla de ultimos eventos en `/`, el ID de cada evento es un enlace al
detalle individual. Tambien se puede abrir directamente:

```text
http://127.0.0.1:8080/events/123
```

La vista de detalle muestra:

- ID.
- Timestamp.
- Tipo de evento.
- Severidad.
- IP y MAC de origen.
- IP y MAC de destino.
- Protocolo.
- Dominio si aplica.
- Mensaje.
- `raw_json` formateado si existe.

La vista es de solo lectura. Si el evento no existe, el dashboard muestra una
pagina 404 amigable. El `raw_json` se muestra sanitizado para evitar exponer
campos con nombres sensibles como contrasenas, tokens, API keys o secretos.

## 9. Filtros disponibles

Los filtros pueden usarse desde el formulario de la vista principal o mediante
query params. El dashboard sigue siendo de solo lectura.

Filtros soportados:

- `type`: tipo de evento.
- `severity`: severidad.
- `source_ip`: IP origen.
- `destination_ip`: IP destino.
- `source_mac`: MAC origen.
- `domain`: dominio.
- `protocol`: protocolo.
- `since`: fecha inicial, en formato `YYYY-MM-DD` o fecha/hora ISO.
- `until`: fecha final, en formato `YYYY-MM-DD` o fecha/hora ISO.

Ejemplos:

```text
/events?type=UNAUTHORIZED_DEVICE
/events?severity=high
/events?source_ip=192.168.1.20
/events?destination_ip=8.8.8.8
/events?source_mac=aa:bb:cc:dd:ee:ff
/events?domain=example.com
/events?protocol=DNS
/events?since=2026-06-01
/events?until=2026-06-07
/events?type=DNS_EVENT&source_ip=192.168.1.20&domain=example.com
```

Las consultas usan parametros contra SQLite; no se construye SQL concatenando
texto recibido del usuario.

## 10. Datos mostrados

El dashboard lee desde la base configurada en:

```env
IDS_DB_PATH=data/gleipnir_events.db
```

Muestra:

- Total de eventos.
- Dispositivos autorizados detectados.
- Dispositivos no autorizados.
- Eventos DNS.
- Eventos HTTP.
- IPs externas en blacklist.
- Alertas enviadas.
- Ultimos 50 eventos.

## 11. Graficas

La vista principal genera graficas simples con HTML/CSS local, sin depender de
internet, CDN ni JavaScript externo. Las graficas se calculan desde los eventos
leidos de SQLite y respetan los filtros seleccionados.

Graficas disponibles:

- Eventos por tipo.
- Eventos por severidad.
- Eventos por hora.
- Top 10 dominios consultados.
- Top 10 IPs externas detectadas.
- Alertas enviadas/suprimidas si existen eventos `ALERT_SENT` o
  `ALERT_SUPPRESSED`.

Si no hay eventos, cada grafica muestra un estado vacio claro.

Si la base SQLite no existe, muestra un mensaje claro. Si existe pero no tiene
eventos, muestra estado vacio sin fallar. Sin filtros, la vista muestra los
ultimos 50 eventos. Con filtros, muestra los ultimos 50 eventos que coinciden
con los criterios seleccionados.

## 12. Consideraciones de seguridad

- Las vistas de eventos del dashboard son de solo lectura.
- Implementa autenticacion local opcional con sesion y compatibilidad Basic Auth.
- Permite editar whitelist y blacklist solo en `/admin/lists` con autenticacion
  activa.
- No exponer a internet.
- Usar preferentemente red local o laboratorio.
- No publicar credenciales.
- No muestra secretos del `.env`.
- Activar `DASHBOARD_AUTH_ENABLED=true` al usar `--host 0.0.0.0 --allow-lan`.
- Mantener `.env`, SQLite, logs y reportes con permisos restringidos.

Para exponerlo en red local, hacerlo explicitamente con `--host 0.0.0.0 --allow-lan` y
validar firewall, segmento de red y autorizacion institucional.

## 13. Cabeceras HTTP de seguridad

El dashboard agrega cabeceras HTTP defensivas en todas sus respuestas:

- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY`.
- `Referrer-Policy: no-referrer`.
- `Content-Security-Policy` basica.

La CSP aplicada es:

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

`style-src 'unsafe-inline'` se conserva porque el dashboard usa estilos CSS
inline en sus plantillas HTML. El dashboard no depende obligatoriamente de
internet ni de CDN externos para graficas o estilos.

Cuando la autenticacion esta activa, o cuando se accede a rutas administrativas,
tambien se agrega:

```text
Cache-Control: no-store
Pragma: no-cache
Expires: 0
```

Esto reduce el riesgo de que eventos, sesiones o pantallas administrativas
queden almacenadas en cache del navegador o de intermediarios.

## 14. Auditoria administrativa

Cuando la administracion web esta habilitada y un usuario autenticado realiza
acciones relevantes, el dashboard registra eventos de auditoria. Si SQLite esta
configurado, los eventos se guardan en la tabla de eventos; si el guardado no
esta disponible, se registra por `logger.py`.

Eventos registrados:

- `ADMIN_WHITELIST_ADD`.
- `ADMIN_WHITELIST_REMOVE`.
- `ADMIN_BLACKLIST_ADD`.
- `ADMIN_BLACKLIST_REMOVE`.
- `ADMIN_LOGIN_SUCCESS`.
- `ADMIN_LOGIN_FAILED`.
- `ADMIN_LOGOUT`.

Cada evento incluye:

- `timestamp`.
- Usuario.
- Accion.
- IP remota si esta disponible.
- Resultado.
- Mensaje.

No se guardan contrasenas, tokens CSRF, API keys ni secretos del `.env`. Los
eventos de cambios en listas tambien conservan compatibilidad con el evento
historico `ADMIN_LIST_ACTION` para reportes previos.

## 15. Checklist de despliegue seguro

- `.env` local y no versionado.
- `DASHBOARD_SECRET_KEY` definido antes de activar autenticacion.
- `DASHBOARD_AUTH_ENABLED=true` al usar `0.0.0.0 --allow-lan`.
- Usuario `admin` creado con `gleipnir user create --username admin --role admin`.
- Usuario `viewer` creado si se requiere visualizacion separada.
- Credenciales antiguas `DASHBOARD_USERNAME` y `DASHBOARD_PASSWORD` eliminadas
  del `.env` despues de `gleipnir user migrate-env`.
- `data/dashboard_users.json` con permisos `600` en Ubuntu y fuera de Git.
- No usar `--allow-unauthenticated-lan` salvo demo controlada.
- HTTPS mediante Nginx/Caddy si se usa fuera de localhost.
- `DASHBOARD_SESSION_COOKIE_SECURE=true` cuando se accede por HTTPS.
- Firewall o segmentacion para limitar acceso.
- Revisar eventos `ADMIN_*`, logs, SQLite y reportes.
- No publicar credenciales, tokens, screenshots de `.env` ni reportes con datos
  sensibles.

Riesgos mitigados:

- Exposicion accidental en interfaces publicas.
- Cambios administrativos no autorizados por CSRF.
- Reutilizacion de sesiones antiguas mediante timeout.
- Cache local de paginas autenticadas o administrativas.
- Ausencia de trazabilidad en cambios de listas y sesiones admin.
