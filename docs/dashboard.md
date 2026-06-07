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

Si `DASHBOARD_AUTH_ENABLED=true`, el navegador solicitara usuario y contrasena
antes de abrir el panel.

## 2. Acceso desde otro equipo de la misma red

Para permitir acceso desde otro equipo de la red local:

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080
```

Usar `0.0.0.0` expone el dashboard en las interfaces de red del servidor. Debe
usarse solo en redes locales controladas, laboratorios o infraestructura
institucional autorizada.

Cuando se use `--host 0.0.0.0`, se recomienda mantener la autenticacion activa
en `.env`.

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

Con autenticacion activa, todas estas rutas solicitan credenciales. La ruta
`/admin/lists` solo esta disponible cuando `DASHBOARD_AUTH_ENABLED=true`.

## 6. Autenticacion del dashboard

El dashboard usa autenticacion HTTP Basic configurable por `.env`. No hay
credenciales hardcodeadas en el codigo.

Activar autenticacion:

```env
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=admin-local
DASHBOARD_PASSWORD=cambiar-esta-contrasena
```

Desactivar autenticacion:

```env
DASHBOARD_AUTH_ENABLED=false
DASHBOARD_USERNAME=
DASHBOARD_PASSWORD=
```

Con la autenticacion activa, el navegador muestra el prompt estandar de usuario
y contrasena. La contrasena no se muestra en la interfaz ni se registra en logs.
Ademas, se habilita `/admin/lists` para administracion manual de listas.

Limitaciones:

- HTTP Basic Auth no cifra credenciales por si solo.
- No exponer el dashboard a internet.
- Usar solo en red local, laboratorio o infraestructura institucional
  autorizada.
- Para produccion real se requeriria HTTPS y autenticacion mas robusta.

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
- Requiere usuario y contrasena por HTTP Basic Auth.
- Valida formato de IP y MAC usando la misma logica de los modulos
  `whitelist.py` y `blacklist.py`.
- Evita duplicados.
- No ejecuta comandos del sistema.
- No permite modificar eventos, reportes ni configuracion del IDS.
- Registra acciones administrativas en logs y, si SQLite esta disponible, como
  eventos `ADMIN_LIST_ACTION`.

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
- Implementa autenticacion HTTP Basic opcional.
- Permite editar whitelist y blacklist solo en `/admin/lists` con autenticacion
  activa.
- No exponer a internet.
- Usar preferentemente red local o laboratorio.
- No publicar credenciales.
- No muestra secretos del `.env`.
- Activar `DASHBOARD_AUTH_ENABLED=true` al usar `--host 0.0.0.0`.
- Mantener `.env`, SQLite, logs y reportes con permisos restringidos.

Para exponerlo en red local, hacerlo explicitamente con `--host 0.0.0.0` y
validar firewall, segmento de red y autorizacion institucional.
