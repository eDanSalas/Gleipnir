# Manual de Usuario de Gleipnir IDS/IPS

Guía práctica para **personas no técnicas** que necesitan instalar, operar o
consultar Gleipnir de forma segura. No necesitas ser ingeniero ni saber Linux a
fondo: cada paso y cada comando se explican antes de usarlos.

> ⚠️ **Aviso de uso responsable:** Gleipnir es una herramienta **defensiva**.
> Úsala únicamente en tu propia red, en un laboratorio o donde tengas
> autorización expresa. Nunca la uses para vigilar o atacar redes ajenas.

> 📸 **Sobre las capturas de pantalla:** este manual incluye marcadores como
> `[CAPTURA: ...]`. Indican exactamente qué imagen debe colocarse ahí. Las
> capturas deben tomarse manualmente en tu equipo (ver la lista al final).

---

## 1. ¿Qué es Gleipnir?

Gleipnir es un sistema que **vigila tu red** y te avisa cuando pasa algo raro.
Tiene cuatro piezas:

- **IDS (Sistema de Detección de Intrusos):** observa el tráfico, **detecta** y
  **avisa**. Por sí solo **no bloquea** nada. Es el comportamiento por defecto.
- **IPS / Firewall (opcional):** además de avisar, puede **aplicar reglas** para
  bloquear o permitir tráfico. Viene **apagado** por seguridad.
- **Dashboard:** una página web local donde **ves** los eventos, gráficas y
  alertas con el navegador.
- **CLI (línea de comandos):** se opera escribiendo comandos en la terminal
  (por ejemplo `gleipnir status`).

En resumen: **el IDS mira y avisa; el IPS, si lo activas tú, puede bloquear.**

---

## 2. ¿Qué puede hacer Gleipnir?

| Capacidad | Ejemplo |
|---|---|
| Detectar dispositivos no autorizados | Un teléfono desconocido se conecta a tu red → alerta |
| Registrar sitios visitados (DNS/HTTP) | Quedan registrados los dominios consultados |
| Alertar por IPs peligrosas | Un equipo habla con una IP de malware → correo de emergencia |
| Investigación forense automática | Consulta AbuseIPDB / Whois sobre la IP peligrosa |
| Enviar correos al administrador | Las alertas llegan al `ADMIN_EMAIL` configurado |
| Generar reportes | Archivos JSON y CSV con los eventos |
| Aplicar reglas IPS opcionales | Bloquear IPs de la blacklist con `nftables` |
| Mostrar todo en un panel web | Tarjetas, gráficas y detalle de eventos |

---

## 3. Requisitos del sistema

### 3.1 Sistema operativo recomendado

- **Ubuntu Server 24.04 LTS** (sin entorno gráfico).
- **Ubuntu Desktop 24.04 LTS** (con escritorio y navegador).

> Gleipnir está pensado **principalmente para Linux (Ubuntu)**. La captura de
> tráfico en vivo y el firewall (`nftables`) son funciones de Linux.

> 💡 **Nota Windows:** en Windows la captura de paquetes usaría **Npcap**. El
> proyecto **no** está orientado a Windows y la captura en vivo y el IPS no se
> documentan para esa plataforma; úsalo en Ubuntu. Windows solo sirve, a lo más,
> para abrir el navegador y consultar el Dashboard de un servidor Ubuntu.

### 3.2 Paquetes del sistema

Abre una terminal y ejecuta:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev tcpdump whois nftables git
git clone https://github.com/eDanSalas/Gleipnir.git
```

¿Para qué sirve cada uno?

| Paquete | Para qué sirve (en simple) |
|---|---|
| `python3` | El lenguaje en el que está hecho Gleipnir |
| `python3-pip` | Instalador de librerías de Python |
| `python3-venv` | Crea un "entorno aislado" para no ensuciar el sistema |
| `libpcap-dev` | Librería que permite **capturar paquetes** de la red en Linux |
| `tcpdump` | Herramienta de captura; ayuda a verificar que la red funciona |
| `whois` | Consulta a quién pertenece una IP/dominio (uso forense) |
| `nftables` | El "firewall" de Linux que usa el IPS opcional |

### 3.3 Dependencias de Python

- **`requirements.txt`**: lista las librerías de Python que Gleipnir necesita
  (por ejemplo `scapy`, `flask`, `requests`).
- **`pyproject.toml`**: define el proyecto y crea el comando `gleipnir`.
- **Entorno virtual `.venv`**: una carpeta donde se instalan esas librerías de
  forma aislada, para no afectar al resto del sistema. Lo crearás en el paso 4.

### 3.4 Captura de paquetes

- **Libpcap** (`libpcap-dev`) es lo que permite a Gleipnir "escuchar" la red.
- Capturar tráfico requiere **permisos de administrador** (`sudo` / root).
- Para ver tus **interfaces de red** (las "tarjetas" por las que pasa el tráfico):

  ```bash
  ip addr
  ```

  Verás nombres como `ens33`, `eth0` o `wlan0`. Anota el que corresponde a tu
  conexión activa; lo usarás en el modo `live`.

### 3.5 Correo SMTP (para recibir alertas)

Gleipnir envía alertas por correo. Necesitas los datos de un servidor de correo
(SMTP). Se configuran en el archivo `.env` (ver sección 5):

| Variable | Qué es |
|---|---|
| `SMTP_HOST` | Servidor de correo, p. ej. `smtp.ejemplo.com` |
| `SMTP_PORT` | Puerto, normalmente `587` (STARTTLS) |
| `SMTP_USER` | Usuario/cuenta que envía los correos |
| `SMTP_PASSWORD` | Contraseña o "contraseña de aplicación" |
| `ADMIN_EMAIL` | Correo del administrador que **recibe** las alertas |

- Gleipnir usa **TLS/STARTTLS** (cifrado) al enviar.
- ⚠️ **Nunca subas tus credenciales a Git** ni las compartas. El archivo `.env`
  es privado.

---

## 4. Instalación paso a paso

1. **Descarga o copia** el proyecto a tu equipo Ubuntu.
2. **Entra a la carpeta** del proyecto:

   ```bash
   cd Gleipnir
   ```
3. **Crea el entorno virtual** (la carpeta aislada `.venv`):

   ```bash
   python3 -m venv .venv
   ```
4. **Activa el entorno** (verás `(.venv)` al inicio de la línea):

   ```bash
   source .venv/bin/activate
   ```
5. **Actualiza pip e instala dependencias + Gleipnir** en modo editable:

   ```bash
   pip install -U pip
   pip install -e .
   ```
6. **Prueba que el comando funciona:**

   ```bash
   gleipnir --help
   ```

[CAPTURA: Comando gleipnir --help mostrando la lista de subcomandos]

> 💡 **Importante sobre `sudo`:** al activar el entorno virtual, el comando
> `gleipnir` solo existe **dentro** de ese entorno. Cuando uses `sudo` (por
> ejemplo para capturar tráfico), `sudo` no conoce tu entorno y dirá
> `command not found`. La solución es escribir la ruta completa:
>
> ```bash
> sudo .venv/bin/gleipnir live --interface ens33
> ```

> 🖥️ **Ubuntu Server (sin escritorio):** todo se hace por terminal; el Dashboard
> se abre desde el navegador de **otro** equipo de la red (ver sección 10.2).
> 🖥️ **Ubuntu Desktop:** puedes abrir el Dashboard en el navegador del mismo equipo.

---

## 5. Configuración inicial

### 5.1 Archivo `.env`

Es un archivo de texto con la **configuración** y los **datos sensibles** de
Gleipnir (correo, claves, rutas). **No debe compartirse ni subirse a Git.**

Crea tu `.env` copiando la plantilla incluida:

```bash
cp .env.example .env
```

Luego edítalo. Ejemplo **seguro sin credenciales reales** (cambia los valores
marcados `CAMBIAR_ESTO`):

```env
SMTP_HOST=smtp.ejemplo.com
SMTP_PORT=587
SMTP_USER=usuario@ejemplo.com
SMTP_PASSWORD=CAMBIAR_ESTO
ADMIN_EMAIL=admin@ejemplo.com

WHITELIST_FILE=data/whitelist.csv
BLACKLIST_FILE=data/blacklist.txt
LOG_DIR=logs/
REPORT_DIR=logs/reports/

DASHBOARD_AUTH_ENABLED=true
DASHBOARD_SECRET_KEY=CAMBIAR_ESTO
DASHBOARD_USERS_FILE=data/dashboard_users.json

IPS_CONFIG_FILE=data/ips_config.json
IPS_BACKEND=nftables
```

> ⚠️ Los valores `CAMBIAR_ESTO` son **ejemplos**. Pon los tuyos. Nunca uses
> contraseñas reales en documentos ni capturas de pantalla.

Notas sobre rutas reales del proyecto:

- La **blacklist** es `data/blacklist.txt` (no `.csv`).
- Los **reportes** se guardan en `logs/reports/`.
- La configuración **operativa** del IPS vive en `data/ips_config.json` (no en
  `.env`); `.env` solo guarda los valores base del IPS.

### 5.2 Probar configuración

```bash
gleipnir test-config
```

Salida esperada: `Configuration OK` seguido de la configuración en formato JSON,
con los secretos **ocultos** (verás `"***"` en contraseñas y claves). Si falta
algo obligatorio, te dirá qué variable falta.

[CAPTURA: Salida de gleipnir test-config con secretos ocultos]

---

## 6. Usuarios del Dashboard

- **viewer (visor):** solo **ve** eventos y reportes. No puede cambiar nada.
- **admin (administrador):** además puede **administrar** whitelist, blacklist y
  la configuración del IPS.

Comandos (las contraseñas se piden de forma segura, no se escriben en el comando):

```bash
gleipnir user create --username admin --role admin
gleipnir user create --username visor --role viewer
gleipnir user list
gleipnir user change-password --username admin
gleipnir user disable --username visor
gleipnir user enable --username visor
```

> 🔒 Las contraseñas **no se guardan en texto plano**. Se guardan como **hashes**
> (un código irreversible) en `data/dashboard_users.json`. No edites ese archivo
> a mano.

---

## 7. Lista blanca: dispositivos autorizados

En lenguaje sencillo:

- **IP**: la "dirección" del equipo en la red (p. ej. `192.168.1.10`).
- **MAC**: el identificador físico de la tarjeta de red (p. ej. `AA:BB:CC:DD:EE:FF`).
- **Descripción**: un nombre amigable para reconocer el equipo.

Si un equipo está en la whitelist, Gleipnir lo considera **autorizado**
(`AUTHORIZED_DEVICE`). Si no está, lo marca como **no autorizado**
(`UNAUTHORIZED_DEVICE`) y puede alertar.

### 7.1 Agregar equipo autorizado desde CLI

```bash
gleipnir whitelist add --ip 192.168.1.10 --mac AA:BB:CC:DD:EE:FF --description "Laptop de Administración"
```

[CAPTURA: Alta de IP/MAC en whitelist desde CLI]

### 7.2 Ver la whitelist

```bash
gleipnir whitelist list
```

### 7.3 Validar la whitelist (revisar que el archivo está bien)

```bash
gleipnir whitelist validate
```

### 7.4 Eliminar un equipo

```bash
gleipnir whitelist remove --ip 192.168.1.10
```

### 7.5 Agregar desde el Dashboard

1. Abre el Dashboard (sección 10).
2. Inicia sesión como **admin**.
3. En la barra superior entra a **Administrar listas**.
4. Ve a la sección **Whitelist**.
5. Captura **IP**, **MAC** y **Descripción**.
6. Pulsa **Agregar**.
7. Verifica que el equipo aparece en la tabla.

[CAPTURA: Formulario de alta de IP/MAC en whitelist en el Dashboard]

---

## 8. Lista negra: IPs peligrosas

La blacklist sirve para identificar **IPs externas peligrosas** (malware, botnet,
virus, phishing). Cuando un equipo se comunica con una de ellas, Gleipnir genera
una **alerta de emergencia** y, si activas el IPS, puede bloquearlas.

```bash
gleipnir blacklist add --ip 203.0.113.50 --reason "Botnet"
gleipnir blacklist list
gleipnir blacklist validate
gleipnir blacklist remove --ip 203.0.113.50
```

**Formato del archivo** `data/blacklist.txt` (una IP por línea, con tipo de
riesgo opcional separado por coma):

```text
203.0.113.50,Botnet
198.51.100.20,Malware
192.0.2.30,Virus
```

Tipos de riesgo soportados: **Virus, Malware, Botnet, Phishing, Unknown**. Si
escribes solo la IP sin riesgo, se interpreta como `Unknown`.

> 💡 Las IPs `203.0.113.x`, `198.51.100.x` y `192.0.2.x` son rangos
> **reservados para documentación**; sirven para ejemplos y pruebas sin afectar
> equipos reales.

---

## 9. Uso básico de Gleipnir CLI

> Todos los comandos de esta sección **existen realmente** en el proyecto. Si un
> comando no aparece aquí, probablemente no existe.

### 9.1 Ver ayuda

```bash
gleipnir --help
```

Muestra todos los subcomandos. Para la ayuda de uno: `gleipnir <comando> --help`.

### 9.2 Probar configuración

```bash
gleipnir test-config
```

### 9.3 Modo offline (analizar un archivo PCAP)

Un **PCAP** es un archivo con tráfico de red ya capturado. Este modo lo procesa
sin tocar la red:

```bash
gleipnir offline --pcap archivo.pcap
```

### 9.4 Modo replay (reproducir un PCAP como si fuera tráfico)

```bash
gleipnir replay --pcap archivo.pcap --delay 1
```

`--delay 1` espera 1 segundo entre paquetes (simula tráfico en el tiempo).

### 9.5 Modo live (captura en vivo)

```bash
sudo .venv/bin/gleipnir live --interface ens33
```

- Una **interfaz** es la tarjeta de red por la que pasa el tráfico. Vela con
  `ip addr` y usa el nombre correcto (`ens33`, `eth0`, `wlan0`…).
- Se usa **sudo** porque capturar tráfico requiere permisos de administrador.
- Si `sudo gleipnir` da `command not found`, usa la ruta completa
  `sudo .venv/bin/gleipnir` (ver nota del paso 4).

Opciones útiles del modo live:

| Opción | Qué hace |
|---|---|
| `--packet-count N` | Procesa como máximo N paquetes y termina |
| `--timeout S` | Captura durante S segundos y termina |
| `--forever` | Captura continua 24/7 (para servicio systemd) |
| `--debug-packets` | Muestra un resumen seguro por paquete (diagnóstico) |
| `--use-pcap` | Usa el motor libpcap de Scapy cuando está disponible |

### 9.6 Reportes

```bash
gleipnir report
```

Opciones reales:

| Opción | Qué hace |
|---|---|
| `--format both\|json\|csv` | Formato de salida (por defecto ambos) |
| `--type UNAUTHORIZED_DEVICE` | Filtra por tipo de evento |
| `--since YYYY-MM-DD` | Desde una fecha |
| `--until YYYY-MM-DD` | Hasta una fecha |
| `--source-ip 192.168.1.10` | Filtra por IP de origen |
| `--domain ejemplo.com` | Filtra eventos DNS/HTTP por dominio |
| `--severity high\|medium\|low\|info` | Filtra por severidad |

### 9.7 Estado / salud

```bash
gleipnir status
```

Hace una revisión local (healthcheck) y devuelve si todo está correcto.

### 9.8 Mantenimiento

```bash
gleipnir maintenance
```

Aplica las políticas de retención (limpia eventos, reportes y logs antiguos).

### 9.9 Correo del administrador

```bash
gleipnir admin-email show
gleipnir admin-email set --email nuevo-admin@ejemplo.com
```

Cambia el destinatario de las alertas (escribe en `.env`; reinicia los procesos
para aplicar).

### 9.10 Dashboard

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

`127.0.0.1` = solo el mismo equipo. `0.0.0.0 --allow-lan` = accesible desde otros
equipos de la red local (ver sección 10).

### 9.11 IPS/Firewall

Comandos reales (detalle en sección 11):

```bash
gleipnir ips status
gleipnir ips config show
gleipnir ips config set --key allowlist_policy --value allow_registered
gleipnir ips enable
gleipnir ips disable
gleipnir ips dry-run-enable
gleipnir ips dry-run-disable
gleipnir ips dry-run
gleipnir ips rules
sudo .venv/bin/gleipnir ips apply
sudo .venv/bin/gleipnir ips remove
gleipnir ips policy allowlist --mode monitor
gleipnir ips policy allowlist --mode allow_registered
gleipnir ips policy allowlist --mode block_unregistered
gleipnir ips policy blacklist --mode monitor
gleipnir ips policy blacklist --mode block
gleipnir ips direction --mode outbound
gleipnir ips direction --mode inbound
gleipnir ips direction --mode both
gleipnir ips private-check enable
gleipnir ips private-check disable
gleipnir ips auto-apply enable
gleipnir ips auto-apply disable
```

---

## 10. Uso del Dashboard

> El Dashboard **no abre una ventana** automáticamente. Lo que hace es **levantar
> un servidor web**. Tú abres el navegador y entras a la dirección indicada.

### 10.1 Abrir el Dashboard en el mismo equipo

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

Abre el navegador en: `http://127.0.0.1:8080`

[CAPTURA: Pantalla inicial del Dashboard / pantalla de login]

### 10.2 Abrir el Dashboard desde otro equipo de la red

```bash
gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan
```

Obtén la IP del servidor:

```bash
ip addr
```

Abre en el otro equipo: `http://IP_DEL_SERVIDOR:8080`

⚠️ **Advertencias importantes:**

- **No** expongas el Dashboard a internet.
- Mantén la **autenticación activada** (`DASHBOARD_AUTH_ENABLED=true`).
- Usa **HTTPS con un reverse proxy** si sale de un laboratorio (ver
  `docs/security.md`).
- **No** abras el puerto en el router.

### 10.3 Pantalla principal

Las tarjetas resumen los eventos:

| Tarjeta | Significado |
|---|---|
| Total de eventos | Cuántos eventos hay en total |
| Dispositivos autorizados | Equipos reconocidos (en whitelist) |
| Dispositivos no autorizados | Equipos desconocidos detectados |
| Eventos DNS | Consultas de dominios observadas |
| Eventos HTTP | Peticiones web en texto claro observadas |
| IPs externas en blacklist | Conexiones a IPs peligrosas |
| Alertas enviadas | Correos de alerta enviados |

[CAPTURA: Dashboard principal con tarjetas de eventos y gráficas]

### 10.4 Eventos

- Abajo verás los **últimos 50 eventos**.
- Usa el formulario de **Filtros** (tipo, severidad, IP, dominio, fechas).
- Haz clic en el **ID** de un evento para ver su **detalle**.
- La **severidad** indica gravedad: `INFO` < `BAJA` < `MEDIA` < `ALTA`.

[CAPTURA: Reporte de eventos / tabla de últimos eventos con filtros]

### 10.5 Administración (solo admin)

- **Administrar listas** (`/admin/lists`): whitelist y blacklist.
- **IPS/Firewall** (`/admin/ips`): configuración del IPS opcional.

### 10.6 Seguridad del Dashboard

- **Login** obligatorio cuando `DASHBOARD_AUTH_ENABLED=true`.
- **Roles**: viewer (ver) y admin (administrar).
- Protección **CSRF** en los formularios.
- Contraseñas **hasheadas** (no en texto plano).
- Usa **Cerrar sesión** al terminar.
- **Nunca** lo expongas a internet.

---

## 11. Configuración IPS/Firewall

Recuerda la diferencia:

- **IDS** = observa y alerta (por defecto).
- **IPS** = puede **aplicar reglas** para bloquear/permitir.

El IPS viene **desactivado** por seguridad. **Activar la configuración no es lo
mismo que aplicar reglas reales:**

- *Activar/cambiar config* solo edita `data/ips_config.json`. **No** toca el firewall.
- *Aplicar reglas reales* requiere `ips_enabled=true`, `dry_run=false` y ejecutar
  `ips apply` con **sudo**.

### 11.1 Ver estado

```bash
gleipnir ips status
```

### 11.2 Ver configuración

```bash
gleipnir ips config show
```

### 11.3 Simular reglas (no bloquea nada)

```bash
gleipnir ips dry-run
```

> ✅ `dry-run` **no bloquea tráfico**: solo muestra las reglas que se aplicarían.

### 11.4 Activar IPS en la configuración

```bash
gleipnir ips enable
```

(Esto **no** aplica reglas todavía; solo marca `ips_enabled=true`.)

### 11.5 Permitir aplicación real

```bash
gleipnir ips dry-run-disable
```

### 11.6 Aplicar reglas reales (requiere sudo y nftables)

```bash
sudo .venv/bin/gleipnir ips apply
```

### 11.7 Quitar las reglas de Gleipnir

```bash
sudo .venv/bin/gleipnir ips remove
```

(Borra **solo** la tabla `inet gleipnir`; nunca toca otras reglas del sistema.)

### 11.8 Configurar desde el Dashboard

1. Entra como **admin**.
2. Abre **IPS/Firewall** (`/admin/ips`).
3. Revisa el **estado** actual.
4. Cambia la **política** (allowlist/blacklist, dirección, etc.).
5. Pulsa **Guardar configuración**.
6. Pulsa **Ver reglas (dry-run)** para revisarlas.
7. Para aplicar reglas reales, se recomienda hacerlo desde la **CLI con sudo**.

> 🔒 El Dashboard **no** pide ni guarda contraseñas sudo, y **no** edita `.env`.
> Si el proceso web no tiene permisos root, te dirá:
> *"El dashboard no tiene permisos para aplicar reglas nftables. Usa
> sudo .venv/bin/gleipnir ips apply desde terminal."*

[CAPTURA: Configuración IPS desde el Dashboard (/admin/ips)]

---

## 12. Interpretación de alertas y eventos

### 12.1 Eventos comunes

| Evento | Qué significa |
|---|---|
| `AUTHORIZED_DEVICE` | Un equipo **registrado** (en whitelist) fue visto. Es normal. |
| `UNAUTHORIZED_DEVICE` | Un equipo **desconocido** fue detectado. Revísalo. |
| `DNS_EVENT` | Se registró una consulta de dominio (DNS). |
| `HTTP_EVENT` | Se registró una petición web en texto claro (HTTP). |
| `BLACKLISTED_EXTERNAL_IP` | Tráfico relacionado con una IP **peligrosa**. Alerta. |
| `ALERT_SENT` | Se **envió** un correo de alerta. |
| `IPS_BLOCKED_BLACKLISTED_IP` | El IPS bloqueó (o simuló bloquear) una IP de la blacklist. |
| `IPS_BLOCKED_UNREGISTERED_DEVICE` | El IPS bloqueó (o simuló) un equipo no registrado. |

> En modo **dry-run**, los eventos de IPS muestran la acción `dry_run_block`
> (simulado), no `blocked`.

### 12.2 Dispositivo no autorizado

Significa que se detectó un equipo que **no está en la whitelist**. Revisa:

- **IP** y **MAC** del equipo.
- **Hora** (timestamp).
- Identifica el **equipo físico**.
- Decide: ¿es legítimo? → agrégalo a la whitelist. ¿No lo reconoces? → investiga.

### 12.3 IP peligrosa

Significa que hubo tráfico con una IP de la blacklist. Revisa:

- **IP destino** (la peligrosa) y **tipo de riesgo** (Botnet, Malware, etc.).
- **Equipo origen** (quién se conectó).
- Si hubo consulta **Abuse/Whois** (datos del proveedor).

### 12.4 Alerta de emergencia — qué hacer

1. Identifica el **equipo origen**.
2. Si corresponde, **desconéctalo o revísalo**.
3. Revisa los **reportes**.
4. Revisa el **contacto de abuso** del proveedor.
5. **Reporta** al área correspondiente si aplica.

### 12.5 Correo forense

Cuando se detecta una IP peligrosa, además de la alerta de emergencia llega un
**Reporte Forense** que puede incluir:

- **AbuseIPDB**: reputación de la IP.
- **Whois**: a quién pertenece y su contacto de abuso.
- **VirusTotal**: análisis si está disponible.
- **Contacto abuse**: correo para reportar.

> ℹ️ Limitación: estos datos dependen de información **pública** y de tener API
> keys configuradas. Si faltan, Gleipnir sigue funcionando y lo indica.

[CAPTURA: Alerta de correo recibida (asunto ALERTA DE EMERGENCIA)]

---

## 13. Reportes

- Un reporte contiene los eventos del IDS/IPS en **JSON** y/o **CSV**.
- Se guardan en la carpeta de reportes (`logs/reports/` por defecto).
- Los secretos se **ocultan** en los reportes.

```bash
gleipnir report
gleipnir report --format json
gleipnir report --format csv
```

Cómo leer las columnas:

| Campo | Significado |
|---|---|
| `timestamp` | Fecha y hora del evento |
| `event_type` | Tipo de evento (ver tabla 12.1) |
| `severity` | Gravedad (INFO/BAJA/MEDIA/ALTA) |
| `source_ip` | IP de origen |
| `destination_ip` | IP de destino |
| `domain` | Dominio (en eventos DNS/HTTP) |
| `message` | Descripción del evento |

[CAPTURA: Reporte generado en terminal]
[CAPTURA: Reporte / eventos visibles en el Dashboard]

---

## 14. Ejemplos de operación diaria

### Escenario 1: Agregar una computadora nueva

1. Obtén su **IP** y **MAC** (`ip addr` en ese equipo).
2. Agrégala a la whitelist:
   `gleipnir whitelist add --ip <IP> --mac <MAC> --description "<nombre>"`.
3. Valida: `gleipnir whitelist validate`.
4. Confírmalo en el Dashboard.

### Escenario 2: Revisar si hubo dispositivos desconocidos

1. Abre el Dashboard.
2. Mira la tarjeta **Dispositivos no autorizados**.
3. Entra a **Eventos**.
4. Abre el detalle de cada `UNAUTHORIZED_DEVICE`.
5. Decide: agregar a whitelist o investigar.

### Escenario 3: Revisar sitios visitados

1. Genera/abre un reporte de eventos DNS/HTTP:
   `gleipnir report --type DNS_EVENT` o filtra por dominio.
2. Filtra por equipo: `--source-ip <IP>`.
3. Revisa los dominios.

### Escenario 4: IP peligrosa detectada

1. Revisa la **alerta de emergencia** (correo).
2. Revisa la **IP origen** (equipo interno).
3. Revisa los datos **Abuse/Whois** del reporte forense.
4. Genera un reporte: `gleipnir report --type BLACKLISTED_EXTERNAL_IP`.
5. Toma acción defensiva.

### Escenario 5: Activar IPS en laboratorio

1. `gleipnir ips status` (ver estado).
2. `gleipnir ips dry-run` (simular reglas).
3. Revisa las reglas mostradas.
4. `gleipnir ips enable` y `gleipnir ips dry-run-disable`.
5. `sudo .venv/bin/gleipnir ips apply` (aplicar).
6. Confirma con `gleipnir ips status`.
7. Si algo falla: `sudo .venv/bin/gleipnir ips remove`.

---

## 15. Troubleshooting básico (solución de problemas)

| # | Problema | Causa probable | Solución paso a paso | Comando útil |
|---|---|---|---|---|
| 1 | `sudo: gleipnir: command not found` | `sudo` no ve el entorno virtual | Usa la ruta completa al binario | `sudo .venv/bin/gleipnir live --interface ens33` |
| 2 | `Permission denied` al capturar | Captura necesita permisos | Ejecuta con `sudo` (ruta completa) | `sudo .venv/bin/gleipnir live --interface ens33` |
| 3 | No llegan correos | SMTP mal configurado o sin internet | Revisa `SMTP_HOST/PORT/USER/PASSWORD/ADMIN_EMAIL`, conexión y TLS/STARTTLS | `gleipnir test-config` |
| 4 | El correo llega a spam | Filtros del proveedor | Revisa carpeta spam; marca el remitente como seguro; usa correo institucional; revisa SPF/DKIM/DMARC del dominio; evita asuntos genéricos; pide al admin de correo permitir el remitente; prueba otro `ADMIN_EMAIL`; no uses cuentas personales si hay políticas | — |
| 5 | `SMTP authentication failed` | Usuario/clave o puerto incorrectos | Verifica contraseña; usa "contraseña de aplicación" si el proveedor la exige; revisa puerto `587`/`465` y TLS | `gleipnir test-config` |
| 6 | El Dashboard no abre | No está corriendo / puerto / host | Verifica que `gleipnir dashboard` está activo, el puerto, el firewall y `127.0.0.1` vs `0.0.0.0` | `gleipnir dashboard --host 127.0.0.1 --port 8080` |
| 7 | No puedo entrar al Dashboard (login) | Usuario inexistente/deshabilitado | Crea/activa usuario; cambia contraseña | `gleipnir user list` / `gleipnir user change-password --username admin` |
| 8 | No accedo desde otro equipo | Host/IP/red/firewall | Usa `--host 0.0.0.0 --allow-lan`, verifica IP (`ip addr`), misma red y firewall | `gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan` |
| 9 | Puerto 8080 ocupado | Otro proceso usa el puerto | Usa otro puerto | `gleipnir dashboard --port 8081` |
| 10 | Olvidé la contraseña del Dashboard | — | Cambia la contraseña con el comando (no edites hashes a mano) | `gleipnir user change-password --username admin` |
| 11 | `dashboard_users.json` con permisos inseguros | Permisos del archivo abiertos | El Dashboard avisa; restringe permisos del archivo | `chmod 600 data/dashboard_users.json` |
| 12 | No aparecen eventos | Aún no hay tráfico/eventos | Genera eventos con `replay` de un PCAP de prueba o captura en vivo | `gleipnir replay --pcap archivo.pcap --delay 1` |
| 13 | `live` muestra paquetes `Raw` | Falta backend de captura | Instala `libpcap-dev`/`tcpdump`, prueba `tcpdump`, usa `--use-pcap`, revisa la interfaz | `sudo apt install -y libpcap-dev tcpdump` |
| 14 | No se detectan DNS/HTTP | HTTPS cifra; DNS puede ir cifrado | HTTPS no muestra rutas; DNS por DoH/DoT no es visible; verifica que haya tráfico; prueba con un PCAP | `gleipnir replay --pcap archivo.pcap` |
| 15 | `ips apply` no aplica reglas | IPS apagado o en dry-run / sin sudo | Activa IPS, desactiva dry-run y usa sudo | `gleipnir ips enable` → `gleipnir ips dry-run-disable` → `sudo .venv/bin/gleipnir ips apply` |
| 16 | `nft: command not found` | nftables no instalado | Instálalo | `sudo apt install -y nftables` |
| 17 | AbuseIPDB/VirusTotal no responden | Sin API key / rate limit / timeout | Configura `ABUSEIPDB_API_KEY`/`VIRUSTOTAL_API_KEY`; espera si hay límite; el IDS sigue funcionando | `gleipnir test-config` |
| 18 | Whois sin contacto de abuso | El proveedor no publica el dato | Es una limitación de datos públicos; usa la info disponible | — |
| 19 | El sistema no bloquea tráfico | Es IDS pasivo por defecto | El IPS debe activarse; `dry-run` no bloquea; `apply` sí | `gleipnir ips status` |

---

## 16. Buenas prácticas de seguridad

- ❌ **No subas `.env` a Git** ni lo compartas.
- ❌ **No compartas contraseñas.**
- ✅ Usa **usuarios separados** viewer/admin.
- ✅ Usa **contraseñas fuertes**.
- ❌ **No expongas el Dashboard a internet.**
- ✅ Usa **HTTPS con reverse proxy** si sale de localhost.
- ✅ **Revisa los logs** periódicamente.
- ✅ **Remueve las reglas IPS** (`ips remove`) si causan problemas.
- ✅ **Prueba primero en `dry-run`** antes de aplicar reglas reales.
- ✅ Úsalo solo en **red propia o laboratorio autorizado**.

---

## 17. Glosario

| Término | Definición sencilla |
|---|---|
| **IDS** | Sistema que **detecta** y avisa, sin bloquear |
| **IPS** | Sistema que además puede **bloquear/permitir** tráfico |
| **Firewall** | "Muro" que filtra tráfico según reglas |
| **Whitelist** | Lista de equipos **autorizados** |
| **Blacklist** | Lista de IPs **peligrosas** |
| **IP** | Dirección de un equipo en la red |
| **MAC** | Identificador físico de la tarjeta de red |
| **DNS** | Servicio que traduce nombres (dominios) a IPs |
| **HTTP** | Protocolo web **sin cifrar** |
| **HTTPS** | Protocolo web **cifrado** (no muestra rutas) |
| **SMTP** | Protocolo para **enviar correos** |
| **PCAP** | Archivo con tráfico de red capturado |
| **Dashboard** | Panel web para ver eventos |
| **CLI** | Operación por línea de comandos (terminal) |
| **nftables** | Firewall de Linux usado por el IPS |
| **Abuse contact** | Correo para **reportar abusos** de una IP |
| **Whois** | Consulta de a quién pertenece una IP/dominio |
| **Threat Intelligence** | Información de reputación/amenazas de IPs |

---

## 18. Comandos rápidos

| Tarea | Comando | Qué hace | ¿sudo? |
|---|---|---|---|
| Ver ayuda | `gleipnir --help` | Lista todos los comandos | No |
| Probar config | `gleipnir test-config` | Valida `.env` (oculta secretos) | No |
| Estado/salud | `gleipnir status` | Healthcheck local | No |
| Mantenimiento | `gleipnir maintenance` | Aplica retención de datos | No |
| Analizar PCAP | `gleipnir offline --pcap archivo.pcap` | Procesa un PCAP | No |
| Reproducir PCAP | `gleipnir replay --pcap archivo.pcap --delay 1` | Simula tráfico | No |
| Captura en vivo | `sudo .venv/bin/gleipnir live --interface ens33` | Escucha la red | Sí |
| Generar reporte | `gleipnir report` | Crea JSON/CSV | No |
| Whitelist: agregar | `gleipnir whitelist add --ip <IP> --mac <MAC> --description "<txt>"` | Autoriza un equipo | No |
| Whitelist: listar | `gleipnir whitelist list` | Muestra autorizados | No |
| Whitelist: validar | `gleipnir whitelist validate` | Revisa el archivo | No |
| Whitelist: eliminar | `gleipnir whitelist remove --ip <IP>` | Quita un equipo | No |
| Blacklist: agregar | `gleipnir blacklist add --ip <IP> --reason "Botnet"` | Marca IP peligrosa | No |
| Blacklist: listar | `gleipnir blacklist list` | Muestra IPs peligrosas | No |
| Blacklist: validar | `gleipnir blacklist validate` | Revisa el archivo | No |
| Blacklist: eliminar | `gleipnir blacklist remove --ip <IP>` | Quita una IP | No |
| Usuario: crear | `gleipnir user create --username <u> --role admin\|viewer` | Crea usuario del Dashboard | No |
| Usuario: listar | `gleipnir user list` | Lista usuarios | No |
| Usuario: cambiar clave | `gleipnir user change-password --username <u>` | Cambia contraseña | No |
| Usuario: deshabilitar | `gleipnir user disable --username <u>` | Desactiva usuario | No |
| Usuario: habilitar | `gleipnir user enable --username <u>` | Activa usuario | No |
| Usuario: migrar `.env` | `gleipnir user migrate-env` | Migra credenciales legadas del `.env` | No |
| Correo admin: ver | `gleipnir admin-email show` | Muestra `ADMIN_EMAIL` | No |
| Correo admin: cambiar | `gleipnir admin-email set --email <correo>` | Cambia el destinatario | No |
| Dashboard local | `gleipnir dashboard --host 127.0.0.1 --port 8080` | Panel web local | No |
| Dashboard LAN | `gleipnir dashboard --host 0.0.0.0 --port 8080 --allow-lan` | Panel accesible en la red | No |
| IPS: estado | `gleipnir ips status` | Estado del IPS | No |
| IPS: ver config | `gleipnir ips config show` | Config operativa | No |
| IPS: cambiar clave config | `gleipnir ips config set --key <k> --value <v>` | Cambia un valor | No |
| IPS: activar | `gleipnir ips enable` | `ips_enabled=true` (no aplica) | No |
| IPS: desactivar | `gleipnir ips disable` | `ips_enabled=false` | No |
| IPS: dry-run on/off | `gleipnir ips dry-run-enable` / `dry-run-disable` | Modo simulación | No |
| IPS: simular | `gleipnir ips dry-run` | Muestra reglas sin aplicar | No |
| IPS: ver reglas | `gleipnir ips rules` | Imprime el ruleset nftables | No |
| IPS: aplicar | `sudo .venv/bin/gleipnir ips apply` | Aplica reglas reales | Sí |
| IPS: remover | `sudo .venv/bin/gleipnir ips remove` | Borra solo la tabla de Gleipnir | Sí |
| IPS: política allowlist | `gleipnir ips policy allowlist --mode monitor\|allow_registered\|block_unregistered` | Cambia política allowlist | No |
| IPS: política blacklist | `gleipnir ips policy blacklist --mode monitor\|block` | Cambia política blacklist | No |
| IPS: dirección | `gleipnir ips direction --mode outbound\|inbound\|both` | Dirección de bloqueo | No |
| IPS: IPs privadas | `gleipnir ips private-check enable\|disable` | Revisar IPs privadas en blacklist | No |
| IPS: auto-apply | `gleipnir ips auto-apply enable\|disable` | Permitir aplicar desde Dashboard | No |

---

## Capturas de pantalla pendientes (tomar manualmente)

1. `[CAPTURA: Comando gleipnir --help]`
2. `[CAPTURA: Salida de gleipnir test-config con secretos ocultos]`
3. `[CAPTURA: Alta de IP/MAC en whitelist desde CLI]`
4. `[CAPTURA: Formulario de alta de IP/MAC en whitelist en el Dashboard]`
5. `[CAPTURA: Pantalla inicial del Dashboard / login]`
6. `[CAPTURA: Dashboard principal con tarjetas de eventos y gráficas]`
7. `[CAPTURA: Reporte de eventos / tabla de últimos eventos con filtros]`
8. `[CAPTURA: Alerta de correo recibida (ALERTA DE EMERGENCIA)]`
9. `[CAPTURA: Configuración IPS desde el Dashboard (/admin/ips)]`
10. `[CAPTURA: Reporte generado en terminal]`
11. `[CAPTURA: Reporte / eventos visibles en el Dashboard]`

---

> Documentación relacionada: `README.md` (resumen e instalación),
> `docs/ips_firewall.md` (IPS en detalle), `docs/dashboard.md` (Dashboard),
> `docs/security.md` (seguridad), `docs/credenciales.md` (protección de
> secretos), `docs/troubleshooting.md` (diagnósticos avanzados).
