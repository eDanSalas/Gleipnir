# Servicio systemd - Dashboard Gleipnir 24/7

Este documento describe como ejecutar el dashboard web local de Gleipnir como
servicio persistente en Ubuntu Server 24.04 LTS.

Las vistas de eventos del dashboard son de solo lectura. Si
`DASHBOARD_AUTH_ENABLED=true`, tambien puede habilitarse `/admin/lists` para
administrar whitelist y blacklist. Debe usarse en red local, laboratorio o
infraestructura institucional autorizada. No exponerlo a internet. Para un
entorno de produccion real se requeriria HTTPS y autenticacion mas robusta.

## 1. Copiar el proyecto a /opt/gleipnir

Desde el servidor donde se ejecutara el dashboard:

```bash
sudo mkdir -p /opt/gleipnir
sudo cp -a . /opt/gleipnir/
sudo chown -R root:root /opt/gleipnir
cd /opt/gleipnir
```

Si la organizacion usa un usuario administrativo especifico para mantener los
archivos, ajustar propietario y permisos segun su politica interna.

## 2. Crear entorno virtual

Instalar prerrequisitos:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev tcpdump whois
```

Crear el entorno virtual:

```bash
cd /opt/gleipnir
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
```

## 3. Instalar Gleipnir en modo editable

```bash
cd /opt/gleipnir
source .venv/bin/activate
pip install -e .
gleipnir --help
```

## 4. Configurar .env

Crear el archivo local de configuracion:

```bash
cd /opt/gleipnir
cp .env.example .env
sudo chmod 600 .env
sudo mkdir -p data logs logs/reports
```

Editar `.env` con los valores reales del entorno. No guardar credenciales reales
en el repositorio ni en el archivo de servicio systemd.

Variables relevantes para el dashboard:

```env
LOG_DIR=logs/
REPORT_DIR=logs/reports/
IDS_DB_PATH=data/gleipnir_events.db
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=admin-local
DASHBOARD_PASSWORD=cambiar-esta-contrasena
```

`IDS_DB_PATH` debe apuntar a la misma base SQLite donde el IDS guarda eventos.
Si el dashboard se ejecuta en el mismo servidor que `gleipnir live`, ambos
servicios pueden compartir `/opt/gleipnir/.env`.

Validar configuracion basica:

```bash
gleipnir test-config
gleipnir status
```

## 5. Configurar DASHBOARD_AUTH_ENABLED

Cuando el servicio use `--host 0.0.0.0`, el dashboard queda disponible desde la
red local por IP y puerto. Mantener autenticacion activa:

```env
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=admin-local
DASHBOARD_PASSWORD=cambiar-esta-contrasena
```

No dejar `DASHBOARD_USERNAME` ni `DASHBOARD_PASSWORD` vacios si
`DASHBOARD_AUTH_ENABLED=true`; el dashboard no debe arrancar con autenticacion
incompleta.

Solo en pruebas locales controladas puede desactivarse:

```env
DASHBOARD_AUTH_ENABLED=false
```

Con autenticacion desactivada, cualquier equipo que alcance el puerto del
servidor podria ver el dashboard. No usar esa configuracion al exponer
`0.0.0.0`.

## 6. Copiar el servicio a /etc/systemd/system/

El archivo de ejemplo se encuentra en:

```text
/opt/gleipnir/deploy/systemd/gleipnir-dashboard.service
```

Contenido principal:

```ini
WorkingDirectory=/opt/gleipnir
EnvironmentFile=/opt/gleipnir/.env
ExecStart=/opt/gleipnir/.venv/bin/gleipnir dashboard --host 0.0.0.0 --port 8080
Restart=always
RestartSec=5
```

Copiarlo al directorio de systemd:

```bash
sudo cp /opt/gleipnir/deploy/systemd/gleipnir-dashboard.service /etc/systemd/system/gleipnir-dashboard.service
```

Revisar el archivo instalado:

```bash
sudo systemctl cat gleipnir-dashboard
```

## 7. Habilitar e iniciar el servicio

Ejecutar en el servidor:

```bash
sudo systemctl daemon-reload
sudo systemctl enable gleipnir-dashboard
sudo systemctl start gleipnir-dashboard
sudo systemctl status gleipnir-dashboard
```

Ver logs en tiempo real:

```bash
journalctl -u gleipnir-dashboard -f
```

Para detenerlo:

```bash
sudo systemctl stop gleipnir-dashboard
```

## 8. Acceder desde navegador

Obtener la IP del servidor:

```bash
ip addr
```

Desde otro equipo de la misma red local:

```text
http://<IP_DEL_SERVIDOR>:8080
```

Ejemplo:

```text
http://192.168.1.50:8080
```

Si `DASHBOARD_AUTH_ENABLED=true`, el navegador solicitara usuario y contrasena.
No publicar estas credenciales ni compartir el archivo `.env`.

## 9. Seguridad operativa

- El servicio no contiene credenciales hardcodeadas.
- Las credenciales se cargan desde `/opt/gleipnir/.env`.
- Mantener `.env` con permisos restrictivos.
- No exponer el dashboard a internet.
- Usar firewall o segmentacion para limitar el acceso al puerto `8080`.
- Mantener `DASHBOARD_AUTH_ENABLED=true` cuando se use `--host 0.0.0.0`.
- Revisar periodicamente `journalctl -u gleipnir-dashboard` sin publicar datos
  sensibles.

## 10. Flujo 24/7

Con el servicio habilitado:

1. Ubuntu inicia `gleipnir-dashboard.service` durante el arranque.
2. systemd carga `/opt/gleipnir/.env`.
3. Ejecuta `/opt/gleipnir/.venv/bin/gleipnir dashboard --host 0.0.0.0 --port 8080`.
4. El dashboard lee eventos desde SQLite usando `IDS_DB_PATH`.
5. Si el proceso falla, systemd lo reinicia por `Restart=always` despues de 5
   segundos.
