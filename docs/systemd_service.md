# Servicio systemd - Gleipnir IDS 24/7

Este documento describe como ejecutar Gleipnir IDS como servicio persistente en
Ubuntu 24.04 LTS usando el modo live.

El despliegue esta pensado para una red propia o institucional autorizada, con
fines defensivos y educativos. No incluye credenciales reales y no modifica la
logica del IDS.

## 1. Copiar el proyecto a /opt/gleipnir

Desde el equipo donde se desplegara el IDS:

```bash
sudo mkdir -p /opt/gleipnir
sudo cp -a . /opt/gleipnir/
sudo chown -R root:root /opt/gleipnir
cd /opt/gleipnir
```

Si se prefiere que un usuario administrativo mantenga los archivos, ajustar el
propietario con la cuenta aprobada por la organizacion.

## 2. Crear entorno virtual

Instalar prerrequisitos del sistema:

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

Preparar configuracion local:

```bash
cp .env.example .env
sudo chmod 600 .env
sudo mkdir -p data logs logs/reports
```

Editar `.env` con los valores reales del entorno. No incluir credenciales en el
repositorio ni compartir el archivo `.env`.

Para despliegue 24/7, se recomienda registrar tambien la interfaz esperada:

```env
GLEIPNIR_INTERFACE=<INTERFAZ>
GLEIPNIR_MODE=live
HEALTH_LOG_INTERVAL_SECONDS=300
EVENT_RETENTION_DAYS=30
MAX_LOG_SIZE_MB=50
MAX_REPORTS_TO_KEEP=20
```

Validar la configuracion:

```bash
gleipnir test-config
gleipnir status
```

`gleipnir status` verifica la configuracion, listas, directorios, SQLite si ya
existe, disponibilidad SMTP sin enviar correo real y la interfaz indicada en
`GLEIPNIR_INTERFACE`.

## 4. Editar la interfaz de red

Identificar la interfaz autorizada para monitoreo:

```bash
ip link
```

Editar el archivo de ejemplo antes de instalarlo:

```bash
sudo nano /opt/gleipnir/deploy/systemd/gleipnir.service
```

Reemplazar el placeholder `<INTERFAZ>` en esta linea:

```ini
ExecStart=/opt/gleipnir/.venv/bin/gleipnir live --interface <INTERFAZ> --forever
```

Ejemplo despues de editar, usando una interfaz real del servidor:

```ini
ExecStart=/opt/gleipnir/.venv/bin/gleipnir live --interface wlan0 --forever
```

No dejar `<INTERFAZ>` en el servicio final, porque systemd intentaria pasarlo
literalmente al comando.

La interfaz usada aqui debe coincidir con `GLEIPNIR_INTERFACE` si esa variable
esta definida en `.env`.

## 5. Copiar el servicio a /etc/systemd/system/

```bash
sudo cp /opt/gleipnir/deploy/systemd/gleipnir.service /etc/systemd/system/gleipnir.service
```

Revisar el archivo instalado:

```bash
sudo systemctl cat gleipnir
```

## 6. Habilitar e iniciar el servicio

Ejecutar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable gleipnir
sudo systemctl start gleipnir
sudo systemctl status gleipnir
```

Ver logs en tiempo real:

```bash
journalctl -u gleipnir -f
```

Para detener el servicio:

```bash
sudo systemctl stop gleipnir
```

## 7. Permisos de captura

El unit file se instala como servicio de sistema y, si no se define `User=`,
systemd lo ejecuta como root. Esto permite usar Scapy para captura live en
Ubuntu, donde normalmente se requieren permisos de red elevados.

Si la organizacion decide ejecutar el servicio con un usuario no root, se deben
configurar capacidades de captura de red de forma controlada y documentada por
el administrador del sistema. La opcion root por systemd es la ruta mas directa
para laboratorio academico, pero debe limitarse a equipos y redes autorizadas.

## 8. Flujo 24/7

Con el servicio habilitado:

1. Ubuntu inicia `gleipnir.service` durante el arranque.
2. systemd carga `/opt/gleipnir/.env`.
3. Ejecuta `/opt/gleipnir/.venv/bin/gleipnir live --interface <INTERFAZ> --forever`.
4. Gleipnir usa `IDSEngine` para procesar eventos live.
5. Los eventos se registran en logs, SQLite y reportes segun la configuracion.
6. Si el proceso falla, systemd lo reinicia por `Restart=always` despues de 5
   segundos.

Con `--forever`, Gleipnir tambien reintenta errores recuperables de captura,
mantiene contadores acumulados y registra lineas periodicas
`LIVE_CAPTURE_HEALTH` cada `HEALTH_LOG_INTERVAL_SECONDS`.

## 9. Mantenimiento de retencion

Cuando Gleipnir corre 24/7, ejecutar periodicamente:

```bash
cd /opt/gleipnir
source .venv/bin/activate
gleipnir maintenance
```

Este comando elimina eventos SQLite mas antiguos que `EVENT_RETENTION_DAYS`,
mantiene solo los ultimos `MAX_REPORTS_TO_KEEP` archivos de reporte y valida
que los logs roten por tamano con `MAX_LOG_SIZE_MB`.

## 10. Seguridad operativa

- Usar el servicio solo en redes propias o con autorizacion expresa.
- Mantener `.env` con permisos restrictivos.
- No almacenar contrasenas ni API keys en el unit file.
- Revisar periodicamente `journalctl -u gleipnir` y los logs configurados.
- Confirmar que `WHITELIST_FILE`, `BLACKLIST_FILE`, `LOG_DIR`, `REPORT_DIR` e
  `IDS_DB_PATH` apunten a rutas existentes y escribibles.
