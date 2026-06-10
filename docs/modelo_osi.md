# Relacion con el Modelo OSI

## Objetivo

Este documento explica como Gleipnir se relaciona con el modelo OSI y que capas
usa para cumplir los criterios del IDS institucional.

## Capa 1 - Fisica

Gleipnir no opera directamente en la capa fisica. No manipula cableado, radio,
potencia, canales ni hardware.

## Capa 2 - Enlace de datos

Uso en el proyecto:

- Direcciones MAC de origen y destino.
- Tramas Ethernet procesadas desde PCAP.
- ARP en modo live con Scapy.
- Validacion de identidad MAC contra whitelist.
- En politica `strict`, la MAC debe coincidir con la IP autorizada del mismo
  registro de whitelist.

Modulos relacionados:

- `src/sniffer.py`
- `src/whitelist.py`
- `src/detector.py`

Rubro cubierto:

- Modulo de listas blancas, capa 2.

## Capa 3 - Red

Uso en el proyecto:

- IPv4.
- IPv6.
- IP origen.
- IP destino.
- Validacion de identidad IP contra whitelist.
- Deteccion de destino externo.
- Comparacion contra blacklist local.
- Enriquecimiento de IP externa cuando se genera un evento relevante.
- En politica `ip_fallback`, si la captura no trae MAC, la autorizacion puede
  hacerse por IP registrada.

Modulos relacionados:

- `src/sniffer.py`
- `src/blacklist.py`
- `src/detector.py`
- `src/threat_intel.py`

Rubro cubierto:

- Modulo de listas blancas, capa 3.
- Modulo de IPs peligrosas.

## Capa 4 - Transporte

Uso en el proyecto:

- Identificacion de protocolo por numero IP cuando esta disponible.
- TCP.
- UDP.
- ICMP.
- ICMPv6.

Gleipnir no abre sesiones ni modifica flujos. Solo registra metadatos.

## Capa 5 - Sesion

No hay manejo directo de sesiones. El IDS no mantiene sesiones de aplicacion ni
interviene conexiones.

## Capa 6 - Presentacion

No hay descifrado, traduccion ni compresion de datos. El sistema no descifra TLS
ni inspecciona contenido cifrado.

## Capa 7 - Aplicacion

Uso en el proyecto:

- DNS: dominio consultado y tipo de consulta si esta disponible.
- HTTP: host, metodo y ruta si estan disponibles.
- SMTP: envio de alertas administrativas.
- APIs HTTPS: AbuseIPDB y VirusTotal.
- Whois: consulta de informacion administrativa de IP.
- CLI `gleipnir`: operacion administrativa desde terminal.
- Healthcheck `gleipnir status`: validacion administrativa sin enviar correo.
- Mantenimiento `gleipnir maintenance`: retencion de eventos, reportes y logs.

Modulos relacionados:

- `src/dns_http_monitor.py`
- `src/mailer.py`
- `src/threat_intel.py`
- `src/reports.py`
- `src/alert_policy.py`
- `src/cli.py`
- `src/status.py`
- `src/maintenance.py`

Rubro cubierto:

- Modulo de monitoreo de sitios.
- Modulo de automatizacion forense Abuse/Whois.
- Alertas por correo.
- Politicas de alerta para evitar correos repetidos.

## Componentes transversales

Algunos modulos no corresponden a una capa OSI especifica, pero sostienen el
flujo del IDS:

- `src/runtime/engine.py`: orquestador central `IDSEngine`.
- `src/config.py`: carga `.env` sin credenciales hardcodeadas.
- `src/logger.py`: bitacoras con redaccion de secretos.
- `src/storage.py`: persistencia SQLite de eventos.
- `src/reports.py`: reportes JSON/CSV con filtros.
- `deploy/systemd/gleipnir.service`: ejecucion 24/7 del modo live.
- `gleipnir live --interface <interfaz> --forever`: supervision operativa del
  ciclo de captura.
- `gleipnir maintenance`: retencion de eventos SQLite, reportes y logs.

Estos componentes operan sobre los metadatos obtenidos de las capas 2, 3, 4 y 7.

## Eventos principales

Gleipnir registra eventos como:

- `AUTHORIZED_DEVICE`
- `UNAUTHORIZED_DEVICE`
- `DNS_EVENT`
- `HTTP_EVENT`
- `BLACKLISTED_EXTERNAL_IP`
- `THREAT_INTEL_RESULT`
- `ALERT_SENT`
- `ALERT_SUPPRESSED`

## Limitaciones por capa

- HTTPS no expone metodo/ruta HTTP en texto claro sin descifrado, y el proyecto
  no implementa descifrado.
- Si un paquete no contiene capa DNS/HTTP accesible, el monitor no inventa datos.
- La identidad IP/MAC depende de lo observado en la red; NAT, DHCP y MAC
  aleatoria pueden afectar resultados.
- SQLite y reportes almacenan metadatos administrativos; no agregan capacidad de
  inspeccion ofensiva ni descifrado.
- systemd, healthcheck y mantenimiento son controles operativos; no amplian la
  inspeccion de red ni modifican trafico.
