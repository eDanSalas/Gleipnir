# Troubleshooting - Gleipnir IDS

> Para una guía de solución de problemas orientada a usuarios no técnicos (correo
> en spam, login del Dashboard, `command not found`, puerto ocupado, IPS, etc.)
> consulta la sección 15 de [`docs/manual_usuario.md`](manual_usuario.md). Este
> documento cubre diagnósticos más técnicos.

## Live capture recibe paquetes como Raw

Si los logs muestran algo similar a:

```text
summary=Raw layers=Raw
```

significa que Gleipnir si esta recibiendo paquetes desde la interfaz, pero
Scapy no esta decodificando la capa de enlace. En ese caso `parse_packet()` no
puede encontrar directamente ARP, IPv4 ni IPv6 hasta reinterpretar los bytes o
usar otro backend de captura.

Primero verifica que la interfaz realmente vea trafico:

```bash
sudo tcpdump -i ens33 -c 10 -nn
```

Instala las dependencias de captura recomendadas en Ubuntu 24.04 LTS:

```bash
sudo apt install -y libpcap-dev tcpdump
```

Despues ejecuta Gleipnir con diagnostico y backend libpcap:

```bash
sudo .venv/bin/gleipnir live --interface ens33 --debug-packets --packet-count 20 --use-pcap
```

Tambien puedes activar libpcap desde `.env`:

```bash
GLEIPNIR_SCAPY_USE_PCAP=true
```

Con `--debug-packets`, Gleipnir muestra por paquete:

- `summary` del paquete.
- Capas detectadas por Scapy.
- Clase Python del paquete.
- Si llego como `Raw`.
- Primeros 32 bytes en hexadecimal.
- Si pudo decodificarse como Ethernet, IPv4 o IPv6.

Gleipnir no imprime payloads completos ni secretos. Si un paquete `Raw` no se
puede decodificar, se cuenta como `unsupported_packets`; no debe convertirse en
un error de parseo masivo.

Contadores utiles para diagnostico live:

- `received`: paquetes recibidos por Scapy.
- `raw_packets`: paquetes recibidos como `Raw`.
- `decoded_from_raw`: paquetes `Raw` reinterpretados correctamente.
- `ignored_packets`: paquetes validos fuera del alcance ARP/IPv4/IPv6.
- `unsupported_packets`: paquetes con formato no soportado.
- `parse_errors`: errores reales de normalizacion.
- `packet_events`: eventos normalizados enviados al IDS.
- `engine_errors`: errores dentro del orquestador.
- `detections`: eventos de deteccion generados.
- `dns_http_events`: eventos DNS/HTTP generados.

