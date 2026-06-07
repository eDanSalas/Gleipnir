# Proyecto: Gleipnir - IDS Institucional

Sistema operativo objetivo: Linux Ubuntu 24.04.4 LTS.

Objetivo:
Desarrollar un IDS que:
- Valide IP/MAC contra lista blanca.
- Detecte tráfico de IP/MAC no autorizada.
- Registre dominios visitados por DNS/HTTP.
- Compare IPs externas contra lista negra.
- Envíe alertas por correo usando SMTP configurado por .env.
- Consulte AbuseIPDB o Whois para datos de abuso.
- Genere documentación para manual de usuario y rúbrica.
- Emplee la API de Virus Total para validar sitios

Restricciones:
- No hardcodear contraseñas.
- Usar variables de entorno mediante .env.
- No implementar ataques, explotación ni evasión.
- Todo debe ser defensivo y para red institucional propia.
- Código claro, modular y documentado de manera segura.
- Antes de terminar, ejecutar pruebas o al menos validación sintáctica.

Stack:
- Python 3.11+
- Scapy o pyshark/libpcap
- python-dotenv
- smtplib/email
- requests
- python-whois o comandos whois
- Api de Virus Total

Definición de terminado:
- Código funcional.
- README actualizado.
- .env.example actualizado.
- Manual de usuario actualizado.
- Sin credenciales reales.