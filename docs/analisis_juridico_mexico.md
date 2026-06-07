# Analisis Juridico Mexico

## Aviso

Este documento es una guia educativa para un proyecto academico. No sustituye
asesoria legal. Antes de operar el IDS en una organizacion real, se recomienda
validar politicas internas, avisos de privacidad y contratos aplicables con el
area juridica correspondiente.

## Alcance del monitoreo

Gleipnir esta disenado para redes institucionales propias y dispositivos bajo
administracion o autorizacion de la organizacion. Su alcance es defensivo:

- Inventario y validacion IP/MAC.
- Deteccion de dispositivos no autorizados.
- Registro de dominios DNS y HTTP cuando esten disponibles.
- Deteccion de IPs externas en blacklist.
- Enriquecimiento de IPs externas mediante servicios de reputacion.
- Alertas administrativas, incluidas alertas suprimidas por politica.
- Reportes administrativos generados desde SQLite.
- Dashboard local de visualizacion y administracion limitada de listas.
- Auditoria administrativa de login/logout y cambios de whitelist/blacklist.
- Healthcheck operativo sin envio de correos reales.
- Mantenimiento de retencion para limitar crecimiento de datos.
- Ejecucion 24/7 con systemd en infraestructura autorizada.

No debe usarse para interceptar comunicaciones privadas, obtener credenciales,
evadir controles, explotar sistemas o monitorear redes ajenas.

## Datos personales y metadatos

En un contexto institucional, IP, MAC, dominios consultados, horarios y reportes
pueden asociarse a una persona, area o equipo. Por ello deben tratarse con
criterios de minimizacion, finalidad, informacion, seguridad y retencion.

La base SQLite configurada con `IDS_DB_PATH` almacena eventos acumulados. Aunque
no debe contener credenciales, si puede contener metadatos operativos sensibles.
Debe limitarse su acceso y definirse un periodo de conservacion.

La auditoria administrativa del dashboard puede registrar usuario, accion, IP
remota, resultado y mensaje. Estos datos apoyan trazabilidad y control interno,
pero tambien deben protegerse porque pueden asociarse a personas administradoras
o a decisiones operativas.

La version actual permite configurar retencion mediante `EVENT_RETENTION_DAYS`,
`MAX_REPORTS_TO_KEEP` y `MAX_LOG_SIZE_MB`. Estas variables apoyan el principio
de minimizacion, porque evitan conservar eventos, reportes y logs por tiempo
indefinido.

## Marco constitucional

La Constitucion reconoce la proteccion de datos personales y la inviolabilidad
de comunicaciones privadas. Para este proyecto, la lectura juridica prudente es:

- Monitorear solo infraestructura propia o autorizada.
- Registrar metadatos necesarios para seguridad.
- Evitar contenido privado cuando no sea indispensable.
- No descifrar ni intervenir comunicaciones sin base legal especifica.

Fuente oficial: Constitucion Politica de los Estados Unidos Mexicanos, Camara de
Diputados: https://www.diputados.gob.mx/LeyesBiblio/pdf/CPEUM.pdf

## Proteccion de datos personales

La Ley Federal de Proteccion de Datos Personales en Posesion de los Particulares
y su Reglamento son relevantes si la organizacion trata datos personales en el
ambito privado. Para el IDS:

- Definir finalidad: seguridad de la red institucional.
- Informar en politicas internas o aviso aplicable.
- Limitar acceso a logs y reportes.
- Evitar conservar datos mas tiempo del necesario.
- Proteger archivos `.env`, logs, reportes y cache.
- Proteger la base SQLite de eventos.
- Proteger acceso al dashboard con autenticacion, roles, CSRF y HTTPS cuando
  aplique.
- Revisar eventos de auditoria administrativa sin publicar datos sensibles.
- Atender derechos y procedimientos internos cuando apliquen.

Fuentes oficiales:

- LFPDPPP: https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf
- Reglamento LFPDPPP:
  https://www.diputados.gob.mx/LeyesBiblio/regley/Reg_LFPDPPP.pdf

## Sujetos obligados

Si el IDS se implementa en una institucion publica, tambien puede aplicar la
legislacion de datos personales para sujetos obligados. En ese caso se requiere
validar el marco especifico de la entidad y sus lineamientos internos.

Fuente oficial de referencia legislativa:
https://www.diputados.gob.mx/LeyesBiblio/ref/lgpdppso.htm

## Acceso ilicito y delitos informaticos

El Codigo Penal Federal contiene disposiciones sobre revelacion de secretos y
acceso ilicito a sistemas y equipos de informatica. Para mantener el proyecto
dentro de un alcance defensivo:

- No acceder a sistemas sin autorizacion.
- No intentar credenciales.
- No explotar vulnerabilidades.
- No alterar trafico.
- No evadir controles.
- No capturar redes de terceros.
- No usar el IDS para obtener secretos, credenciales o contenido privado.

Fuente oficial: Codigo Penal Federal, Camara de Diputados:
https://www.diputados.gob.mx/LeyesBiblio/pdf/CPF.pdf

## Ambito laboral e institucional

Si el IDS se usa en equipos o redes de una organizacion, debe existir una
politica interna que informe a usuarios y administradores:

- Que la red institucional puede ser monitoreada con fines de seguridad.
- Que tipo de metadatos se registran.
- Quien puede acceder a los reportes.
- Quien puede consultar la base SQLite y bitacoras.
- Cuanto tiempo se conservan.
- Que existe una politica de retencion para eventos, reportes y logs.
- Que el dashboard administrativo registra auditoria de accesos y cambios de
  listas.
- Como se reportan incidentes.

Fuente de referencia: Ley Federal del Trabajo, Camara de Diputados:
https://portalhcd.diputados.gob.mx/LeyesBiblio/PortalWeb/Leyes/Vigentes/PDF/125_230421.pdf

## Telecomunicaciones y comunicaciones

La regulacion de telecomunicaciones protege derechos de usuarios y audiencias y
establece reglas sobre servicios de telecomunicaciones. El IDS no debe
presentarse como intervencion de comunicaciones ni como herramienta para acceder
a contenido privado. Su diseno actual opera sobre metadatos observables en una
red institucional propia.

Fuente oficial: Ley en Materia de Telecomunicaciones y Radiodifusion:
https://www.diputados.gob.mx/LeyesBiblio/pdf/LMTR.pdf

## Politica minima recomendada

La organizacion deberia contar con una politica de uso aceptable que indique:

- La red es institucional y puede ser monitoreada para seguridad.
- El monitoreo busca proteger disponibilidad, integridad y seguridad.
- Se registran IPs, MACs, dominios DNS/HTTP cuando esten disponibles, IPs
  externas, resultados de reputacion y eventos de alerta.
- No se buscan contrasenas ni contenido privado.
- Los reportes tienen acceso restringido.
- La base SQLite, logs, cache y reportes tienen acceso restringido.
- El dashboard no se expone a internet y usa HTTPS con reverse proxy si sale de
  localhost o laboratorio local.
- Los eventos de auditoria administrativa se revisan solo por personal
  autorizado.
- Hay periodo de retencion definido.
- Los usuarios deben reportar equipos no registrados o incidentes.

## Servicios externos de reputacion

AbuseIPDB, VirusTotal y Whois pueden recibir IPs externas consultadas para
enriquecimiento defensivo. En la version actual, Gleipnir no consulta estos
servicios para todo el trafico, sino solo cuando hay una IP externa relevante o
un evento `BLACKLISTED_EXTERNAL_IP`. La organizacion debe validar que esa
transferencia de metadatos sea compatible con sus politicas internas y contratos
aplicables.

## Reportes y filtros

Los reportes filtrados ayudan a limitar la revision a eventos necesarios por
tipo, fecha, IP origen, dominio o severidad. Esta funcion debe usarse para
minimizar exposicion de datos y entregar solo la informacion necesaria al
personal autorizado.

## Operacion 24/7 y systemd

El modo `gleipnir live --interface <interfaz> --forever` y el servicio systemd
estan pensados para continuidad operativa en una red propia. Antes de activarlo,
la organizacion debe confirmar autorizacion sobre la interfaz monitoreada,
permisos de captura, finalidad de seguridad, retencion de datos y acceso
restringido a logs, SQLite y reportes.

`gleipnir status` ayuda a validar configuracion y disponibilidad sin enviar
correos reales. `gleipnir maintenance` ayuda a cumplir la politica de retencion
definida por la organizacion.

## Conclusion

Gleipnir puede alinearse con un uso legal y proporcional si se limita a redes
propias, se informa a usuarios, se minimizan datos, se protegen bitacoras y se
evita cualquier funcion ofensiva o de intervencion no autorizada.
