# Despliegue HTTPS del dashboard con reverse proxy

Esta guia describe un despliegue seguro conceptual para proteger el dashboard
web de Gleipnir con HTTPS mediante un reverse proxy. No implementa TLS dentro de
Flask y no modifica la logica del IDS.

## 1. Por que no exponer Flask directamente a internet

El servidor web integrado que usa Flask para el dashboard es adecuado para uso
local, laboratorio o demostracion academica. No debe exponerse directamente a
internet porque no esta pensado como frontera publica de seguridad.

En un entorno real, el componente expuesto debe ser un servidor web preparado
para operar como borde HTTP/HTTPS, por ejemplo Nginx o Caddy. Ese reverse proxy
puede terminar TLS, aplicar cabeceras de seguridad, centralizar logs web y
restringir que el puerto interno de Flask solo sea accesible desde el propio
servidor.

## 2. Autenticacion sin HTTPS

HTTP Basic Auth y el login por formulario no cifran la conexion por si solos.
Si el dashboard se sirve por HTTP, el contenido de la sesion, credenciales y
eventos viajan sin cifrado de transporte. Por eso:

- En laboratorio local puede usarse `127.0.0.1` o una red local controlada.
- Para un entorno real, usar HTTPS mediante reverse proxy.
- No publicar el dashboard directamente en internet.
- No exponer el puerto Flask interno fuera del servidor.

## 3. Recomendacion de arquitectura

Recomendacion general:

1. Mantener Gleipnir escuchando solo en `127.0.0.1:8080`.
2. Ejecutar Nginx o Caddy en el mismo servidor.
3. Terminar TLS en el reverse proxy.
4. Exponer solo el reverse proxy.
5. Mantener `DASHBOARD_AUTH_ENABLED=true`.
6. Usar `DASHBOARD_SESSION_COOKIE_SECURE=true` cuando el acceso sea por HTTPS.

Flujo recomendado:

```text
Navegador HTTPS -> Reverse proxy TLS -> http://127.0.0.1:8080 -> Gleipnir dashboard
```

Ejecutar el dashboard interno:

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

No usar `--host 0.0.0.0` para este escenario. El puerto interno del dashboard
debe quedar accesible solo desde el mismo equipo.

## 4. Ejemplo conceptual con Nginx

Este ejemplo es conceptual. Reemplazar placeholders por valores autorizados de
la organizacion. No incluye certificados reales ni dominios reales.

```nginx
server {
    listen 443 ssl http2;
    server_name <DOMINIO_INTERNO>;

    ssl_certificate     <RUTA_CERTIFICADO_TLS>;
    ssl_certificate_key <RUTA_LLAVE_TLS>;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Referrer-Policy no-referrer;
}
```

Notas:

- El reverse proxy escucha HTTPS.
- `proxy_pass` apunta al dashboard local en `127.0.0.1:8080`.
- Flask no se expone directamente.
- Las cabeceras ayudan a reducir riesgos comunes del navegador.
- La politica exacta de TLS y cabeceras debe definirse con el administrador de
  seguridad de la organizacion.

## 5. Ejemplo conceptual con Caddy

Este ejemplo tambien usa placeholders y no incluye dominios reales ni
credenciales.

```caddyfile
<DOMINIO_INTERNO> {
    reverse_proxy 127.0.0.1:8080

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
    }
}
```

Caddy puede administrar TLS segun su configuracion y el entorno donde se
despliegue. Validar siempre que el dominio, certificados y acceso sean
autorizados por la organizacion.

## 6. Configuracion recomendada de Gleipnir

En `.env`:

```env
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_SESSION_COOKIE_SECURE=true
DASHBOARD_SESSION_TIMEOUT_MINUTES=30
```

Usar usuarios y contrasenas propios del entorno, sin guardarlos en el
repositorio. No publicar `.env`, logs ni bases SQLite.

El dashboard tambien agrega cabeceras HTTP defensivas propias:

- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY`.
- `Referrer-Policy: no-referrer`.
- `Cache-Control: no-store` en rutas autenticadas/administrativas.
- CSP basica con `default-src 'self'`.

El reverse proxy puede agregar politicas adicionales de TLS y cabeceras segun
las reglas de la organizacion.

## 7. Uso en laboratorio local

Para demostracion academica o laboratorio controlado, puede mantenerse el
dashboard en:

```bash
gleipnir dashboard --host 127.0.0.1 --port 8080
```

Si se requiere acceso desde otra computadora de la misma red, usar
`--host 0.0.0.0 --allow-lan` solo en una red local/laboratorio autorizada y con
autenticacion activa. No se recomienda publicar el dashboard a internet.

Limitaciones conocidas:

- No hay MFA.
- No hay gestion avanzada de usuarios.
- No se implementa TLS dentro de Flask.
- El acceso sin HTTPS solo es aceptable en localhost o laboratorio controlado.
