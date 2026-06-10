# Capa opcional IPS/Firewall (nftables)

Gleipnir es, por defecto, un **IDS pasivo**: detecta, registra y alerta, pero
**no bloquea** tráfico. Esta capa **opcional** añade enforcement defensivo con
`nftables` para entornos de **red propia o laboratorio**. Está desactivada por
defecto y nunca aplica reglas reales sin configuración explícita.

> Uso responsable: aplica reglas únicamente en redes donde tengas autorización
> expresa. No uses esta capa para ataques, evasión, spoofing ni filtrado en
> redes ajenas.

## 1. IDS vs IPS en Gleipnir

| Aspecto | Modo IDS (por defecto) | Modo IPS/Firewall (opcional) |
|---|---|---|
| Acción | Observa, registra, alerta | Además puede bloquear |
| Tráfico | Nunca se modifica | Se puede `drop` con nftables |
| Activación | Siempre | `IPS_ENABLED=true` |
| Riesgo | Nulo sobre la red | Puede cortar conectividad si se configura mal |
| Permisos | Captura (sudo para live) | sudo/root para aplicar reglas |

El modo IDS sigue siendo el comportamiento predeterminado aunque actives la capa
IPS: la detección, los logs, las alertas por correo y el reporte forense no
cambian.

## 2. Dónde se guarda la configuración

La configuración se divide en dos:

- **`.env` (valores base, rutas y secretos):** solo el backend, la tabla/cadena
  y la ruta al archivo operativo. **El dashboard nunca edita `.env`.**

  ```env
  IPS_CONFIG_FILE=data/ips_config.json
  IPS_BACKEND=nftables
  IPS_TABLE=gleipnir
  IPS_CHAIN=gleipnir_filter
  ```

- **`data/ips_config.json` (configuración OPERATIVA editable):** lo que el usuario
  cambia desde la CLI o el dashboard. Se crea con valores seguros por defecto si
  no existe. No contiene secretos.

  ```json
  {
    "ips_enabled": false,
    "dry_run": true,
    "allowlist_policy": "monitor",
    "blacklist_policy": "block",
    "block_direction": "both",
    "blacklist_check_private": false,
    "auto_apply": false
  }
  ```

  Valores válidos: `ips_enabled`/`dry_run`/`blacklist_check_private`/`auto_apply`
  = `true|false`; `allowlist_policy` = `monitor|allow_registered|block_unregistered`;
  `blacklist_policy` = `monitor|block`; `block_direction` = `outbound|inbound|both`.

### Activar configuración ≠ aplicar reglas reales

- **Activar** (`ips enable`, cambiar políticas, etc.) solo edita
  `data/ips_config.json`. **No** toca nftables.
- **Aplicar** reglas reales requiere `ips_enabled=true`, `dry_run=false` y ejecutar
  `ips apply` con **sudo/root** (CAP_NET_ADMIN). `dry_run=true` es el valor
  recomendado para pruebas: solo simula.
- `auto_apply` (por defecto `false`) controla si el dashboard puede intentar
  aplicar reglas; aun así requiere permisos root del proceso.

## 3. Qué hace el modo dry-run

En dry-run, Gleipnir **construye** la tabla/cadena y las reglas nftables y las
**muestra**, pero **no ejecuta** ningún cambio. Los eventos de detección que en
modo real se bloquearían se registran con la acción `dry_run_block`, para que
puedas auditar exactamente qué haría el IPS antes de activarlo.

## 4. Seguridad del diseño nftables

- Gleipnir crea **solo su propia tabla** `table inet <IPS_TABLE>` y la cadena
  `<IPS_CHAIN>`.
- **Nunca** ejecuta `nft flush ruleset` ni toca reglas del sistema fuera de su
  tabla.
- `gleipnir ips remove` borra **únicamente** `table inet gleipnir`.
- Errores del backend (nft ausente, sin permisos, sintaxis) se registran y se
  devuelven como resultado estructurado; **no detienen el IDS**.
- La cadena se engancha en `hook forward` (escenario gateway/laboratorio).

## 5. Ejemplo de reglas generadas

Con whitelist `192.168.1.10 / aa:bb:cc:dd:ee:ff`, blacklist `8.8.8.8` y
`2001:db8::1`, `IPS_ALLOWLIST_POLICY=allow_registered`, `IPS_BLACKLIST_POLICY=block`,
`IPS_BLOCK_DIRECTION=both`:

```nft
table inet gleipnir {
    set gleipnir_blacklist_v4 {
        type ipv4_addr
        flags interval
        elements = { 8.8.8.8 }
    }
    set gleipnir_blacklist_v6 {
        type ipv6_addr
        flags interval
        elements = { 2001:db8::1 }
    }
    set gleipnir_allow_v4 {
        type ipv4_addr
        flags interval
        elements = { 192.168.1.10 }
    }
    set gleipnir_allow_mac {
        type ether_addr
        elements = { aa:bb:cc:dd:ee:ff }
    }
    chain gleipnir_filter {
        type filter hook forward priority 0; policy accept;
        ip daddr @gleipnir_blacklist_v4 drop
        ip saddr @gleipnir_blacklist_v4 drop
        ip6 daddr @gleipnir_blacklist_v6 drop
        ip6 saddr @gleipnir_blacklist_v6 drop
        ip saddr @gleipnir_allow_v4 accept
        ether saddr @gleipnir_allow_mac accept
    }
}
```

Con `IPS_ALLOWLIST_POLICY=block_unregistered` se añade además
`ip saddr != @gleipnir_allow_v4 drop` (solo si la allowlist tiene IPs; nunca se
emite un `drop` general que deje sin red al segmento).

## 6. Comandos

### Ver / aplicar / remover

```bash
gleipnir ips status            # estado, backend, dry-run, nft disponible
gleipnir ips dry-run           # reglas que se aplicarían (no modifica nada)
gleipnir ips rules             # ruleset nftables generado
sudo .venv/bin/gleipnir ips apply    # requiere ips_enabled=true, dry_run=false, root
sudo .venv/bin/gleipnir ips remove   # borra solo la tabla inet gleipnir
```

### Configurar (edita data/ips_config.json, no aplica reglas)

```bash
gleipnir ips config show
gleipnir ips config set --key allowlist_policy --value allow_registered
gleipnir ips enable
gleipnir ips disable
gleipnir ips dry-run-enable
gleipnir ips dry-run-disable
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

- `ips enable` muestra: *"IPS habilitado en configuración. Para aplicar reglas
  reales ejecuta: sudo .venv/bin/gleipnir ips apply"*.
- `ips apply` rechaza la ejecución si `ips_enabled=false` o `dry_run=true` y
  explica cómo cambiarlo.

### Dashboard (`/admin/ips`, solo rol admin)

La sección **IPS/Firewall** del dashboard permite ver el estado, cambiar la
configuración (con CSRF y auditoría), ejecutar dry-run y, si `auto_apply=true` y
el proceso tiene permisos root, aplicar/remover reglas. El dashboard:

- **No** edita `.env` (solo `data/ips_config.json`).
- **No** pide ni almacena contraseñas sudo.
- Si el proceso no tiene permisos, muestra: *"El dashboard no tiene permisos para
  aplicar reglas nftables. Usa sudo .venv/bin/gleipnir ips apply desde terminal."*

Se recomienda aplicar reglas reales desde la **CLI con sudo**, no desde el
dashboard.

## 7. Permitir tráfico si IP/MAC está registrada

- **Modo IDS**: un equipo registrado genera `AUTHORIZED_DEVICE` (solo monitoreo;
  no se permite ni bloquea activamente).
- **Modo IPS** con `IPS_ALLOWLIST_POLICY=allow_registered`: se generan reglas que
  **permiten** explícitamente las IPs autorizadas (y MAC en capa Ethernet si el
  backend lo soporta en el contexto).
- **Modo IPS** con `IPS_ALLOWLIST_POLICY=block_unregistered`: se **bloquea** el
  tráfico de IP/MAC no registradas, solo cuando el usuario lo activa
  explícitamente (`IPS_ENABLED=true`, `IPS_DRY_RUN=false`). Se registra el evento
  `IPS_BLOCKED_UNREGISTERED_DEVICE`.

### Limitación de MAC

El filtrado por MAC (`ether saddr`) solo es fiable en el mismo segmento
Ethernet/puente. En tráfico enrutado (L3) la MAC de origen es la del último
salto, no la del host original; por eso las reglas por **IP** son preferentes y
autoritativas. Además:

- **strict**: si la MAC no está disponible por el tipo de captura, **no** se
  bloquea automáticamente; solo se alerta.
- **ip_fallback**: se permite/bloquea con base en la IP si el usuario lo
  configuró.

## 8. Detección de IPs en blacklist (origen y destino)

La detección revisa **ip_destino** (saliente) **e ip_origen** (entrante):

| Caso | Evento direccional | Dirección |
|---|---|---|
| Interna → externa en blacklist | `BLACKLISTED_EXTERNAL_IP_OUTBOUND` | outbound |
| Externa en blacklist → interna | `BLACKLISTED_EXTERNAL_IP_INBOUND` | inbound |
| IP privada/local en blacklist (si `BLACKLIST_CHECK_PRIVATE=true`) | `BLACKLISTED_PRIVATE_IP` | local |

- Con `BLACKLIST_CHECK_PRIVATE=false` (por defecto) solo se revisan IPs globales
  (`is_global`). Nota: rangos de documentación como `203.0.113.0/24` **no** son
  globales; usa IPs públicas reales o activa `BLACKLIST_CHECK_PRIVATE=true` en
  laboratorio.
- Cuando el IPS bloquea una IP de blacklist se registra
  `IPS_BLOCKED_BLACKLISTED_IP`.

Cada evento incluye: `timestamp`, `ip_origen`, `ip_destino`, dirección
(`inbound`/`outbound`/`local`), protocolo, tipo de riesgo (Virus/Malware/Botnet…),
severidad y acción tomada (`detected`, `alerted`, `blocked`, `dry_run_block`).

## 9. Cómo demostrar el requisito

1. IP/MAC registrada → `AUTHORIZED_DEVICE` (IDS) / regla `accept` (IPS
   `allow_registered`).
2. IP/MAC no registrada → `UNAUTHORIZED_DEVICE` (IDS) / bloqueo opcional
   (`IPS_BLOCKED_UNREGISTERED_DEVICE` con `block_unregistered`).
3. IP en blacklist (origen o destino) → alerta de emergencia + evento
   direccional.
4. IP en blacklist con IPS activo → bloqueo opcional
   (`IPS_BLOCKED_BLACKLISTED_IP`).

## 9b. Ejemplo seguro de laboratorio

```bash
gleipnir ips config show          # ver configuración operativa actual
gleipnir ips enable               # ips_enabled=true (no aplica nada todavía)
gleipnir ips dry-run-enable       # dry_run=true (modo seguro)
gleipnir ips dry-run              # revisar las reglas que se aplicarían
gleipnir ips dry-run-disable      # dry_run=false (ahora apply puede aplicar)
sudo .venv/bin/gleipnir ips apply # aplicar reglas reales (requiere root)
sudo .venv/bin/gleipnir ips remove# limpiar solo la tabla de Gleipnir
```

## 9c. Cómo demostrar al profesor

1. Activar IPS desde CLI: `gleipnir ips enable`.
2. Ver el dry-run: `gleipnir ips dry-run`.
3. Cambiar políticas desde el dashboard en `/admin/ips` (rol admin).
4. Aplicar reglas reales desde CLI: `sudo .venv/bin/gleipnir ips apply`.
5. Remover reglas: `sudo .venv/bin/gleipnir ips remove`.
6. Mostrar evidencia: eventos `ADMIN_IPS_*` en el dashboard/SQLite y eventos
   `IPS_BLOCKED_*` en los reportes (`gleipnir report --type IPS_BLOCKED_BLACKLISTED_IP`).

## 10. Riesgos y limitaciones

- Un `block_unregistered` mal configurado puede cortar conectividad legítima;
  pruébalo siempre primero con `gleipnir ips dry-run`.
- El hook `forward` cubre tráfico enrutado (gateway/lab). Para filtrado del
  propio host se necesitarían hooks `input`/`output` (no implementado).
- La MAC no es fiable en L3 (ver §7).
- Requiere `nft` instalado y privilegios root para aplicar/remover reglas.
