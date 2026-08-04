# Network / WLAN / DNS

## Qué evidencias de red soporta la app

La familia `network` cubre evidencias locales de conectividad y configuración de red en Windows con un enfoque prudente:

- perfiles WLAN (`Wlansvc` XML)
- eventos `Microsoft-Windows-WLAN-AutoConfig/Operational` ya parseados por EVTX
- salidas Registry/RECmd relacionadas con `NetworkList` y `Tcpip\\Parameters\\Interfaces`
- fichero `hosts`
- DNS cache/config en CSV/JSON
- salidas `ipconfig`, `netsh wlan`, `netstat` y `arp` en TXT

No se interpreta un indicador aislado como prueba de actividad maliciosa. La prioridad es contextualizar conectividad, perfiles Wi-Fi, DNS/hosts y correlaciones con otras evidencias.

## Qué se parsea directamente desde Velociraptor

Discovery detecta y puede extraer selectivamente:

- `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/*/*.xml`
- `Windows/System32/drivers/etc/hosts`
- `*DNSCache*.csv/json`
- `*ipconfig*.txt`
- `*netsh*.txt`
- `*netstat*.txt`
- `*arp*.txt`
- salidas `NetAdapter`, `NetIPConfiguration`, `NetRoute`, `NetTCPConnection`, `NetUDPEndpoint` cuando existan

También detecta:

- `Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx` como `handled_by_evtx_parser`
- hives `SOFTWARE`, `SYSTEM` y `NTUSER.DAT` relacionados como candidatos `discovery_only` o `detected_not_implemented` si no hay parser raw

## Qué queda como discovery

Queda como discovery o dependencia de otro parser:

- WLAN EVTX raw si solo está el `.evtx` y no el CSV parseado
- hives raw `SOFTWARE` / `SYSTEM` / `NTUSER.DAT`
- inventario de red derivado de outputs genéricos no soportados todavía

Eso significa que la app preserva la evidencia y la muestra en la UI, pero no debe venderla como parseada si todavía no existe parser específico.

## WLAN profiles

El parser WLAN XML extrae:

- `SSID`
- nombre de perfil
- `connectionType`
- `connectionMode`
- autenticación
- cifrado
- tipo de clave
- si existe `keyMaterial`
- hints de randomización MAC

Los perfiles WLAN se normalizan como:

- `artifact.type = network`
- `event.type = wlan_profile`
- `event.action = wlan_profile_observed`

### Qué significan SSID / auth / encryption / keyMaterial

- `SSID`: nombre de la red Wi-Fi observada en el perfil
- `authentication`: tipo de autenticación, por ejemplo `WPA2PSK`, `open`
- `encryption`: cifrado, por ejemplo `AES`, `TKIP`, `none`
- `keyMaterial`: indica que el perfil contenía material de clave

### Por qué no se muestran claves Wi-Fi en claro

Si aparece `keyMaterial`, la app:

- marca `wlan.key_material_present = true`
- añade `wlan_key_material_present`
- redacta el valor (`[REDACTED]`)
- no lo mete en `search_text`
- no lo resume en `raw_summary`

Esto evita filtrar secretos en búsquedas, timeline o paneles de detalle.

## NetworkList / TCPIP registry

Las claves de `NetworkList` aportan:

- nombres de perfiles de red
- GUIDs
- categoría de red
- timestamps de `last_write` útiles como contexto

Las claves de `Tcpip\\Parameters\\Interfaces` aportan:

- IPs
- gateways
- DNS servers
- DHCP
- dominio/sufijo si existe

La app lo normaliza como:

- `network_profile`
- `interface_config`
- `dns_config`

pero sigue preservando `registry.*` para que el analista vea la clave y el valor originales.

## DNS cache / config

El parser DNS soporta CSV/JSON genéricos con campos tipo:

- `Name`
- `Domain`
- `Type`
- `Data`
- `IPAddress`
- `TTL`
- `Server`
- `Interface`

Esto sirve para responder:

- qué dominios o entradas DNS fueron observadas
- qué servidor DNS estaba configurado
- si el indicador coincide con Browser, BITS, PowerShell, Defender o Cloud

### Limitaciones de DNS

- la cache DNS puede no existir tras reboot
- el formato depende mucho de la fuente
- un dominio observado no implica por sí solo navegación o malware

## Hosts file

El parser:

- ignora comentarios y líneas vacías
- soporta múltiples hostnames por línea
- crea eventos `hosts_entry`

Qué buscar:

- redirecciones a `127.0.0.1` o `0.0.0.0`
- dominios de Microsoft, Defender, cloud o seguridad redirigidos
- overrides no comentados y no estándar

Una entrada en `hosts` no es automáticamente maliciosa, pero gana mucho valor si correlaciona con Browser, Defender, BITS o cambios de archivo en MFT.

## ipconfig / netsh / netstat / arp

### `ipconfig /all`

Permite extraer:

- nombre de interfaz
- descripción
- MAC
- IPv4 / IPv6
- gateway
- DNS servers
- DHCP server

### `netsh wlan`

Permite extraer:

- perfiles Wi-Fi
- nombres de perfil
- hints de SSID
- autenticación/cifrado si el output lo incluye

### `netstat`

Permite extraer:

- protocolo
- local address / port
- foreign address / port
- estado
- PID si existe

### `arp`

Permite extraer:

- interfaz
- IP
- MAC
- tipo

Estos outputs son especialmente útiles en live response, pero también son volátiles: describen un estado observado en el momento de la captura.

## Diferencia entre indicador observado y actividad maliciosa

La app diferencia entre:

- `network profile observed`
- `wlan profile observed`
- `wlan connection observed`
- `dns configuration observed`
- `hosts entry observed`
- `possible suspicious network configuration`
- `suspicious network activity candidate`

No afirma C2, spoofing, intrusión ni uso malicioso solo por ver:

- un SSID
- un DNS público
- una entrada normal en `hosts`
- un dominio observado en cache DNS

## Cómo correlaciona con otras evidencias

### Browser

- dominio DNS o `hosts` que coincide con histórico web
- override de `hosts` que afecta un dominio visitado

### BITS

- dominio o IP remota de BITS que coincide con DNS
- descarga cercana a WLAN connection o cambio de red

### PowerShell

- URLs, dominios o IPs de comandos que coinciden con DNS / netstat
- descargas o conexiones a IP directa

### Defender

- dominios, recursos o paths relacionados con indicadores de red observados

### Cloud Sync

- dominios cloud como `onedrive.live.com`, `drive.google.com`, `dropbox.com`, `mega.nz`, `icloud.com`, `box.com`
- actividad cloud cercana a indicadores WLAN o DNS

### SRUM

- bytes enviados/recibidos por aplicación cercanos a Browser, BITS o Cloud

### EVTX

- actividad WLAN o de procesos cerca de otros eventos sospechosos

### MFT / USN

- cambios en `hosts`
- modificación de artefactos de red o outputs exportados

## Falsos positivos comunes

- perfiles WLAN corporativos o de hoteles
- DNS públicos (`8.8.8.8`, `1.1.1.1`) usados legítimamente
- entradas de `hosts` para desarrollo local
- outputs `netstat` con software de administración o seguridad
- dominios cloud normales observados por Browser o sync clients

## Limitaciones

- la cache DNS puede no existir o ser incompleta
- un perfil WLAN no prueba conexión reciente
- `hosts` necesita timestamp y correlación para tener peso alto
- `netstat` y `arp` son especialmente volátiles si vienen de live response
- BSSID, señal y razón de conexión no siempre estarán presentes
- la app no debe inferir credenciales Wi-Fi ni mostrarlas en claro

## Ejemplos de investigación

### 1. Override en `hosts` y navegación afectada

1. Ver un `hosts_entry` sospechoso para dominio de Microsoft o seguridad.
2. Correlacionar con Browser para comprobar si ese dominio fue visitado.
3. Revisar MFT/USN para saber cuándo cambió el fichero `hosts`.

### 2. WLAN abierta cerca de actividad sospechosa

1. Ver un `wlan_profile` con autenticación `open`.
2. Revisar `wlan_connection` cercanas en EVTX.
3. Correlacionar con Browser, BITS o PowerShell en la misma ventana temporal.

### 3. DNS / netstat y PowerShell

1. Observar dominio o IP directa en DNS o `netstat`.
2. Buscar el mismo indicador en PowerShell y BITS.
3. Si además aparece en Defender o SRUM, tratarlo como correlación fuerte, no como indicador aislado.
