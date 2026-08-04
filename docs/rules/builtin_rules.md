# Reglas builtin

## Qué son en esta plataforma

En Kairon DFIR hay dos conceptos distintos:

1. **Rules** almacenadas o importadas:
   - heuristic
   - sigma
   - yara

2. **Builtin detections**:
   - señales automáticas generadas por código a partir de tags y severidad de eventos normalizados

Este documento se centra en las **builtin detections** actuales.

## Estado por defecto

Las builtin detections están **activadas por defecto** si el ajuste de runtime:

```text
AUTO_CREATE_HEURISTIC_DETECTIONS = true
```

## Cómo desactivarlas

### Desactivar todas

Pon el ajuste runtime:

```text
AUTO_CREATE_HEURISTIC_DETECTIONS = false
```

### Desactivar builtin concretas

Edita:

```text
backend/app/rules/builtin_detection_overrides.yaml
```

Ejemplo:

```yaml
disabled_rules:
  - suspicious_command_line
  - rdp_activity
```

Después reinicia backend y worker para que el cambio quede aplicado.

## Tabla resumen

| Regla builtin | Severidad | Qué busca | Evidencia | Activada por defecto |
| --- | --- | --- | --- | --- |
| Suspicious command line | hereda del evento | Eventos con tag `suspicious_command` | EVTX y cualquier evento normalizado con tag sospechoso | Sí |
| Service installation | hereda del evento | Tags `persistence` + `service_install` | 4697 / 7045 y similares | Sí |
| Scheduled task persistence | hereda del evento | Tags `scheduled_task` + `persistence` | 4698 / 4702 / TaskScheduler | Sí |
| Scheduled Task PowerShell Encoded | hereda del evento | tareas con PowerShell encoded | XML/CSV de Task Scheduler | Sí |
| Scheduled Task Runs From AppData | hereda del evento | tareas que ejecutan desde AppData | XML/CSV de Task Scheduler | Sí |
| Scheduled Task Runs From Temp | hereda del evento | tareas que ejecutan desde Temp | XML/CSV de Task Scheduler | Sí |
| Scheduled Task Hidden And Enabled | hereda del evento | tareas ocultas, habilitadas y sospechosas | XML/CSV de Task Scheduler | Sí |
| Scheduled Task LOLBin | hereda del evento | tareas con LOLBins | XML/CSV de Task Scheduler | Sí |
| Scheduled Task UNC Path | hereda del evento | tareas que ejecutan desde UNC | XML/CSV de Task Scheduler | Sí |
| Scheduled Task COM Handler | hereda del evento | tareas con acción COM handler | XML raw de Task Scheduler | Sí |
| Downloaded File Persisted As Scheduled Task | hereda del evento | descarga correlacionada con tarea persistente | Browser + Scheduled Tasks | Sí |
| PowerShell Encoded Command | hereda del evento | comandos PowerShell con `EncodedCommand` | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Download Cradle | hereda del evento | `Invoke-WebRequest`, `DownloadString`, `WebClient`, `Start-BitsTransfer` | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Invoke-Expression | hereda del evento | `IEX` o `Invoke-Expression` | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell ExecutionPolicy Bypass | hereda del evento | `-ExecutionPolicy Bypass` | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Defender Tampering | hereda del evento | `Set-MpPreference` / `Add-MpPreference` / exclusiones | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Scheduled Task Persistence | hereda del evento | creación de tareas desde PowerShell | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Run Key Persistence | hereda del evento | `reg add` o Run Key persistence desde PowerShell | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Credential Access Keywords | hereda del evento | `lsass`, `mimikatz`, `sekurlsa`, `procdump` | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Download From Raw IP | hereda del evento | descargas hacia IP directa | PSReadLine / transcripts / scripts observados | Sí |
| PowerShell Script In User Writable Path | hereda del evento | scripts observados o ejecutados desde AppData/Temp/Downloads/Public | PowerShell + filesystem | Sí |
| Recycle Bin Executable Deleted | hereda del evento | ejecutables enviados a la papelera | RBCmd / `$I` raw | Sí |
| Recycle Bin Script Deleted | hereda del evento | scripts enviados a la papelera | RBCmd / `$I` raw | Sí |
| Recycle Bin Deleted Download | hereda del evento | descarga correlacionada con papelera | Browser + Recycle Bin | Sí |
| Recycle Bin Deleted Defender Detection | hereda del evento | archivo detectado por Defender y luego reciclado | Defender + Recycle Bin | Sí |
| Recycle Bin Double Extension Deleted | hereda del evento | doble extensión sospechosa reciclada | RBCmd / `$I` raw | Sí |
| Recycle Bin Content Missing | hereda del evento | `$I` presente sin `$R` | Recycle Bin raw | Sí |
| Recycle Bin Suspicious Tool Deleted | hereda del evento | tool/payload sensible reciclado | RBCmd / `$I` raw | Sí |
| Recycle Bin Deleted File In User Writable Path | hereda del evento | archivo reciclado desde ruta sensible | RBCmd / `$I` raw | Sí |
| Shellbag Network Share Accessed | hereda del evento | Shellbags con rutas UNC/share | SBECmd | Sí |
| Shellbag USB Folder Accessed | hereda del evento | Shellbags con rutas USB/removable | SBECmd | Sí |
| Shellbag Suspicious Tool Folder | hereda del evento | Shellbags en carpetas de tooling/payload | SBECmd | Sí |
| Shellbag Cloud Sync Folder | hereda del evento | Shellbags en OneDrive/Dropbox/Google Drive/Mega | SBECmd | Sí |
| Shellbag User Writable Suspicious Path | hereda del evento | Shellbags en AppData/Temp/Downloads con indicadores sospechosos | SBECmd | Sí |
| Shellbag Deleted Or Missing Folder Candidate | hereda del evento | Shellbags que parecen apuntar a carpetas ya no presentes | SBECmd | Sí |
| Shellbag Folder Related To Deleted Download | hereda del evento | correlación carpeta Shellbag + descarga luego borrada | Shellbags + Browser + Recycle Bin | Sí |
| JumpList Downloaded File Opened | hereda del evento | archivo descargado que luego aparece en JumpLists | JLECmd + Browser | Sí |
| JumpList Deleted File Was Opened | hereda del evento | archivo reciente en JumpLists que después se borra o recicla | JLECmd + Recycle Bin/MFT | Sí |
| JumpList Executable In User Writable Path | hereda del evento | ejecutable reciente en Downloads/AppData/Temp/Desktop; la ruta escribible por usuario sola no dispara la regla | JLECmd / raw automaticDestinations | Sí |
| JumpList Script In User Writable Path | hereda del evento | script reciente en rutas de usuario sensibles; la ruta sola no basta | JLECmd / raw automaticDestinations | Sí |
| JumpList Double Extension | hereda del evento | item reciente con doble extensión sospechosa | JLECmd | Sí |
| JumpList Network Share Accessed | hereda del evento | item reciente en share UNC o red | JLECmd | Sí |
| JumpList USB Item Accessed | hereda del evento | item reciente en medio removible/USB | JLECmd | Sí |
| JumpList Suspicious Tool Item | hereda del evento | nombres de tooling/payload/credenciales en JumpLists | JLECmd | Sí |
| JumpList Suspicious Command Arguments | hereda del evento | argumentos asociados con PowerShell encoded/bypass/mshta/etc | JLECmd | Sí |
| Suspicious Run Key Command | hereda del evento | Run keys sospechosas o con PowerShell/LOLBins | RECmd `registry_run_key` | Sí |
| Service ImagePath in suspicious path | hereda del evento | Servicios registry con ImagePath/ServiceDll sospechosos | RECmd `registry_service` | Sí |
| RunMRU Suspicious Command | hereda del evento | Comandos sospechosos en `RunMRU` | RECmd `run_mru_command` | Sí |
| RDP MRU Entry | hereda del evento | Historial de destinos RDP | RECmd `rdp_mru` | Sí |
| USB Device Seen | hereda del evento | Dispositivos USB y mappings de volumen | RECmd `usb_device_seen` / `mounted_device` | Sí |
| USB Storage Device Observed | hereda del evento | Dispositivo USB de almacenamiento con metadata suficiente | SetupAPI / USBSTOR / MountedDevices | Sí |
| Executable Accessed From USB | hereda del evento | ejecutable o DLL observado en ruta removible | LNK / JumpLists / MFT / PowerShell | Sí |
| Script Accessed From USB | hereda del evento | script observado en ruta removible | LNK / JumpLists / PowerShell / MFT | Sí |
| Browser Download To USB | hereda del evento | descarga directa hacia unidad externa | Browser + USB correlation | Sí |
| PowerShell Copy To USB | hereda del evento | copia o movimiento hacia unidad externa | PowerShell + USB correlation | Sí |
| Suspicious Tool On USB | hereda del evento | tooling sensible observado en ruta USB | LNK / JumpLists / filesystem | Sí |
| Possible USB Exfiltration Candidate | hereda del evento | hipótesis de copia/salida a USB por señales convergentes | Correlación USB + file activity | Sí |
| Deleted File From USB | hereda del evento | archivo borrado o reciclado desde unidad removible | Recycle Bin / MFT + USB | Sí |
| Network/Cloud To USB Correlation | hereda del evento | ruta de red/cloud relacionada con USB | Correlación multi-artefacto | Sí |
| Multiple File Creations On USB | hereda del evento | ráfaga de creaciones/modificaciones en USB | MFT/USN + USB | Sí |
| BITS Download Executable To User Writable Path | hereda del evento | ejecutable/DLL descargado por BITS a AppData, Temp, ProgramData o rutas similares | BITS CSV/JSON/TXT | Sí |
| BITS Download Script To Temp | hereda del evento | script descargado por BITS a Temp o ruta muy sensible | BITS CSV/JSON/TXT | Sí |
| BITS Notify Command Persistence | hereda del evento | job BITS con notify command o callback | BITS CSV/JSON/TXT | Sí |
| BITS Direct IP Download | hereda del evento | URL remota BITS que usa IP directa | BITS CSV/JSON/TXT | Sí |
| BITS Cleartext HTTP Executable | hereda del evento | descarga BITS por HTTP claro de ejecutable o script | BITS CSV/JSON/TXT | Sí |
| BITS Download Then Execute | hereda del evento | archivo descargado por BITS que luego se ejecuta | BITS + Prefetch/EVTX | Sí |
| BITS Download Detected By Defender | hereda del evento | archivo descargado por BITS que luego detecta Defender | BITS + Defender | Sí |
| Suspended Or Stale BITS Job | hereda del evento | job BITS suspendido, en error o estancado | BITS CSV/JSON/TXT | Sí |
| PowerShell Created BITS Job | hereda del evento | correlación Start-BitsTransfer o bitsadmin con job BITS | PowerShell + BITS | Sí |
| Non-Microsoft BITS Job With Suspicious Extension | hereda del evento | job no claramente Microsoft que baja `.exe`, `.ps1`, `.zip`, etc. | BITS CSV/JSON/TXT | Sí |
| UserAssist LOLBin Execution | hereda del evento | UserAssist apuntando a LOLBins | RECmd `userassist_execution` | Sí |
| BAM Execution from Suspicious Path | hereda del evento | BAM/DAM desde rutas de usuario sospechosas | RECmd `bam_execution` / `dam_execution` | Sí |
| Registry Persistence via UNC Path | hereda del evento | Persistencia registry apuntando a UNC | RECmd run keys/services | Sí |
| Alternate Data Stream Detected | hereda del evento | ADS observados en `$MFT` | MFTECmd `alternate_data_stream` | Sí |
| Double Extension File | hereda del evento | ficheros tipo `report.pdf.exe` | MFTECmd / USN | Sí |
| Deleted Executable Candidate | hereda del evento | ejecutables/scripts con `InUse = false` | MFTECmd `file_deleted_or_not_in_use` | Sí |
| Executable in Downloads | hereda del evento | ejecutables/scripts en Downloads, AppData o Temp | MFTECmd / USN | Sí |
| Possible Timestomping SI/FN Mismatch | hereda del evento | diferencias amplias entre timestamps `$SI` y `$FN` | MFTECmd | Sí |
| Executable Downloaded | hereda del evento | descargas de ejecutables o instaladores | Browser download | Sí |
| Script Downloaded | hereda del evento | descargas `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` | Browser download | Sí |
| Archive Downloaded From File Sharing | hereda del evento | ZIP/RAR/7z desde sharing o cloud storage | Browser download | Sí |
| Download From Raw IP | hereda del evento | descargas desde IP directa | Browser download | Sí |
| Double Extension Download | hereda del evento | descargas tipo `invoice.pdf.exe` | Browser download | Sí |
| Downloaded File Later Executed | hereda del evento | correlación descarga -> ejecución | Browser + MFT/Prefetch/EVTX | Sí |
| Browser Visit To Paste Site | hereda del evento | visitas a paste sites | Browser history | Sí |
| Browser Visit To Remote Access Tool | hereda del evento | visitas a AnyDesk/TeamViewer/etc. | Browser history | Sí |
| Browser Download To Suspicious Path | hereda del evento | descargas a AppData/Temp/Desktop/Public | Browser download | Sí |
| Browser Download Detected By Defender | hereda del evento | correlación descarga -> Defender | Browser + Defender | Sí |
| Possible exfiltration tool | hereda del evento | Tag `possible_exfiltration` | Procesos o PowerShell sospechoso | Sí |
| RDP activity | hereda del evento | Tag `rdp` | 4624 tipo 10, 1149, 21/24/25, 4778/4779 | Sí |
| Lateral movement candidate | hereda del evento | Tag `lateral_movement_candidate` | Eventos remotos sospechosos | Sí |
| High-risk event | high/critical | Cualquier evento con severidad `high` o `critical` | Eventos normalizados | Sí |

## Detalle de cada builtin

### 1. Suspicious command line

- **ID interno**: `suspicious_command_line`
- **Severidad**: hereda `event.severity`
- **Qué busca**: cualquier evento que ya haya sido etiquetado como `suspicious_command`
- **Por qué es relevante**: suele capturar PowerShell encoded, download cradles, LOLBins o comandos muy agresivos
- **Qué evidencias usa**: sobre todo EVTX 4688 y 4104, aunque no está limitado a EVTX
- **Campos consultados**:
  - `tags`
  - `process.command_line`
  - `powershell.script_block_text`
  - `event.severity`
- **Ejemplo de match**: `powershell.exe -enc ...`
- **Posibles falsos positivos**: administración legítima, scripting defensivo o automatizaciones corporativas
- **Cómo investigarlo**: revisar command line, usuario, host, proceso padre y momento de ejecución

### 2. Service installation

- **ID interno**: `service_installation`
- **Severidad**: hereda `event.severity`
- **Qué busca**: creación de servicios con tags de persistencia
- **Qué evidencias usa**: EVTX 4697 y 7045
- **Campos consultados**:
  - `tags`
  - `service.name`
  - `service.image_path`
- **Ejemplo de match**: servicio nuevo apuntando a `C:\\Users\\...\\AppData\\...`
- **Posibles falsos positivos**: instaladores legítimos, agentes EDR, herramientas de soporte
- **Cómo investigarlo**: revisar image path, cuenta, start type y si el binario existe

### 3. Scheduled task persistence

- **ID interno**: `scheduled_task_persistence`
- **Severidad**: hereda `event.severity`
- **Qué busca**: creación o modificación de tareas con tags de persistencia
- **Qué evidencias usa**: EVTX 4698, 4702, TaskScheduler 106/140/141/200/201/129
- **Campos consultados**:
  - `task.name`
  - `task.command`
  - `task.arguments`
  - `tags`
- **Ejemplo de match**: tarea que ejecuta `powershell.exe` desde ruta de usuario
- **Posibles falsos positivos**: tareas legítimas de software o administración
- **Cómo investigarlo**: revisar nombre, comando, usuario, frecuencia y contenido XML

### Scheduled Tasks adicionales

- `scheduled_task_powershell_encoded`: tareas con `PowerShell` y `-EncodedCommand`
- `scheduled_task_runs_from_appdata`: acciones que apuntan a `AppData`
- `scheduled_task_runs_from_temp`: acciones que apuntan a `Temp`
- `scheduled_task_hidden_and_enabled`: `Hidden=true` y `Enabled=true` con rasgos sospechosos
- `scheduled_task_lolbin`: uso de `mshta`, `regsvr32`, `wscript`, `cscript`, `certutil`, `bitsadmin`, etc.
- `scheduled_task_unc_path`: acción apuntando a `\\host\share\...`
- `scheduled_task_com_handler`: tareas `ComHandler` observadas
- `downloaded_file_persisted_as_scheduled_task`: correlación entre Browser download y acción de la tarea

### PowerShell adicionales

- `powershell_encoded_command`: uso de `-EncodedCommand`
- `powershell_download_cradle`: descarga o cradle vía `Invoke-WebRequest`, `DownloadString`, `WebClient` o `Start-BitsTransfer`
- `powershell_invoke_expression`: `IEX` / `Invoke-Expression`
- `powershell_execution_policy_bypass`: `ExecutionPolicy Bypass`
- `powershell_defender_tampering`: exclusiones o cambios peligrosos de Defender
- `powershell_scheduled_task_persistence`: creación o registro de tareas
- `powershell_run_key_persistence`: persistencia en Run Keys
- `powershell_credential_access_keywords`: referencias a `LSASS`, `mimikatz`, `sekurlsa`, `procdump`, `comsvcs.dll`
- `powershell_download_from_raw_ip`: URL directa a IP
- `powershell_script_in_user_writable_path`: script observado en rutas de usuario sospechosas

### Recycle Bin adicionales

- `recycle_bin_executable_deleted`: ejecutable enviado a la papelera
- `recycle_bin_script_deleted`: script enviado a la papelera
- `recycle_bin_deleted_download`: archivo descargado y luego reciclado
- `recycle_bin_deleted_defender_detection`: archivo detectado por Defender y luego reciclado
- `recycle_bin_double_extension_deleted`: doble extensión sospechosa reciclada
- `recycle_bin_content_missing`: metadata `$I` presente sin `$R`
- `recycle_bin_suspicious_tool_deleted`: herramienta/payload sensible reciclado
- `recycle_bin_deleted_file_in_user_writable_path`: archivo reciclado desde Downloads, Desktop, Temp, AppData, Public o ProgramData

### Shellbags adicionales

- `shellbag_network_share_accessed`: carpeta UNC o share observada en Shellbags
- `shellbag_usb_folder_accessed`: carpeta en volumen removible/USB observada
- `shellbag_suspicious_tool_folder`: carpeta con nombres tipo `mimikatz`, `rclone`, `payload`, `credentials`, `dump`
- `shellbag_cloud_sync_folder`: carpeta de OneDrive, Dropbox, Google Drive, Box, Mega o Nextcloud
- `shellbag_user_writable_suspicious_path`: carpeta en AppData, Temp, Downloads o similar con rasgos sospechosos
- `shellbag_deleted_or_missing_folder_candidate`: Shellbag que parece apuntar a carpeta borrada o no presente
- `shellbag_folder_related_to_deleted_download`: carpeta Shellbag que correlaciona con una descarga luego reciclada o borrada

### USB adicionales

- `usb_storage_device_observed`: dispositivo USB de almacenamiento con serial/vendor/product o volumen útil
- `usb_executable_accessed`: ejecutable o DLL observado en ruta removible
- `usb_script_accessed`: script observado en ruta removible
- `browser_download_to_usb`: descarga directa a unidad externa
- `powershell_copy_to_usb`: comando de copia/movimiento/compresión hacia USB
- `usb_suspicious_tool_observed`: tooling sensible en almacenamiento removible
- `possible_usb_exfiltration_candidate`: hipótesis de salida de datos a USB
- `deleted_file_from_usb`: archivo borrado o reciclado desde unidad removible
- `network_or_cloud_to_usb_correlation`: actividad de red/cloud relacionada con actividad USB
- `multiple_file_creations_on_usb`: ráfaga de cambios en la unidad removible

### WMI adicionales

- `wmi_persistence_chain_detected`: cadena WMI de filter + consumer + binding
- `wmi_command_line_event_consumer_suspicious_command`: consumer WMI con PowerShell, LOLBins o comandos sensibles
- `wmi_active_script_event_consumer`: ActiveScriptEventConsumer con script
- `wmi_encoded_powershell_consumer`: PowerShell encoded dentro del consumer
- `wmi_download_command`: consumer WMI que descarga contenido remoto
- `wmi_registry_trigger`: query WQL basada en `RegistryValueChangeEvent`
- `wmi_process_start_trigger`: query WQL basada en `Win32_ProcessStartTrace` o eventos similares
- `wmi_consumer_references_user_writable_path`: consumer que apunta a AppData, Temp, ProgramData o Public
- `wmi_consumer_payload_executed`: payload WMI con correlación de ejecución
- `wmi_consumer_payload_detected_by_defender`: payload WMI correlacionado con Defender

### Autoruns / ASEP adicionales

- `autorun_from_user_writable_path`: entrada ASEP apuntando a AppData, Temp, ProgramData o rutas de usuario
- `unsigned_autorun_in_persistence_location`: persistencia unsigned o unverified
- `autorun_uses_lolbin`: ASEP que usa PowerShell, rundll32, regsvr32, mshta, wscript u otros LOLBins
- `autorun_encoded_powershell`: PowerShell encoded dentro del ASEP
- `autorun_download_command`: ASEP que descarga contenido remoto o referencia rutas UNC
- `ifeo_debugger_persistence`: persistencia por IFEO Debugger
- `winlogon_shell_userinit_modified`: Shell/Userinit modificado
- `appinit_appcert_dll_persistence`: persistencia por AppInit/AppCert DLLs
- `service_or_driver_from_user_writable_path`: servicio o driver fuera de rutas estándar
- `startup_folder_suspicious_executable`: ejecutable o script sospechoso en Startup folder
- `autorun_target_detected_by_defender`: target ASEP correlacionado con Defender
- `autorun_target_executed`: target ASEP ejecutado después
- `downloaded_then_persisted`: cadena descarga -> persistencia

### Network / WLAN / DNS adicionales

- `hosts_file_redirects_security_domain`: `hosts` redirige un dominio de Microsoft, Defender, seguridad o vendor crítico
- `suspicious_hosts_file_entry`: override en `hosts` que merece revisión aunque no sea automáticamente high confidence
- `open_wifi_profile_observed`: perfil WLAN con autenticación abierta o cifrado ausente
- `suspicious_dns_server_configuration`: configuración DNS poco habitual o con señales de riesgo
- `powershell_network_indicator_correlated_with_dns`: URL, dominio o IP de PowerShell correlacionado con DNS u otros indicadores de red
- `bits_domain_correlated_with_dns`: dominio BITS observado también en DNS o actividad de red relacionada
- `browser_domain_affected_by_hosts_override`: Browser accede a un dominio afectado por override local en `hosts`
- `direct_ip_network_connection_by_suspicious_process`: conexión `netstat` a IP directa con proceso sospechoso cuando el output lo permite
- `cloud_provider_network_activity`: actividad de red relacionada con proveedores cloud observados
- `wlan_connection_near_suspicious_activity`: conexión o cambio WLAN próximo a otra actividad de mayor riesgo

### 4. Possible exfiltration tool

- **ID interno**: `possible_exfiltration_tool`
- **Qué busca**: tags `possible_exfiltration`
- **Qué evidencias usa**: procesos o PowerShell con herramientas de copia/sincronización
- **Campos consultados**:
  - `tags`
  - `process.path`
  - `process.command_line`
  - `network.destination_ip`
- **Ejemplo de match**: uso de `rclone`, `bitsadmin` o utilidades equivalentes
- **Falsos positivos**: backup legítimo
- **Investigación**: validar destino, tamaño de datos y contexto operativo

### 4b. Suspicious Run Key Command

- **ID interno**: `suspicious_run_key_command`
- **Qué busca**: `registry_run_key` con comandos sospechosos, PowerShell encoded o LOLBins
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: revisar `process.command_line`, `registry.key_path`, usuario y correlación con `4688` o Prefetch

### 4c. Service ImagePath in suspicious path

- **ID interno**: `service_imagepath_suspicious`
- **Qué busca**: `registry_service` con `ImagePath` o `ServiceDll` en rutas sospechosas
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: revisar `service.image_path`, `service.service_dll`, `Start`, `ObjectName` y correlación con `7045` / `4697`

### 4d. RunMRU Suspicious Command

- **ID interno**: `run_mru_suspicious_command`
- **Qué busca**: comandos sospechosos lanzados desde el cuadro Ejecutar
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: correlacionar con `4688`, PowerShell, Prefetch y contexto del usuario

### 4e. RDP MRU Entry

- **ID interno**: `rdp_mru_entry`
- **Qué busca**: historial de destinos RDP del cliente
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: validar destino, usuario y si hubo logon RDP real en EVTX

### 4f. USB Device Seen

- **ID interno**: `usb_device_seen`
- **Qué busca**: presencia de USBSTOR y MountedDevices
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: revisar vendor/product/serial y correlacionar con LNK, Jump Lists y timeline

### 4g. UserAssist LOLBin Execution

- **ID interno**: `userassist_lolbin_execution`
- **Qué busca**: UserAssist de PowerShell, cmd, regsvr32 y otros LOLBins
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: correlacionar con BAM, Prefetch y EVTX 4688

### 4h. BAM Execution from Suspicious Path

- **ID interno**: `bam_execution_suspicious_path`
- **Qué busca**: BAM/DAM en AppData, Temp, Downloads u otras rutas de usuario
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: revisar ruta, binario y si existe rastro de ejecución real adicional

### 4i. Registry Persistence via UNC Path

- **ID interno**: `registry_persistence_unc_path`
- **Qué busca**: persistencia que carga binarios o DLLs desde `\\server\share\...`
- **Qué evidencias usa**: RECmd
- **Cómo investigarlo**: validar share remoto, accesibilidad y correlación con actividad de red

### 4j. Alternate Data Stream Detected

- **ID interno**: `alternate_data_stream_detected`
- **Qué busca**: archivos con ADS observados en MFTECmd
- **Qué evidencias usa**: MFT
- **Cómo investigarlo**: revisar `file.path`, `file.ads`, si existe `Zone.Identifier` y correlación con descargas o ejecución

### 4k. Double Extension File

- **ID interno**: `double_extension_file`
- **Qué busca**: nombres como `invoice.pdf.exe`
- **Qué evidencias usa**: MFT / USN
- **Cómo investigarlo**: validar origen, usuario, ruta y si se abrió o ejecutó

### 4l. Deleted Executable Candidate

- **ID interno**: `deleted_executable_candidate`
- **Qué busca**: scripts o ejecutables con `InUse = false`
- **Qué evidencias usa**: MFT
- **Cómo investigarlo**: correlacionar con USN, Prefetch, EVTX 4688 y LNK/Jump Lists

### 4m. Executable in Downloads

- **ID interno**: `executable_in_downloads`
- **Qué busca**: ejecutables o scripts en rutas de usuario sospechosas
- **Qué evidencias usa**: MFT / USN
- **Cómo investigarlo**: revisar si el archivo se ejecutó, si tiene ADS y si aparece en Registry o Defender

### 4n. Possible Timestomping SI/FN Mismatch

- **ID interno**: `possible_timestomping_si_fn_mismatch`
- **Qué busca**: discrepancias amplias entre `$SI` y `$FN`
- **Qué evidencias usa**: MFT
- **Cómo investigarlo**: comparar timestamps, revisar contexto del archivo y no tratarlo como prueba concluyente por sí solo

### 5. RDP activity

- **ID interno**: `rdp_activity`
- **Qué busca**: eventos con tag `rdp`
- **Qué evidencias usa**: 4624 LogonType 10, 1149, 21/24/25, 4778/4779
- **Campos consultados**:
  - `tags`
  - `source.ip`
  - `user.name`
  - `windows.logon_type`
- **Ejemplo de match**: autenticación RDP exitosa desde IP remota
- **Falsos positivos**: soporte remoto o administración legítima
- **Investigación**: revisar origen, horario, usuario y host destino

### 6. Lateral movement candidate

- **ID interno**: `lateral_movement_candidate`
- **Qué busca**: tags `lateral_movement_candidate`
- **Qué evidencias usa**: eventos remotos, servicios, autenticación o tooling lateral
- **Campos consultados**:
  - `tags`
  - `process.command_line`
  - `service.image_path`
  - `source.ip`
- **Investigación**: correlacionar con RDP, SMB, servicios y credenciales

### 7. High-risk event

- **ID interno**: `high_risk_event`
- **Qué busca**: eventos con severidad `high` o `critical`
- **Qué evidencias usa**: cualquiera
- **Campos consultados**:
  - `event.severity`
  - `event.type`
  - `event.message`
  - `tags`
- **Cómo investigarlo**: abrir el evento y revisar el motivo de la severidad

## Limitaciones actuales

- No existe todavía un gestor visual para desactivar builtin una a una.
- La desactivación individual es por archivo YAML en backend.
- La lógica builtin depende de tags y severidad ya calculados por parsers/normalizadores.

## Execution artifacts

### Amcache Executable In Downloads

- **ID interno**: `amcache_executable_in_downloads`
- **Qué busca**: ejecutables o scripts observados por Amcache dentro de `Downloads`
- **Cómo investigarlo**: revisar Browser downloads, hash, publisher y si además existe `Prefetch` o `4688`

### Amcache Executable In AppData

- **ID interno**: `amcache_executable_in_appdata`
- **Qué busca**: binarios observados por Amcache en `AppData`, `Temp` u otras rutas similares
- **Cómo investigarlo**: validarlo como presencia/posible uso y elevar solo con correlación fuerte

### ShimCache Suspicious Path

- **ID interno**: `shimcache_suspicious_path`
- **Qué busca**: entradas `ShimCache` / `AppCompat` en rutas sospechosas o UNC
- **Cómo investigarlo**: no venderlo como ejecución confirmada por sí solo

### AppCompat LOLBin Observed

- **ID interno**: `appcompat_lolbin_observed`
- **Qué busca**: `powershell.exe`, `cmd.exe`, `rundll32.exe`, `certutil.exe` y otros LOLBins observados en artefactos de compatibilidad
- **Cómo investigarlo**: correlacionar con fuentes de ejecución fuerte y contexto del usuario

### Remote Access Tool Observed

- **ID interno**: `remote_access_tool_observed`
- **Qué busca**: `AnyDesk`, `TeamViewer`, `ngrok`, `plink` y similares observados en artefactos de compatibilidad
- **Cómo investigarlo**: validar si la herramienta estaba autorizada y si hubo actividad remota asociada

### Double Extension Program Observed

- **ID interno**: `double_extension_program_observed`
- **Qué busca**: binarios como `invoice.pdf.exe` o `photo.jpg.exe`
- **Cómo investigarlo**: cruzar con Browser downloads, `MFT/USN` y ejecución fuerte

### Downloaded Program Observed In Amcache

- **ID interno**: `downloaded_program_observed_in_amcache`
- **Qué busca**: archivo descargado por navegador que luego aparece observado en Amcache
- **Cómo investigarlo**: confirmar path, tiempos y si además existe ejecución fuerte

### Program Observed And Executed

- **ID interno**: `program_observed_and_executed`
- **Qué busca**: Amcache/AppCompat correlacionado con `Prefetch` o `EVTX 4688`
- **Cómo investigarlo**: revisar el emparejamiento exacto y la cadena evidencia -> observación -> ejecución

### Program Observed And Detected By Defender

- **ID interno**: `program_observed_and_detected_by_defender`
- **Qué busca**: programa observado en Amcache/AppCompat que además aparece en Defender
- **Cómo investigarlo**: validar hash/path y la acción tomada por Defender

## Reglas SRUM

### SRUM High Upload

- **ID interno**: `srum_high_upload`
- **Qué busca**: aplicaciones con volumen de subida elevado en SRUM
- **Cómo investigarlo**: revisar proceso, usuario, volumen y correlación con Browser, Prefetch, EVTX y Defender

### SRUM Remote Access Tool Network Usage

- **ID interno**: `srum_remote_access_tool_network_usage`
- **Qué busca**: `AnyDesk`, `TeamViewer`, `RustDesk` y herramientas similares con red en SRUM
- **Cómo investigarlo**: validar si era soporte remoto autorizado y correlacionar con ejecución fuerte

### SRUM File Transfer Tool Network Usage

- **ID interno**: `srum_file_transfer_tool_network_usage`
- **Qué busca**: `rclone`, `WinSCP`, `FileZilla` y utilidades parecidas con tráfico SRUM
- **Cómo investigarlo**: revisar volumen, momento, origen del binario y si hubo archivos asociados

### SRUM LOLBin Network Usage

- **ID interno**: `srum_lolbin_network_usage`
- **Qué busca**: `powershell.exe`, `bitsadmin.exe`, `certutil.exe`, `curl.exe`, etc. con actividad de red
- **Cómo investigarlo**: correlacionar con `4688`, PowerShell y descargas

### SRUM Suspicious Path Network Usage

- **ID interno**: `srum_suspicious_path_network_usage`
- **Qué busca**: procesos en AppData, Temp, Downloads u otras rutas sensibles con red en SRUM
- **Cómo investigarlo**: validar ruta, binario y si existe correlación con Browser, MFT o Amcache

### SRUM Possible Exfiltration Candidate

- **ID interno**: `srum_possible_exfiltration_candidate`
- **Qué busca**: alto upload o ratio subida/bajada desbalanceado
- **Cómo investigarlo**: mantener wording prudente y revisar contexto, volumen, aplicación y otras fuentes

### SRUM Browser Download Correlation

- **ID interno**: `srum_browser_download_correlation`
- **Qué busca**: programa descargado desde navegador que luego aparece activo en SRUM
- **Cómo investigarlo**: revisar dominio de descarga, momento y si hay ejecución adicional

### SRUM Downloaded Program Network Active

- **ID interno**: `srum_downloaded_program_network_active`
- **Qué busca**: programa descargado que además tuvo actividad de red y, a veces, ejecución fuerte
- **Cómo investigarlo**: revisar cadena descarga -> observación -> ejecución -> red

## Reglas Defender

- `defender_high_severity_detection`
- `defender_remediation_failed`
- `defender_detected_downloaded_file`
- `defender_detected_executed_file`
- `defender_detection_in_scheduled_task`
- `defender_hacktool_or_pua`
- `defender_allowed_threat`
- `defender_quarantined_file`
- `defender_detection_in_user_writable_path`
- `defender_detection_with_network_activity`
- `sensitive_file_in_cloud_sync_folder`: archivo sensible observado dentro de carpeta cloud
- `archive_created_in_cloud_sync_folder`: comprimido observado dentro de carpeta cloud
- `multiple_files_staged_in_cloud_folder`: varios ficheros relevantes modificados dentro de cloud en ventana corta
- `powershell_copy_to_cloud_folder`: PowerShell o command line copiando a cloud
- `browser_download_to_cloud_folder`: descarga de navegador directamente a carpeta cloud
- `bits_download_to_cloud_folder`: descarga BITS a carpeta cloud
- `executable_or_script_in_cloud_folder`: ejecutable o script observado dentro de cloud
- `defender_detection_in_cloud_folder`: detección de Defender dentro de carpeta cloud
- `persistence_target_in_cloud_folder`: persistencia apuntando a ruta cloud
- `possible_cloud_exfiltration_candidate`: cadena prudente de staging/copia a cloud sin afirmar upload confirmado
