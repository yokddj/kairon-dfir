# Análisis semiautomático

## Qué es

Es una capa de agrupación de eventos normalizados orientada a responder más rápido a la pregunta:

> ¿Qué pasó en este host o este caso?

No sustituye a la revisión manual. Resume actividad relevante.

## Endpoint y vista

- Backend: `GET /api/cases/{case_id}/analysis/semi-auto`
- Frontend: `Análisis semiautomático`

## Secciones actuales

### 1. Programas ejecutados

| Campo | Detalle |
| --- | --- |
| Qué busca | Creación de procesos y ejecución observada |
| Evidencias actuales | EVTX 4688, Prefetch / PECmd, parte de PowerShell, Registry / RECmd |
| EventIDs/artefactos | 4688, `PECmd_Output.csv`, `RECmd_Output.csv` (`userassist_execution`, `bam_execution`, `dam_execution`, `run_mru_command`, `muicache_entry`) |
| Qué muestra | timestamp, usuario, proceso, ruta, fuente, run count, last run, previous runs, confidence |
| Cómo interpretarlo | Busca ejecuciones anómalas, padres extraños o rutas sospechosas |
| Limitaciones actuales | La correlación EVTX 4688 + Prefetch es básica y se apoya en nombre, host y cercanía temporal |
| Futuro | UserAssist, BAM/DAM, Amcache, correlación más fuerte con Prefetch raw |

### 2. PowerShell

| Campo | Detalle |
| --- | --- |
| Qué busca | Script blocks, module logging, pipeline execution, encoded command, download cradle |
| Evidencias actuales | 4104, 4103, 800, 400, 403, Prefetch de `powershell.exe` / `pwsh.exe`, Jump Lists/LNK que apunten a scripts PowerShell, `ConsoleHost_history.txt`, transcripts y scripts PowerShell observados |
| Qué muestra | script block, usuario, ScriptBlockId, razones sospechosas |
| Cómo interpretarlo | Prioriza encoded commands, descargas y cambios Defender |
| Limitaciones actuales | `PSReadLine` no suele tener timestamp por comando y un script observado no equivale a ejecución confirmada |
| Futuro | más correlación con `4104`, transcripts enriquecidos y mejor agrupación por sesión |

### 3. Logons

| Campo | Detalle |
| --- | --- |
| Qué busca | Logons exitosos, fallidos, explícitos y privilegios especiales |
| Evidencias actuales | 4624, 4625, 4648, 4672 |
| Qué muestra | usuario, LogonType, IP origen, workstation, status |
| Cómo interpretarlo | Revisa logons remotos, cuentas de servicio y fallos reiterados |
| Limitaciones actuales | La cobertura depende de que el EVTX parseado esté completo |
| Futuro | Más correlación con WinRM, NTLM y Kerberos |

### 4. RDP

| Campo | Detalle |
| --- | --- |
| Qué busca | Autenticaciones RDP, reconexiones y desconexiones |
| Evidencias actuales | 4624 LogonType 10, 1149, 21/22/23/24/25/39/40, 4778, 4779 |
| Qué muestra | usuario, IP origen, resumen, sesión |
| Cómo interpretarlo | Útil para accesos remotos, pivotes y sesiones tardías |
| Limitaciones actuales | No toda la telemetría RDP tiene el mismo nivel de detalle |
| Futuro | Correlación con LNK, Prefetch y servicios remotos |

### 5. Tareas programadas

| Campo | Detalle |
| --- | --- |
| Qué busca | Definiciones de tareas, tareas sospechosas, persistencia y ejecución correlacionada |
| Evidencias actuales | XML raw de `C:\\Windows\\System32\\Tasks\\*`, CSVs compatibles de Scheduled Tasks, 4698, 4699, 4700, 4701, 4702, 106, 140, 141, 200, 201, 102, 129 |
| Qué muestra | nombre, task path, command, arguments, RunAs, trigger summary, hidden/enabled, razones sospechosas |
| Cómo interpretarlo | Diferencia entre definición observada, persistencia candidata y ejecución observada por correlación |
| Limitaciones actuales | El XML describe configuración; la confianza sube mucho cuando hay EVTX, Prefetch, Browser, MFT o Defender relacionados |
| Futuro | `TaskCache` de Registry y enriquecimiento más fuerte de eventos TaskScheduler |

### 6. Servicios

| Campo | Detalle |
| --- | --- |
| Qué busca | Servicios creados o modificados |
| Evidencias actuales | 7045, 7040, 7036, 4697 |
| Qué muestra | nombre, image path, cuenta, start type |
| Cómo interpretarlo | Foco en persistencia y ejecución vía servicio |
| Limitaciones actuales | No cruza aún con Registry SYSTEM\\Services de forma fuerte |
| Futuro | Registry y más correlación con Prefetch del binario |

### 7. Conexiones de red

| Campo | Detalle |
| --- | --- |
| Qué busca | Conexiones permitidas y aplicación responsable |
| Evidencias actuales | 5156 |
| Qué muestra | app, IP origen, IP destino, protocolo |
| Cómo interpretarlo | Útil para ver procesos con actividad de red |
| Limitaciones actuales | SRUM ya entra, pero sigue sin aportar IP/destino exacto por sí solo y Sysmon 3 sigue pendiente |
| Futuro | Sysmon y correlación más fuerte por red |

## Browser activity

El análisis semiautomático ya incorpora:

- `browser_history`
- `downloaded_files`
- `web_searches`
- `cloud_activity`
- `suspicious_downloads`
- `downloaded_and_executed`

La correlación básica enlaza descargas con:

- `MFT/USN`
- `LNK`
- `Jump Lists`
- `Prefetch`
- `EVTX 4688`
- `Defender`

Estas secciones se alimentan tanto de browser CSV/JSON parseado como del parser raw de navegador desde colecciones Velociraptor.

## Secciones SRUM

- `network_activity`
- `application_network_usage`
- `high_upload_activity`
- `remote_access_activity`
- `possible_exfiltration`
- `downloaded_and_network_active_programs`

Estas secciones usan wording prudente: SRUM refuerza **actividad de red por aplicación**, no “exfiltración confirmada” ni destino exacto por sí solo.

## Secciones Scheduled Tasks

- `scheduled_tasks`
- `suspicious_tasks`
- `task_executions`
- `downloaded_and_persisted`

Interpretación operativa:

- `scheduled_task_definition` y `scheduled_task_com_handler` significan **tarea observada**, no ejecución probada.
- La sección `scheduled_tasks` resume configuración, principal, triggers y acciones.
- `suspicious_tasks` prioriza PowerShell codificado, LOLBins, rutas UNC, scripts en rutas de usuario, tareas `hidden + enabled` y `ComHandler`.
- `task_executions` sube confianza cuando aparecen EVTX de TaskScheduler/Security o ejecución relacionada en Prefetch/EVTX.
- `downloaded_and_persisted` enlaza Browser downloads con comandos o argumentos de tareas.

## Secciones PowerShell fuera de EVTX

- `powershell_activity`
- `powershell_downloads`
- `powershell_encoded_commands`
- `powershell_defender_tampering`
- `powershell_persistence`
- `powershell_recon`
- `powershell_credential_access`

Interpretación operativa:

- `powershell_console_history` significa comando observado en historial interactivo, no éxito confirmado.
- `powershell_transcript_command` aporta mejor contexto temporal y de sesión.
- `powershell_script_file_observed` significa script observado en disco, no ejecución probada.
- La confianza sube cuando aparecen correlaciones con `4104`, `4688`, Prefetch, Browser, MFT, Defender, Scheduled Tasks o SRUM.

## Secciones Recycle Bin

- `recycled_files`
- `deleted_files`
- `deleted_downloads`
- `deleted_executables`
- `deleted_scripts`
- `deleted_detected_files`
- `cleanup_candidates`

Interpretación operativa:

- `file_recycled` significa que el archivo fue enviado a la papelera.
- No equivale a borrado permanente.
- La confianza sube cuando aparece correlación con `MFT/USN`, Browser downloads o Defender.
- `cleanup_candidates` prioriza metadata `$I` sin `$R`, scripts, ejecutables y elementos sospechosos borrados después de uso o detección.

## Secciones USB

- `usb_devices`
- `usb_storage_devices`
- `usb_volume_mappings`
- `usb_file_activity`
- `usb_folder_activity`
- `download_to_usb`
- `possible_usb_exfiltration`
- `suspicious_usb_activity`

Interpretación operativa:

- `usb_device_install` y `usb_volume_mapping` significan dispositivo o volumen observado, no copia confirmada.
- `usb_file_activity` y `usb_folder_activity` resumen actividad en rutas removibles.
- `download_to_usb` destaca descargas directas a una unidad externa.
- `possible_usb_exfiltration` es deliberadamente prudente y debe leerse como hipótesis de trabajo.
- `setupapi_driver_activity` es una sección secundaria para bloques de SetupAPI de valor bajo o diagnóstico, y no debe confundirse con un USB externo concreto conectado.

## Secciones BITS

- `background_downloads`
- `bits_jobs`
- `bits_transfers`
- `suspicious_bits_jobs`
- `bits_notify_commands`
- `downloaded_then_executed`
- `downloaded_then_detected`
- `possible_persistence`

Interpretación operativa:

- un job BITS no es sospechoso por defecto
- `Windows Update` y jobs Microsoft pueden ser benignos
- `bits_notify_commands` merece revisión porque puede actuar como persistencia o callback
- `downloaded_then_executed` y `downloaded_then_detected` son secciones de mayor valor porque ya combinan varias fuentes
- `qmgr` raw sin parser no aparece falsamente como job parseado; queda como discovery

## Secciones WMI

- `wmi_persistence`
- `wmi_filters`
- `wmi_consumers`
- `wmi_bindings`
- `suspicious_wmi_consumers`
- `wmi_encoded_powershell`
- `wmi_download_commands`
- `possible_wmi_execution`

## Secciones Autoruns / ASEP

- `autoruns_persistence`
- `suspicious_autoruns`
- `run_key_persistence`
- `startup_folder_persistence`
- `service_driver_persistence`
- `ifeo_debugger_persistence`
- `winlogon_persistence`
- `appinit_appcert_persistence`
- `downloaded_then_persisted`
- `persisted_then_executed`
- `persistence_detected_by_defender`

Interpretación operativa:

- una entrada Autoruns es persistencia observada o candidata, no ejecución confirmada

## Secciones Cloud Sync

Se añaden secciones:

- `cloud_sync_roots`
- `cloud_accounts`
- `cloud_file_activity`
- `cloud_sensitive_files`
- `cloud_archives`
- `downloaded_to_cloud`
- `copied_to_cloud`
- `executable_from_cloud`
- `defender_detection_in_cloud`
- `possible_cloud_staging`
- `possible_cloud_exfiltration`

El wording sigue siendo prudente:

- `cloud sync root observed`
- `cloud staging candidate`
- `possible cloud exfiltration candidate`

La existencia de un archivo dentro de OneDrive, Dropbox o Google Drive no equivale por sí sola a subida confirmada.
- `suspicious_autoruns` prioriza rutas user-writable, unsigned/unverified, LOLBins, comandos de descarga y mecanismos críticos
- `downloaded_then_persisted` y `persisted_then_executed` son las secciones de mayor valor porque ya combinan varias fuentes

## Secciones Network / WLAN / DNS

Se añaden secciones:

- `network_overview`
- `wlan_profiles`
- `wlan_connections`
- `network_profiles`
- `dns_config`
- `dns_cache`
- `hosts_entries`
- `suspicious_hosts_entries`
- `suspicious_dns_config`
- `network_indicators`
- `network_correlations`

Interpretación operativa:

- `wlan_profile` significa que el perfil Wi-Fi fue observado, no que exista conexión reciente confirmada
- `wlan_connection` aporta más contexto temporal cuando llega desde EVTX
- `hosts_entries` resume overrides locales y debe revisarse junto con Browser, Defender y MFT
- `network_indicators` agrupa dominios, IPs, DNS y configuración observada
- `network_correlations` es la capa de mayor valor porque conecta esos indicadores con Browser, BITS, PowerShell, Cloud Sync, SRUM o Defender

Wording prudente:

- `network indicator observed`
- `possible suspicious network configuration`
- `possible correlation`

La familia `network` contextualiza conectividad y configuración local, pero no debe leerse como prueba automática de C2 o intrusión sin correlación suficiente.
- `wmi_bindings`
- `suspicious_wmi_consumers`
- `wmi_encoded_powershell`
- `wmi_download_commands`
- `possible_wmi_execution`
- `wmi_activity`

Interpretación operativa:

- `wmi_persistence` debe leerse como candidato de persistencia, no como ejecución confirmada
- la señal más fuerte aparece cuando existen `filter + consumer + binding`
- `suspicious_wmi_consumers` resume consumers con comandos, scripts o correlaciones de mayor valor
- `wmi_activity` recoge actividad WMI observada en EVTX, pero no equivale automáticamente a persistencia

### 8. Defender / malware

| Campo | Detalle |
| --- | --- |
| Qué busca | Detecciones, cuarentenas, remediación, fallos de remediación y correlaciones |
| Evidencias actuales | 1116, 1117, 1118, 1119, 5007, 5013, `DetectionHistory`, `MPLog`, CSV/JSON Defender |
| Qué muestra | threat name, path/resource, action, severity, status, user, related events |
| Cómo interpretarlo | Confirma detección o acción tomada, pero no siempre implica ejecución o infección activa |
| Limitaciones actuales | Quarantine raw solo discovery; deduplicación fina con EVTX aún mejorable |
| Futuro | metadata más profunda de cuarentena y soporte log adicional |

Secciones nuevas relacionadas:

- `defender_detections`
- `detected_files`
- `detected_downloads`
- `detected_executions`
- `quarantined_items`
- `remediation_failures`

### 9. Cambios de cuentas

| Campo | Detalle |
| --- | --- |
| Qué busca | Altas, bajas, cambios de contraseña, usuarios en grupos |
| Evidencias actuales | 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740 |
| Qué muestra | título, usuario, resumen |
| Cómo interpretarlo | Útil para abuso de cuentas y escalada |
| Limitaciones actuales | No hay correlación con artifacts de SAM/Registry raw |
| Futuro | RECmd y parsing de hives |

### 10. Persistencia

Qué busca:

- servicios
- tareas
- WMI persistence
- patrones persistentes ya etiquetados
- Run Keys y Services del Registro

Evidencias actuales:

- EVTX 7045 / 4697 / 7040 / 7036
- `RECmd_Output.csv` para `registry_run_key` y `registry_service`

### 11. Anti-forensics

Qué busca:

- borrado de logs de auditoría

Evidencias actuales:

- `1102`

### 12. Hallazgos sospechosos

Qué busca:

- PowerShell encoded
- download cradle
- Defender tampering
- rutas sospechosas
- LOLBins
- ejecuciones vía Prefetch desde rutas sospechosas
- PowerShell / cmd / mshta / rundll32 / regsvr32 / certutil / bitsadmin observados en Prefetch
- ADS observados en MFT
- doble extensión y nombres sospechosos en MFT/USN
- diferencias grandes entre `$SI` y `$FN`

Importante:

> Un hallazgo sospechoso no equivale a malware confirmado. Significa que merece revisión manual.

### 13. Archivos creados / modificados / borrados / renombrados

Qué busca:

- creaciones, borrados, renombrados y modificaciones de archivos

Evidencias actuales:

- `MFTECmd_Output.csv`

## Execution artifacts: Amcache / ShimCache / AppCompat

Esta capa añade o refuerza estas secciones:

- `program_inventory`
- `execution_candidates`
- `downloaded_and_observed_programs`
- `suspicious_programs`

Interpretación operativa:

- `Amcache` se usa como observación de programas, inventario y metadatos.
- `ShimCache` / `AppCompat` / `RecentFileCache` se usan como presencia o posible ejecución.
- La confianza sube a `high` solo si la correlación encuentra `Prefetch`, `EVTX 4688`, Browser download, `MFT/USN` o `Defender`.
- Sin correlación, no deben leerse como “ejecución confirmada”.
- CSVs USN compatibles con MFTECmd

Qué muestra:

- timestamp
- ruta
- extensión
- size
- source (`mft` o `usn`)
- reason cuando viene de USN

Cómo interpretarlo:

- `USN` suele ser más útil para actividad temporal concreta
- `MFT` suele aportar mejor contexto histórico y deleted candidates

### 14. Candidateos de ejecución y archivos sospechosos

Qué busca:

- `.exe`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.dll`, `.scr` en rutas sospechosas
- ADS
- doble extensión
- posibles anomalías `$SI/$FN`

Evidencias actuales:

- `MFTECmd_Output.csv`
- CSVs USN compatibles con MFTECmd

### 15. Timeline

Qué busca:

- una vista ordenada de actividades generadas

Qué muestra:

- timestamp
- activity_type
- host
- user
- resumen

### 16. Archivos abiertos

Qué busca:

- accesos a targets desde shortcuts `.lnk`
- documentos abiertos
- targets de usuario con valor contextual

Evidencias actuales:

- `LECmd_Output.csv`
- `JLECmd_Output.csv`
- raw `automaticDestinations-ms` desde Velociraptor y `customDestinations-ms` con soporte parcial
- secciones reforzadas para JumpLists: `recent_files`, `downloaded_files_opened`, `deleted_files_opened`, `network_file_activity`, `usb_file_activity`, `cloud_file_activity`, `suspicious_recent_items`
- si una JumpList usa `timestamp_precision = source_file_mtime`, la confianza temporal baja respecto a entradas con `TargetAccessed` o `DestListLastAccessed`
- `user_writable_path` en JumpLists se trata como contexto; no eleva por sí solo a hallazgo sospechoso
- `RECmd_Output.csv` para `TypedPaths`, `RecentDocs` y `Shellbags`

Qué muestra:

- timestamp
- usuario
- target efectivo
- extensión
- source LNK
- drive type
- network path

Nota:

- cuando `TargetPath` o `TargetIDAbsolutePath` son parciales como `Desktop\\`, la app usa `lnk.effective_path` para enseñar la mejor ruta disponible

### 17. Scripts abiertos

Qué busca:

- `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` y similares abiertos vía LNK

Evidencias actuales:

- `LECmd_Output.csv`
- `JLECmd_Output.csv`

Cómo interpretarlo:

- no siempre implica ejecución confirmada
- sí indica interacción fuerte y merece correlación con `4688`, PowerShell y Prefetch
- si el target mostrado parece genérico, revisa en detalle `lnk.effective_path`, `lnk.local_path` y `lnk.relative_path`

### 18. Rutas de red / USB

Qué busca:

- targets `UNC`
- shares
- volúmenes removibles o candidatos a USB

Evidencias actuales:

- `LECmd_Output.csv`
- `JLECmd_Output.csv`

### 19. Documentos recientes

Qué busca:

- documentos abiertos recientemente por una aplicación
- contexto de app y usuario

Evidencias actuales:

- `JLECmd_Output.csv`

### 20. Aplicaciones usadas

Qué busca:

- aplicaciones con Jump Lists recientes
- frecuencia de interacción
- último uso observado

Evidencias actuales:

- `JLECmd_Output.csv`

### 21. Actividad de usuario

Qué busca:

- rutas tecleadas en Explorer
- comandos lanzados desde Ejecutar
- documentos recientes
- artefactos Registry que ayudan a explicar interacción del usuario sin obligar a revisar `raw`

Qué mirar primero:

- `registry.key_path`
- `registry.value_name`
- `registry.value_data`
- `process.path`
- `destination.hostname`
- carpetas observadas por Shellbags

Evidencias actuales:

- `RECmd_Output.csv`

### 21b. Folder activity / Shellbags

Qué busca:

- carpetas vistas o navegadas por el usuario
- rutas UNC o shares
- carpetas USB/removable
- carpetas cloud sync
- carpetas sospechosas o ya no presentes

Evidencias actuales:

- `SBECmd_Output.csv`
- `*Shellbags*.csv`
- `RECmd_Output.csv` cuando incluya shellbags normalizados

Qué muestra:

- timestamp
- usuario
- path
- tipo de ruta
- source hive/file
- MRU position
- related events

Cómo interpretarlo:

- Shellbags no prueban ejecución
- sí ayudan mucho a demostrar interacción con carpetas, shares, USB o rutas luego borradas
- la confianza sube cuando correlacionan con LNK, JumpLists, Browser, MFT/USN o Recycle Bin

### 20. Dispositivos USB

Qué busca:

- dispositivos USB vistos en el registro
- mappings de unidad/volumen
- contexto para correlación con LNK y Jump Lists

Evidencias actuales:

- `RECmd_Output.csv`
# Semi-automatic analysis consumes native raw EVTX and LNK events using the same normalized schema as external parsers. For `native_lnk`, this now includes `startup_lnk`, cloud targets, UNC/network paths, removable media hints and partial/unresolved target quality flags.
