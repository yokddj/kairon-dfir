# Findings and Correlation

## Qué es un finding

Un `finding` es una conclusión investigativa apoyada en uno o más eventos, detections, cadenas de proceso o IOC relacionados.

No es equivalente a una regla disparada.

## Tipos v1 principales

- `download_execute_detect`
- `office_powershell`
- `powershell_network`
- `persistence_execution`
- `cloud_exfil_candidate`
- `usb_exfil_candidate`
- `execution_cleanup`
- `suspicious_process_chain`
- `user_executed_suspicious_command`
- `trusted_office_macro_document`
- `user_activity_suspicious_program`
- `downloaded_executable_origin`
- `suspicious_file_deleted_or_renamed`
- `office_security_alert_document`
- `suspicious_ui_observed_file`
- `security_notification_observed`

## Severidad, confianza y estado

- severidad: `low` a `critical`
- confianza: `low`, `medium`, `high`
- estado: `new`, `reviewed`, `confirmed`, `dismissed`

El estado debe preservarse si el finding o sus señales vuelven a aparecer en reruns.

## Deduplidación

La correlación intenta evitar findings duplicados usando fingerprints y contexto de caso/evidencia/host/eventos.

## Relación con detections y reglas

- una `detection` puede apoyar un finding
- una detection confirmada puede promoverse a finding
- no toda detection high debe convertirse automáticamente en finding high

## Limitaciones

- la correlación sigue siendo heurística
- `usb_exfil_candidate` y `cloud_exfil_candidate` expresan hipótesis, no prueba concluyente
- los findings deben leerse junto al Timeline, Search y Process Graph
- `user_executed_suspicious_command` se reserva para señales de alta confianza como `RunMRU` con PowerShell encoded / LOLBIN claro
- `trusted_office_macro_document` usa `TrustRecords` como evidencia de documento confiado o contenido habilitado, pero su interpretación depende de versión Office y valor observado
- `user_activity_suspicious_program` evita dispararse por `RecentDocs`, `TypedPaths` o `Shellbags` aislados
- `downloaded_executable_origin` usa `Zone.Identifier` y contexto de URL/origen web para enlazar un fichero con su procedencia; no confirma ejecución por sí solo
- `suspicious_file_deleted_or_renamed` usa USN / `$LogFile` / `$I30` para señalar staging, borrado o rename sospechoso, pero la severidad alta depende de correlación adicional
- `office_security_alert_document` se apoya en OAlerts/Office cache/UI artifacts para resaltar Protected View, macros o content enablement; conviene leerlo junto con Email, NTFS y User Activity
- `suspicious_ui_observed_file` usa thumbnails, ActivitiesCache o Windows Search para marcar referencias UI a ficheros sospechosos, no como prueba de ejecución
- `security_notification_observed` resume notificaciones de seguridad de alto valor como Defender/quarantine/phishing, con cuerpo truncado y sanitizado
