# EVTX / EvtxECmd

## Qué es EVTX

EVTX es el formato de logs de eventos de Windows. En la plataforma se soportan dos rutas:

- salida ya parseada con **EvtxECmd**
- parseo **raw nativo** del `.evtx` cuando está disponible la dependencia del parser

## Por qué se sigue usando EvtxECmd_Output.csv

Porque permite:

- ingestión rápida y reproducible
- preservar raw y payload sin diseñar todavía un parser raw completo
- normalizar eventos relevantes con control sobre `Provider/Channel`

El parser raw nativo y el flujo `EvtxECmd_Output.csv` comparten la misma filosofía de clasificación:

- no clasificar por `EventID` solamente
- validar siempre `Provider + Channel + EventID`
- degradar a `windows_event` genérico cuando el `EventID` colisiona con otra familia

## Campos que se extraen

- `EventID`
- `Provider`
- `Channel`
- `TimeCreated`
- `RecordNumber`
- `Computer`
- `UserName`
- `PayloadData*`
- `Payload`
- `EventData`
- `Xml` / `RawXml` si existe

## Cómo se parsea Payload JSON

Si `Payload` contiene JSON válido, se intenta extraer y fusionar en `windows.event_data`.

Ejemplo:

```json
{
  "EventData": {
    "Data": [
      {"@Name": "TargetUserName", "#text": "SYSTEM"},
      {"@Name": "LogonType", "#text": "5"}
    ]
  }
}
```

Se convierte en algo parecido a:

- `windows.event_data.TargetUserName = SYSTEM`
- `windows.event_data.LogonType = 5`

Además:

- `windows.payload.Payload` conserva el payload original
- `windows.event_data.payload_columns` conserva `PayloadData*`
- `raw` conserva la fila original

## Qué significa `source_mismatch`

Un `source_mismatch` significa:

- el `EventID` coincide con uno conocido
- pero `Provider/Channel` **no** son los esperados
- por tanto el evento **no** se etiqueta como `logon_failed`, `service_created`, etc.

En ese caso cae a una clasificación genérica:

- `event.category = windows_event`
- `event.type = event_id_<ID>`
- `event.action = windows_event_observed`
- tags incluyen `source_mismatch`

Ejemplo importante:

- `EventID 400` solo se interpreta como PowerShell si el origen es realmente PowerShell
- `Microsoft-Windows-AppXDeploymentServer/Operational` con `EventID 400` **no** debe verse como PowerShell
- `Microsoft-Windows-StateRepository/Operational` con `EventID 400` **no** debe verse como PowerShell

## Tabla de EventIDs soportados

| EventID | Provider / Channel esperado | Clasificación | Qué busca | Campos importantes | Sección semiautomática |
| --- | --- | --- | --- | --- | --- |
| 4624 | Security-Auditing / Security | `logon_success` | Inicio de sesión exitoso | usuario, LogonType, IP, ProcessName | Logons / RDP |
| 4625 | Security-Auditing / Security | `logon_failed` | Inicio de sesión fallido | usuario, LogonType, Status, IP | Logons |
| 4634 | Security-Auditing / Security | `logoff` | Cierre de sesión | usuario, LogonType | Logons |
| 4647 | Security-Auditing / Security | `user_logoff` | Logoff iniciado por usuario | usuario, LogonId | Logons |
| 4648 | Security-Auditing / Security | `explicit_credentials_logon` | Uso explícito de credenciales | SubjectUserName, TargetUserName, ProcessName | Logons |
| 4672 | Security-Auditing / Security | `special_privileges_assigned` | Privilegios especiales | SubjectUserName, PrivilegeList | Logons |
| 4688 | Security-Auditing / Security | `process_creation` | Creación de proceso | NewProcessName, CommandLine, ParentProcessName | Programas ejecutados |
| 4689 | Security-Auditing / Security | `process_termination` | Fin de proceso | ProcessName, ProcessId | Timeline |
| 4697 | Security-Auditing / Security | `service_created` | Instalación de servicio | ServiceName, ServiceFileName | Servicios / Persistencia |
| 4698 | Security-Auditing / Security | `scheduled_task_created` | Tarea creada | TaskName, TaskContent | Tareas / Persistencia |
| 4702 | Security-Auditing / Security | `scheduled_task_updated` | Tarea modificada | TaskName, TaskContent | Tareas / Persistencia |
| 4720 | Security-Auditing / Security | `user_created` | Usuario creado | TargetUserName | Cambios de cuentas |
| 4722 | Security-Auditing / Security | `user_enabled` | Usuario habilitado | TargetUserName | Cambios de cuentas |
| 4723 | Security-Auditing / Security | `password_change_attempt` | Cambio de contraseña | TargetUserName | Cambios de cuentas |
| 4724 | Security-Auditing / Security | `password_reset_attempt` | Reset de contraseña | TargetUserName | Cambios de cuentas |
| 4725 | Security-Auditing / Security | `user_disabled` | Usuario deshabilitado | TargetUserName | Cambios de cuentas |
| 4726 | Security-Auditing / Security | `user_deleted` | Usuario borrado | TargetUserName | Cambios de cuentas |
| 4728 / 4732 | Security-Auditing / Security | `user_added_to_group` | Usuario añadido a grupo | MemberName, SubjectUserName | Cambios de cuentas |
| 4735 / 4737 | Security-Auditing / Security | `group_changed` | Grupo modificado | TargetUserName | Cambios de cuentas |
| 4738 | Security-Auditing / Security | `user_modified` | Usuario modificado | TargetUserName | Cambios de cuentas |
| 4740 | Security-Auditing / Security | `account_locked_out` | Cuenta bloqueada | TargetUserName | Cambios de cuentas |
| 4768 / 4769 / 4771 / 4776 | Security-Auditing / Security | Kerberos / NTLM | Autenticación de dominio | usuario, status, IP | Logons |
| 4778 / 4779 | Security-Auditing / Security | RDP reconnection/disconnection | Sesiones RDP | AccountName, ClientAddress | RDP |
| 5140 / 5145 | Security-Auditing / Security | Share access | Acceso a shares SMB | ShareName, RelativeTargetName, IpAddress | Network / Timeline |
| 5156 | Security-Auditing / Security | `network_connection_allowed` | Conexión permitida | Application, SourceAddress, DestinationAddress | Network |
| 1102 | Eventlog / Security | `audit_log_cleared` | Borrado de logs de auditoría | SubjectUserName | Anti-forensics |
| 7036 / 7040 / 7045 | Service Control Manager / System | cambios de servicio | Estado, start type, creación | ServiceName, ImagePath | Servicios / Persistencia |
| 106 / 129 / 140 / 141 / 200 / 201 | TaskScheduler Operational | actividad de tareas | Registro, borrado, acción iniciada/finalizada | TaskName, ActionName | Tareas |
| 400 / 403 / 600 / 800 | PowerShell | ciclo de motor / pipeline | HostApplication, CommandLine | PowerShell |
| 4103 / 4104 / 4105 / 4106 | PowerShell Operational | module logging / script block | ScriptBlockText, ScriptBlockId | PowerShell |
| 21 / 22 / 23 / 24 / 25 / 39 / 40 | TerminalServices LocalSessionManager | actividad RDP | User, Address, Reason | RDP |
| 1149 | TerminalServices RemoteConnectionManager | `rdp_authentication_success` | Autenticación RDP | User, Domain, SourceNetworkAddress | RDP |
| 1116 / 1117 / 1118 / 1119 / 5007 / 5013 | Windows Defender Operational | actividad Defender | ThreatName, Path, Action | Defender |
| 5857 / 5858 / 5859 / 5860 / 5861 | WMI Activity Operational | actividad WMI | ClientMachine, Query, Consumer | Persistencia / Timeline |
| Sysmon 1,3,7,10,11,12,13,14,15,22,23,26 | Sysmon Operational | preparado | telemetría Sysmon | según evento | Futuro |

## Puntos importantes

### No todo EventID significa lo mismo

Ejemplo:

> `4625` solo debe interpretarse como fallo de inicio de sesión cuando viene de `Security / Microsoft-Windows-Security-Auditing`.

Otro ejemplo:

> `400` solo debe interpretarse como actividad de PowerShell cuando `Provider/Channel` corresponden a PowerShell.

### 1102 no se trata como Security-Auditing

`1102` se espera en:

- `Channel = Security`
- `Provider = Microsoft-Windows-Eventlog` o `Eventlog`

### Cómo comprobar que funciona

1. Importa un `EvtxECmd_Output.csv`.
2. Busca `4624`.
3. Abre un evento.
4. Verifica:
   - `windows.event_id = 4624`
   - `user.name`
   - `windows.logon_type`
   - `process.path`
   - `windows.event_data`
   - `windows.payload`
