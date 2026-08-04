# Cómo añadir reglas nuevas

## Dónde están hoy las reglas

### Reglas almacenadas en base de datos

Se crean o importan por API/UI y viven como objetos `Rule` o `RuleSet`.

### Ficheros YAML del repositorio

Actualmente el repo incluye reglas auxiliares en:

```text
backend/app/rules/
```

En este directorio ya existen, por ejemplo:

- `suspicious_keywords.yaml`
- `artifact_profiles.yaml`
- `known_windows_artifacts.yaml`
- `builtin_detection_overrides.yaml`

Importante:

- `suspicious_keywords.yaml` ayuda a etiquetar eventos, no es una `Rule` de base de datos por sí sola.
- Las builtin detections viven en código y se documentan aparte.

## Motores soportados hoy

- `heuristic`
- `sigma`
- `yara`

## Formato real de una regla heuristic

El motor heuristic soporta un formato simple con:

- `query.any`
- `filters`

Ejemplo:

```yaml
name: PowerShell encoded command
description: Busca comandos PowerShell con -enc
severity: high
query:
  any:
    - field: process.command_line
      contains: -enc
filters:
  event.type:
    - process_creation
```

## Formato real de Sigma

La ruta Sigma del proyecto soporta un MVP centrado en:

- `detection.selection`
- `condition: selection`

Campos Sigma conocidos se remapean a campos normalizados, por ejemplo:

- `EventID` -> `windows.event_id`
- `Image` -> `process.path`
- `CommandLine` -> `process.command_line`
- `TargetUserName` -> `user.name`

## YARA

YARA se importa como:

- regla individual
- rule pack

La ejecución YARA se hace sobre archivos preservados, no sobre CSV/JSON parseados por defecto.

## Campos útiles para reglas

- `event.type`
- `event.category`
- `event.action`
- `windows.event_id`
- `windows.channel`
- `windows.provider`
- `process.command_line`
- `process.path`
- `powershell.script_block_text`
- `file.path`
- `service.image_path`
- `task.command`
- `detection.threat_name`
- `tags`
- `suspicious_reasons`

## Cómo definir severidad

Usa una severidad que ayude al analista a priorizar:

- `info`
- `low`
- `medium`
- `high`
- `critical`

## Cómo añadir descripción y recomendación

Siempre que sea posible, una regla debe responder:

1. Qué busca
2. Por qué es relevante
3. Qué revisar después de un match

## Ejemplos prácticos

### Regla heuristic para PowerShell encoded command

```yaml
name: PowerShell encoded command
description: Busca procesos PowerShell con -enc
severity: high
query:
  any:
    - field: process.command_line
      contains: -enc
filters:
  process.name:
    - powershell.exe
    - pwsh.exe
```

### Regla heuristic para servicio desde AppData

```yaml
name: Suspicious service path
description: Servicio creado con binario bajo AppData
severity: high
query:
  any:
    - field: service.image_path
      contains: \\AppData\\
filters:
  event.type:
    - service_created
```

### Regla heuristic para tarea programada que ejecuta PowerShell

```yaml
name: Scheduled task runs PowerShell
description: Tarea programada que llama a PowerShell
severity: medium
query:
  any:
    - field: task.command
      contains: powershell
filters:
  event.type:
    - scheduled_task_created
    - scheduled_task_updated
```

### Regla para log cleared 1102

```yaml
name: Audit log cleared
description: Busca borrado del log de auditoría
severity: high
query:
  any:
    - field: windows.event_id
      equals: 1102
filters:
  event.type:
    - audit_log_cleared
```

## Cómo desactivar una regla

### Reglas almacenadas

La UI y la API ya soportan `enabled = true/false`.

### Builtin detections

Consulta [builtin_rules.md](builtin_rules.md). Se desactivan:

- globalmente con `AUTO_CREATE_HEURISTIC_DETECTIONS`
- individualmente con `builtin_detection_overrides.yaml`

## Cómo evitar falsos positivos

1. Filtra por `event.type` o `artifact.type` cuando sea posible.
2. No busques solo por texto si existe un campo normalizado mejor.
3. Usa Provider/Channel correctos en eventos Windows.
4. Añade descripción clara de contexto esperado.
