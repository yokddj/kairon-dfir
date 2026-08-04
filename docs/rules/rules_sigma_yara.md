# Rules, Sigma and YARA

## Rules Engine v2

La UI de `Rules` está pensada ahora como flujo `Sigma-first`.

Motor común para:

- `Sigma` sobre eventos normalizados
- `YARA` sobre ficheros accesibles de la evidencia
- detecciones builtin

La separación importante en producto es:

- `Sigma`
  - corre sobre `indexed events`
- `YARA`
  - corre sobre `preserved files`
- `Heuristics`
  - detecciones internas automáticas

No deben mezclarse visualmente en la UI.

## Sigma

### Qué soporta

- validación de reglas YAML
- ejecución por caso, evidencia, host o ventana temporal
- mapping de campos frecuentes hacia el esquema normalizado
- creación de detections enlazadas a eventos

### Import correcto

- `Import Sigma rule`
  - un único fichero `.yml` o `.yaml`
- `Import Sigma rule pack`
  - un `ZIP/TAR/7z` con varias reglas Sigma

Si una colección comprimida no coincide con un formato especializado, debe caer a ingest genérica sin obligar al usuario a entender la tecnología interna.

### Output útil

Cada detection Sigma debe exponer:

- regla
- evento enlazado
- campos coincidentes
- resumen de condición
- severidad
- confidence
- tags / MITRE si existen

## YARA

### Qué soporta

- validación y compilación de reglas
- ejecución sobre ficheros preservados o rutas seleccionadas
- `matched_strings` truncados y seguros
- deduplicación y estado persistente en rerun

### Import correcto

- `Import YARA rule`
  - un único fichero `.yar` o `.yara`
- `Import YARA rule pack`
  - un `ZIP/TAR/7z` con varios ficheros YARA

La UI debe dejar claro que YARA no se ejecuta sobre logs indexados.

### Límites de seguridad

- no seguir symlink escape
- no salir de roots permitidos
- saltar ficheros demasiado grandes según configuración
- no lanzar full scan masivo por defecto

### Recomendación operativa

- empieza con un scope pequeño
- usa `selected paths` o evidencia concreta
- evita toda la colección salvo necesidad clara

## Detections

Todas las ejecuciones de reglas desembocan primero aquí.

Estados:

- `new`
- `reviewed`
- `confirmed`
- `dismissed`

Acciones:

- abrir detalle
- abrir evento o archivo relacionado
- pivotar a Search
- abrir Timeline
- abrir Process Graph si hay contexto de proceso
- promover a Finding

## Debug reports

El debug pack puede incluir:

- `rules_run_report.json`
- `detections_report.json`
- `sigma_matches.jsonl`
- `yara_matches.jsonl`

## Recomendación de uso

- empieza por Sigma builtin/controlado
- añade YARA cuando ya tengas un scope claro
- usa `Rule Runs` para comprobar estado, volumen y errores
- abre `Detections` filtrado por `source=sigma|yara` tras cada run
- usa `Search` con queries como `detection.source:sigma` o `detection.source:yara`
- no promociones detecciones débiles a findings high sin contexto adicional

## Operations v2

La pestaña `Rule Library` permite ahora operaciones masivas sobre reglas importadas:

- selección múltiple por regla o pack
- `Enable selected`
- `Disable selected`
- `Delete selected`
- `Delete all matching`
- `Delete all imported rules`

Protecciones:

- las heurísticas builtin no deben borrarse con `delete imported rules`
- los borrados masivos destructivos requieren escribir `DELETE RULES`
- borrar reglas o packs no elimina las detecciones ya creadas

`Rule Runs` añade control operativo:

- `Cancel run`
- `Mark failed/stale`
- `Retry run`
- `Delete run record`
- acciones bulk para runs seleccionados

Qué significa `stale`:

- el run sigue marcado como `queued` o `running` en persistencia
- pero no hay `heartbeat` reciente del worker
- la UI lo expone como warning operativo para que el analista lo cancele, lo marque como fallido o lo reintente
