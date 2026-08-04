# Primeros pasos

## 1. Levantar la aplicación

1. Copia `.env.example` a `.env`.
2. Ejecuta:

```bash
docker compose up --build
```

3. Abre:
   - frontend: `http://localhost:5173`
   - API: `http://localhost:8000`
   - OpenSearch: `http://localhost:9200`

## 2. Crear o abrir un caso

1. Entra en `Cases`.
2. Crea un caso nuevo o abre uno existente.
3. Si vas a trabajar en una investigación concreta, déjalo como **caso activo**.

## 3. Qué evidencia subir hoy

Lo más recomendable hoy es subir:

- colecciones parseadas de KAPE/EZ Tools
- carpetas parseadas de Velociraptor
- especialmente `*_EvtxECmd_Output.csv`

## 4. Cómo subir evidencia

1. Entra en el caso.
2. Usa `Upload files` o `Upload folder`.
3. Espera a que la ingesta cambie a `completed`.

## 5. Cómo saber si el parsing terminó bien

Revisa:

1. Estado de la evidencia.
2. `Artifact Views` del caso.
3. `Activity` por si hubo errores de parsing/indexación.
4. `Search` para confirmar que aparecen eventos del caso.

## 6. Cómo buscar un EventID

Ejemplos prácticos:

- `4624` -> logons exitosos
- `4625` -> logons fallidos
- `4104` -> script blocks de PowerShell
- `4688` -> creación de procesos
- `7045` -> creación de servicios
- `4698` -> creación de tareas programadas
- `1116` -> detección Defender

Consejo:

1. Abre `Search`.
2. Deja la query vacía para ver el volumen general.
3. Usa `Search mode = IOC` o `smart` para EventID concretos.
4. Si necesitas precisión extra, filtra `artifact.type = evtx`.

## 7. Cómo abrir el detalle de un evento

Puedes llegar al evento desde:

- `Search`
- `Artifact Explorer`
- `Detections` si la detection apunta a un evento
- `Timeline`

En el detalle busca:

- `event.type`
- `windows.event_id`
- `windows.channel`
- `windows.provider`
- `raw`
- `windows.event_data`
- `windows.payload`

## 8. Cómo revisar el análisis semiautomático

1. Ve a `Análisis semiautomático`.
2. Selecciona el caso.
3. Si el resumen sale vacío, primero pulsa `Clear time filter`.
4. Revisa:
   - Logons
   - PowerShell
   - Servicios
   - Tareas
   - Red
   - Defender
   - Hallazgos sospechosos

## 9. Cómo revisar reglas y detecciones

### Rules

Usa `Rules` para:

- ver reglas individuales
- ver rule packs
- importar Sigma/YARA/heuristic
- activar/desactivar reglas
- ejecutar reglas sobre un caso

### Detections

Usa `Detections` para:

- ver señales automáticas
- filtrar por engine, severity, status y caso
- marcar reviewed o false positive
- borrar selecciones o conjuntos filtrados

## 10. Cómo crear un finding desde eventos o detections

Hoy puedes crear findings desde:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Detections`

Flujo recomendado:

1. Selecciona uno o varios eventos, o una o varias detections del mismo caso.
2. Pulsa `Create finding`.
3. Ajusta título, severidad y descripción.
4. Guarda el finding y revísalo en `Findings`.

Usa `Promote to finding` en `Detections` si quieres una promoción rápida sin editar demasiado contexto.

## 11. Qué hacer si no aparecen resultados

1. Comprueba que la ingesta terminó realmente.
2. Comprueba que el caso activo es el correcto.
3. Revisa `Activity` por si hubo errores de bulk indexing.
4. Revisa si estás usando un filtro temporal demasiado estrecho.
5. Si acabas de cambiar mappings o parser EVTX, considera reimportar el caso.
