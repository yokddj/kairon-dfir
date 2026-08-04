# Search Timeline, Incident Timeline and Reports

## Search Timeline

Search Timeline is a view inside Search for exploring matching events over time. It is not the curated incident story.

Use it when you need to:

- preserve Search filters while moving from results to time order
- inspect events around a query, host, evidence, artifact type, or time range
- abrir alrededor de un evento
- pivotar desde findings
- crear `key events / bookmarks`
- abrir en Process Graph
- filtrar por host canónico incluyendo aliases consolidados

Legacy `/timeline` and `/cases/{case_id}/timeline` routes redirect to `Search -> Search Timeline` and preserve filters.

MFT/filesystem records are excluded by default to avoid flooding the view. Use `artifact_type=mft` or `include_filesystem_timeline=true` when filesystem timestamps are the intended scope.

## Incident Timeline

Incident Timeline is the curated, reportable story of the incident. It is built from reviewed evidence, marked events, findings, command history, Defender events, selected high-signal artifacts and, for validation cases, optional ground-truth seeds.

It should not be treated as:

- all indexed events
- a raw EVTX timeline
- an automatic complete attack path

Use Incident Timeline to:

- group confirmed or high-confidence activity by phase, host, or time
- add analyst notes
- link evidence back to Search and Execution Story
- export a concise timeline into Reports

## Host identity en Timeline

Si el analista fusiona aliases de un endpoint:

- el filtro por host usa el nombre canónico
- la consulta incluye también `observed_host.name` y aliases asociados
- el detalle del evento puede mostrar `Observed as` cuando el hostname original fue distinto

Esto evita perder eventos históricos al cambiar hostname, pasar de FQDN a NetBIOS o consolidar nombres de colección.

## Key events

Los key events sirven para:

- resaltar hitos
- capturar nota analítica
- seleccionar material para reportes

Si un informe no tiene key events, suele quedar con menos narrativa y menos trazabilidad temporal.

## Report Builder

Permite seleccionar:

- findings
- key events
- Incident Timeline items
- process chains
- notas del analista
- marked events
- Command History suspicious commands
- Execution Story summaries
- Defender events

## Exportes

- `Markdown`: disponible y sigue siendo la fuente editable más simple
- `PDF`: no debe considerarse estable salvo validación específica del despliegue

## Secciones típicas del informe

- summary
- scope
- findings
- Search Timeline highlights / key events
- Incident Timeline
- process chains
- suspicious command history
- execution story summaries
- Defender detections/configuration events where selected
- hosts canónicos y aliases relevantes
- IOCs deduplicados
- notas y recomendaciones

## Host identity en Reports

Cuando el caso usa gestión de aliases:

- el informe debe referirse al `Canonical Host`
- puede listar aliases conocidos para contexto
- los merges manuales deben entenderse como decisión analítica, no como sobrescritura de la evidencia original

El nombre observado original sigue siendo la referencia técnica útil para trazabilidad y debug.

## Limitaciones

- Markdown es el export validado
- no todos los gráficos o visualizaciones complejas se incrustan como imágenes
- secretos y tokens se redactan automáticamente cuando el export path lo soporta
- la calidad narrativa depende de findings y key events bien curados
- el informe no debe sustituir la validación técnica del caso
