# Kairon Navigation — Implementation Architecture (RFC)

*De la arquitectura comprometida a un plan de implementación técnico.*

**Fuente de verdad:** `Kairon Navigation — The Committed Architecture` (documento comprometido, en adelante **"el documento comprometido"** o **CA**). Ese documento fija las decisiones de navegación. Este RFC no las reabre — las convierte en arquitectura de implementación, auditando el código real y definiendo cómo cada pieza del sistema actual (Capability Registry, Readiness, Coverage, Canonical Entities, Search, Timeline, Findings, Reports, soporte Linux/Windows/Memory) encaja en Tier 1 / Tier 2.

**Alcance:** arquitectura funcional y de información. Sin React, sin CSS, sin componentes de librería, sin wireframes. Diseño, no implementación.

**Estado:** propuesta de arquitectura de implementación, pendiente de aprobación antes de codificar.

---

## 1. Auditoría — arquitectura actual vs. arquitectura comprometida

Metodología: se auditó el código real (`frontend/src/components/Sidebar.tsx`, `frontend/src/App.tsx`, `backend/app/services/case_capabilities.py`, `frontend/src/components/workbench/WorkbenchOverview.tsx`, modelos de entidades, rutas de Search/Timeline/Findings/Reports/Host Information), no solo la documentación.

### 1.1 Qué ya existe y coincide con la CA

| Concepto CA | Estado actual | Evidencia |
|---|---|---|
| "Technical Tools" demotado, separado de Investigation | **Ya implementado, casi textual** | `Sidebar.tsx` ya tiene una sección `TECHNICAL_TOOL_ITEMS` (Artifact Views, Validation Matrix, Debug Export) visualmente separada de `INVESTIGATION_ITEMS`. |
| Investigation (Tier 1) como grupo fijo | **Ya implementado** | `INVESTIGATION_ITEMS` en `Sidebar.tsx`: Overview, Evidence, Host Information, Search, Timeline, Incident Timeline, Detections, Findings, Reports — 9 ítems fijos, no derivados de registry. |
| Un mecanismo único de "Home" reutilizable por superficie | **Ya implementado al 80%** | `WorkbenchOverviewPage.tsx` + `WorkbenchOverview.tsx` es un único componente parametrizado por `workbenchId`, ya usado para `/w`, `/l`, `/m`. Renderiza header, quick actions, coverage por dominio, actividad reciente y warnings — exactamente la forma que CA §01 pide para Tier 2. |
| Detections ≠ Findings, con promoción explícita | **Ya implementado, coincide con CA §03** | `DetectionResult` y `Finding` son modelos y páginas separados; `Finding.detection_ids` enlaza, `CreateFindingDialog` promueve. Es la misma semántica que describe CA ("señal automática" vs "juicio del analista"). |
| Prefijos de ruta compactos por superficie | **Ya implementado** | `/cases/:caseId/w/...`, `/l/...`, `/m/...` — exactamente el patrón que CA asume para que "una superficie nueva cueste una línea". |
| Redirects de compatibilidad de un solo salto | **Ya implementado y testeado** | `App.tsx` tiene una familia de componentes de redirect (`LegacyCaseParamRedirect`, `LegacyMemoryRootRedirect`, etc.) con tests de contrato que verifican que son de un solo salto y terminan en rutas canónicas. Reutilizable como mecanismo de migración para este RFC. |
| Host Information como página Tier 1 con espacio para crecer | **Ya implementado, cumple exactamente CA §08** | `HostInformationPage.tsx` ya agrupa Host Facts en slots (Identity/OS/Platform/…) y Host User Inventory, sin haber "salido" de Tier 1. |

### 1.2 Qué existe pero contradice la forma de la CA

| Concepto CA | Estado actual | Problema |
|---|---|---|
| **Separación estricta Tier 1 / Tier 2** (CA §04, la separación "de la que todo depende") | **Violada hoy** | `Sidebar.tsx`, sección "Investigation Surfaces" (líneas ~446-478), no renderiza una línea por superficie: renderiza el árbol completo **Workbench → Domain → Capability** dentro del rail permanente (`buildWorkbenchTree()`), con expand/collapse y persistencia en `localStorage`. Hoy son solo 9 capabilities, así que el efecto visual es leve — pero la *forma* es exactamente el anti-patrón que CA §04 dice que hizo de Memory un grupo de 11 ítems: profundidad de superficie apilada en el rail global. Si el Capability Registry crece (ver §1.4), este árbol reproduce el problema a escala completa. |
| Un solo lugar de profundidad por superficie (Home → domains → capabilities) | **Fragmentado en dos lugares para Memory** | Memory tiene *dos* mecanismos de profundidad simultáneos y no unificados: (a) el árbol Workbench→Domain→Capability del sidebar (3 capabilities hoy), y (b) `MemoryWorkspace.tsx`, que renderiza una tira de tabs fija de **11 ítems** (`MEMORY_TABS` en `frontend/src/lib/memoryWorkspaceState.ts`: Overview, Processes, Graph, Network, Modules & DLLs, Handles, Suspicious Memory, VADs, System, Runs, Raw Observations) a nivel de evidencia individual. Este es probablemente el origen real del diagnóstico "Memory es un grupo de 11 ítems permanente" citado en CA §00 — solo que vive en un inspector de evidencia, no en el sidebar. No debe borrarse (es funcionalmente el inspector de un memory image), pero su relación con el patrón "domain tabs" de Tier 2 no está resuelta. |
| Breadcrumb derivado de la ruta, distingue Tier 1 de Tier 2 | **No existe como mecanismo automático** | `InvestigationBreadcrumbs`/`InvestigationContext.tsx` existen, pero cada página pasa un array `breadcrumbs` hardcodeado a mano; si no lo pasa, cae a un fallback genérico de 3 niveles. Solo 5 páginas lo usan. `WorkbenchOverviewPage` (la Home de superficie) **no tiene breadcrumb**. Sin derivación automática, no hay garantía de que Tier 1 y Tier 2 se lean como raíces distintas, que es justamente lo que CA §04 exige ("must be visually and navigationally distinct"). |
| Iconografía por superficie como dato del registry | **Hardcodeada en el componente** | `WorkbenchOverview.tsx`: `const Icon = workbench.id === "memory" ? Cpu : workbench.id === "linux" ? ShieldCheck : HardDrive`. Funciona para 3 superficies; no escala a 9+ sin tocar código de componente cada vez — contradice el principio "nunca listas hardcodeadas" (CA implícito, y explícito en la práctica de este repo, ver `docs/architecture/information-architecture.md`). |

### 1.3 Qué no existe todavía

| Pieza requerida por este RFC | Estado |
|---|---|
| **Surface Registry declarativo** (CA lo asume implícitamente al decir "Investigation Surfaces — flat, one line per surface present") | **No existe.** Hoy las "superficies" (workbenches) son un *side effect* calculado en tiempo de request a partir de qué valores de `platform`/`evidence_domain` aparecen en `CAPABILITY_REGISTRY`, no una lista declarada con label/icono/descripción/orden propios. El orden de superficie está hardcodeado como diccionario en Python (`{"windows": 10, "linux": 20, "macos": 30, "memory": 40}`). |
| **Vocabulario de Domain controlado** (CA §03: "Access · Execution · Persistence · Software · Logs · Files · Network" como vocabulario compartido) | **No existe.** `domain` es un string libre por capability, sin enum ni registry propio. Hoy solo existen 5 valores en uso (`execution`, `persistence`, `access`, `software`, `network`), y ninguno de `Files`, `Logs` existe todavía como dominio. |
| **Health como concepto distinto de Readiness** | **No existe a nivel de capability/superficie.** "Health" en el código de hoy es infraestructura (OpenSearch, colas, disco) — un dominio completamente distinto, no wireado al Capability Registry. |
| **Estado `planned`/`not_implemented` en el registry** | **No existe.** El único valor de `availability` usado hoy es `"shipped"`. No hay forma de que el registry declare "esta capability existe conceptualmente pero aún no tiene backend" — necesario para el estado "Not implemented" pedido en §14. |
| **Entidad canónica genérica** (Host/User/Process/File/Service/Package/Connection/ScheduledTask/AuthenticationEvent/BrowserSession) | **No existe como capa transversal.** Ver §7 — existen dos implementaciones reales y sólidas del *patrón* (Host, Memory Process) pero no generalizadas al resto de tipos. |
| **Señal de capability habilitada/deshabilitada al frontend** (para Memory como capability opcional) | **No existe.** `docs/architecture/backlog.md` ya lo tiene como ítem P1 abierto ("Frontend capability state") — este RFC depende de él (ver §18). |

### 1.4 El hallazgo que más condiciona el roadmap

El Capability Registry hoy tiene **9 entradas totales** (3 Windows, 3 Linux, 3 Memory) repartidas en 5 valores de `domain`. Pero la ingesta real ya cubre decenas de familias de artefactos por plataforma (EVTX, Prefetch, Registry, MFT/USN, Shellbags, USB, WMI, BITS, Defender, SRUM, Jumplists, Autoruns, Amcache/Shimcache para Windows; auth, syslog, audit, shell history, cron, systemd, SSH, sudoers, packages, red, OS info para Linux — ver `docs/architecture.md`, `docs/linux-support.md`). Esos artefactos solo son alcanzables hoy vía Search / Artifact Views genéricos, no vía capability dedicada.

**Consecuencia directa para este RFC:** implementar la navegación comprometida no es solo mover componentes — requiere ampliar sustancialmente `CAPABILITY_REGISTRY` (más domains, más capabilities por domain) para que la página Tier 2 de cada superficie tenga contenido real que mostrar en sus domain tabs. Este trabajo de registro está acoplado al "Linux parity program" y a la expansión de dominios Windows ya identificados como *Strategic initiative* en `docs/roadmap.md`. Se refleja en el Roadmap (§17) como fases explícitas, no como un efecto colateral silencioso.

### 1.5 Qué debe eliminarse, moverse o reutilizarse (resumen)

- **Eliminar (de forma):** el renderizado del árbol completo Workbench→Domain→Capability *dentro del rail global* en `Sidebar.tsx`. Se colapsa a una línea por superficie presente (§2).
- **Mover:** toda la lógica de `buildWorkbenchTree()`, `DomainGroup`, `CapabilityItem` no se descarta — se **traslada** conceptualmente de "árbol de sidebar" a "contenido de la página Surface Home / domain tabs" (§4, §6), donde ya casi encaja tal cual.
- **Reutilizar tal cual:** `WorkbenchOverview.tsx` como base de Surface Home; el patrón entidad+observación de `CaseHost`/`HostFact` y `MemoryProcessEntity` como base de Canonical Entities (§7); el patrón de redirects de un solo salto para la migración (§17); `InvestigationBreadcrumbs`/`InvestigationContext` como base del breadcrumb (una vez hecho derivable de ruta/registry).
- **Decisión pendiente, no eliminar todavía:** el destino de `MemoryWorkspace`/`MEMORY_TABS` (§4.4, marcado explícitamente como *decisión pendiente*).

---

## 2. Arquitectura completa de navegación

Esta sección traduce CA §01 a mecánica de implementación concreta sobre el código auditado.

### 2.1 Tier 1 — Global Rail

Composición (ya casi correcta hoy, ver §1.1/§1.2):

```
Case
  Cases                    — ya existe (link fijo "Cases" en Sidebar.tsx)

Investigation
  Overview, Evidence, Host Information, Search, Timeline,
  Incident Timeline, Detections, Findings, Reports
                           — ya existe (INVESTIGATION_ITEMS), sin cambios de fondo

Investigation Surfaces     — CAMBIA DE FORMA: hoy es un árbol de 3 niveles,
                              pasa a ser una línea por surface_registry entry
                              presente en el caso (ver §2.2)

Technical Tools
  Artifact Views, Validation Matrix, Debug Export
                           — ya existe (TECHNICAL_TOOL_ITEMS), sin cambios
```

**El único cambio estructural real en Tier 1** es la sección "Investigation Surfaces": pasa de renderizar un árbol expandible de Workbench→Domain→Capability a renderizar **una fila por surface** (label + icono + badge de estado agregado, si acaso), fuente de datos = Surface Registry (§2.2), no `CAPABILITY_REGISTRY` recorrido en profundidad. Click → navega a la Surface Home (Tier 2); no expande in-place.

Esto es exactamente la operación que CA §07 describe como "la única modificación de esta propuesta si se prefiriera la versión de hub único": aquí no colapsamos a un hub, mantenemos una línea por surface (decisión ya tomada por CA §07 — "Agreed. Per-surface entries…"), pero sí colapsamos la profundidad que hoy se renderiza de más.

### 2.2 Surface Registry (nueva pieza de infraestructura)

No existe hoy (§1.3). Se define como una capa **backend**, hermana de `CAPABILITY_REGISTRY`, no un reemplazo:

- Identidad: `id` (`windows`, `linux`, `memory`, `cloud`, `containers`, `mobile`, `network`, `email`, `macos`, …).
- `label`, `icon` (referencia simbólica, no el asset — el icono real lo resuelve el frontend a partir del id, pero la *decisión* de qué id usar deja de estar en un ternario de componente).
- `platform` / `evidence_domain` de correspondencia con `CAPABILITY_REGISTRY` (reutiliza el mismo eje que ya existe, no inventa uno nuevo).
- `nav.order` (reemplaza el diccionario hardcodeado `{"windows": 10, "linux": 20, ...}`).
- `overview_route` (ya existe como campo calculado hoy — se vuelve declarado).
- `status`: `shipped | preview | planned` (necesario para representar Memory como *Preview* per `docs/roadmap.md`, y para futuras superficies anunciadas pero no activas).

`CAPABILITY_REGISTRY` sigue siendo dueño de las capabilities; cada entrada referencia un `surface_id`. La sección "Investigation Surfaces" del rail se genera iterando el Surface Registry filtrado por presencia real de evidencia en el caso (mecanismo de "presente en el caso" que **ya existe** hoy vía `platforms`/`evidence_domains` en la respuesta del registry — se reutiliza, no se reinventa).

### 2.3 Tier 2 — Surface Home

Ver detalle completo en §4. En términos de navegación: es el **único** lugar donde vive la profundidad Domain → Capability. La URL raíz de cada superficie (`/w`, `/l`, `/m`, futuros `/cl`, `/co`, …) sigue siendo, tal como hoy, la Surface Home.

### 2.4 Breadcrumbs

Se define como **derivado de ruta + registry**, no como prop manual por página:

- Nivel 1: raíz fija (`Overview` del caso, o el nombre de la superficie si se está en Tier 2) — distingue visualmente "estoy en una lente global" de "estoy dentro de una superficie", que es exactamente la exigencia de CA §04.
- Nivel 2 (solo en Tier 2): Domain activo, resuelto contra `nav.parent`/`domain` del capability actual.
- Nivel 3 (solo en Tier 2, si aplica): Capability activa.
- Nivel 4 (solo en páginas de entidad, §7): la entidad abierta (p. ej. un host, un proceso).

Esto reemplaza el prop `breadcrumbs` hardcodeado; `InvestigationBreadcrumbs` se conserva como componente de render, pero su input pasa a calcularse a partir de la ruta activa y el registry, no a mano por cada página.

### 2.5 Historial, back navigation, deep links

- El mecanismo de query-string ya presente en Search/Artifact Explorer (`useSearchParams`) se mantiene como estándar para estado filtrable — no se toca, ya cumple con lo que CA implícitamente requiere (URLs que preservan contexto).
- `canonicalRoutes.ts` se amplía (no se reemplaza) con builders para cada nueva Surface Home / domain / capability, siguiendo el mismo patrón ya validado.
- Los redirects de un solo salto (`LegacyCaseParamRedirect` y familia) son el mecanismo de migración: cuando una capability cambia de ruta como parte de este RFC, se registra un redirect, nunca se elimina el bookmark en caliente. Ya hay tests de contrato que impiden cadenas de redirect — se reutilizan tal cual.
- Back navigation: al colapsar el árbol del sidebar a una línea por superficie, la navegación "atrás" desde una capability profunda vuelve naturalmente a la Surface Home (una página real con su propia entrada de historial), no a un estado de árbol expandido/colapsado en el sidebar — una simplificación real del modelo de historial actual.

### 2.6 Qué permanece visible siempre / qué nunca aparece en el sidebar

- Permanece siempre: Tier 1 completo (Case, Investigation, Investigation Surfaces como lista de líneas, Technical Tools).
- Nunca en el sidebar: nombres de artefacto o de herramienta de parsing (EVTX, Prefetch, Registry, Volatility, SQLite, Plaso, KAPE) — auditado: hoy el sidebar **ya no** los expone directamente (los `INVESTIGATION_ITEMS`/`TECHNICAL_TOOL_ITEMS` están libres de esto); el riesgo está en capabilities futuras mal tituladas al crecer el registry (§18).
- Nunca en el sidebar: profundidad de domain/capability de una superficie — vive exclusivamente en su Surface Home.

---

## 3. Arquitectura de páginas

Tabla de páginas Tier 1 + páginas estructurales, con estado actual señalado explícitamente.

| Página | Objetivo | Datos | Relación con otras páginas | Qué NO debe contener |
|---|---|---|---|---|
| **Overview** (ya existe: `CaseOverviewPage.tsx`) | "¿Cuál es el estado de todo el caso?" | Agregado cross-surface: evidencia, hosts, procesamiento, findings recientes | Enlaza a cada Surface Home y a las lentes globales | Ninguna vista específica de una sola plataforma |
| **Host Information** (ya existe, ver §12) | "¿Qué sabemos de este host?" | Host Facts resueltos + Host User Inventory | Referenciado desde Overview, Search (pivot a host), Reports | Detalle de artefactos crudos — eso es Search/Artifact Views |
| **Search** (ya existe, ver §8) | Encontrar algo en cualquier evidencia | Eventos normalizados indexados | Alimenta Timeline, Findings, entidades | Vistas especializadas de una sola familia — eso es Artifact Views |
| **Timeline** (ya existe, ver §9) | Orden cronológico de lo indexado | Search scoped por tiempo | Vista de Search, no destino independiente de datos | Narrativa curada — eso es Incident Timeline |
| **Incident Timeline** (ya existe, ver §9) | Historia reportable del incidente | Selección curada: findings, eventos marcados, command history, etc. | Alimenta Reports | Todos los eventos indexados sin curar |
| **Detections** (ya existe, ver §10) | Señales automáticas | `DetectionResult` por regla | Promueve a Findings | Juicio analítico ya confirmado — eso es Findings |
| **Findings** (ya existe, ver §10) | Conclusiones del analista | `Finding`, enlazado a evidencia/host/detección | Alimenta Reports; referenciado desde Search/Artifact Views/Memory | Señales sin revisar |
| **Reports** (ya existe, ver §11) | Producir el entregable | Selección de findings/timeline/eventos clave | Consume Findings + Incident Timeline + Host Information | Edición de evidencia; generación de hallazgos nuevos |
| **Surface Home** (Linux/Windows/Memory ya existen; patrón genérico, ver §4) | "¿Qué mostró este tipo de evidencia?" | Coverage/Readiness por domain, quick actions, actividad reciente | Punto de entrada único a la profundidad de una superficie | Cualquier dato de otra superficie o del caso completo |
| **Artifact Views** (ya existe, Technical Tool) | Revisar una fuente concreta con columnas especializadas | Eventos filtrados por `artifact.type` | Alcanzable desde Search y desde capabilities sin página dedicada aún | No es un segundo motor de búsqueda global |
| **Validation Matrix / Debug Export** (ya existen, Technical Tools) | QA de la herramienta, no del caso | Estado de parsers/exports | — | Hallazgos investigativos |

---

## 4. Arquitectura de Surface Home (genérica y reutilizable)

Se toma `WorkbenchOverview.tsx` como línea base real (§1.1) y se completa hasta cubrir exactamente lo pedido por CA + este RFC, de forma genérica para cualquier `surface_id` presente o futuro (Linux, Windows, Memory, Cloud, Containers, Email, Network, Mobile, macOS).

### 4.1 Secciones de la página (orden fijo, ya validado por la implementación actual)

1. **Header de superficie** — icono (desde Surface Registry, §2.2), label, stats agregadas (hosts / evidencia / estado de procesamiento). *Ya existe como `PlatformHeader`.*
2. **Readiness / Coverage global de la superficie** — resumen agregado antes de bajar a domain. *Ya existe parcialmente vía `coverage.status_counts`; se formaliza como widget reutilizable (§13).*
3. **Quick Actions** — acciones destacadas, generadas desde `overview.quick_action`/`featured` de las capabilities de esa superficie. *Ya existe.*
4. **Domain tabs** — navegación horizontal por domain (CA §01: `[ Access ]  Execution  Persistence  Software  Logs  Files  Network`). **Cambio respecto a hoy:** hoy esto es una grilla de `CoverageCard` por domain, no una barra de tabs horizontal; se reformula como tabs horizontales con la misma fuente de datos (`workbench.domains`), sin perder el badge de readiness por domain que ya existe en la card.
5. **Capabilities del domain seleccionado** — lista/cards de capability dentro del tab activo, cada una con su Coverage/Readiness/Health widget (§6, §13).
6. **Recent Findings / Recent Activity** — *ya existe* (`RecentActivityPanel`), scoped a evidencia de esa superficie.
7. **Warnings** — *ya existe* (`WarningPanel`) — bloqueadores de investigación (procesamiento fallido, plugins degradados, host de memoria sin asignar, etc.).
8. **Panel de extensión específico de superficie (opcional)** — el patrón ya está validado por `MemoryImagesPanel`, que se muestra solo si la superficie lo requiere. Esto es lo que permite que Memory necesite un panel adicional (imágenes de memoria) sin convertir el componente en un caso especial: es una extensión declarada, no una bifurcación de código por `if platform === "memory"` esparcida por la página.

### 4.2 Genericidad

El componente no debe bifurcar por nombre de superficie salvo en el punto de extensión (4.1.8), que ya es el único lugar donde el código actual distingue Memory — y ahí seguirá siendo el único. El resto (header, quick actions, domain tabs, capabilities, actividad, warnings) es 100% dirigido por el payload del registry, tal como ya documenta `docs/architecture/information-architecture.md` ("Workbench overview rendering is generic... does not branch into Windows/Linux/Memory capability lists").

### 4.3 Reutilización explícita para superficies futuras

Cloud, Containers, Email, Network, Mobile, macOS **no requieren una Home nueva** — requieren: una entrada en Surface Registry, entradas nuevas en `CAPABILITY_REGISTRY` con su `domain`/`platform`/`evidence_domain`, y (si aplica) un panel de extensión 4.1.8 propio. Cero cambio de componente de página.

### 4.4 Decisión pendiente: `MemoryWorkspace` / `MEMORY_TABS`

El tab-strip de 11 ítems por evidencia de memoria (§1.2) es un **inspector de una evidencia concreta**, no la Surface Home de Memory. No se decide aquí si:

(a) sus 11 tabs deben re-mapearse 1:1 a domains del vocabulario compartido (Execution, Network, Files, …) y perder su identidad de "tab de plugin de Volatility", o
(b) debe seguir existiendo como una vista de "Evidence Inspector" independiente del árbol Domain→Capability, alcanzable *desde* una capability de Memory Surface Home pero con su propia navegación interna.

Se registra como **decisión pendiente** (§ver también Roadmap Fase 3) porque tiene implicaciones de UX específicas de memoria forense que exceden el alcance de este RFC de navegación general.

---

## 5. Arquitectura de Domains

### 5.1 Qué es un Domain hoy vs. qué debe ser

Hoy `domain` es un string libre sin catálogo (§1.3). Se formaliza como una lista controlada, análoga en tratamiento al Surface Registry pero **compartida entre superficies** (ese es su valor: "Persistence vive en la tercera pestaña" es una lección que sirve para Linux, Windows y todo lo futuro — CA §03):

- `id` (`access`, `execution`, `persistence`, `network`, `files`, `logs`, `software`, `memory`, …), `label`, `nav.order` global de dominio (orden por defecto de los tabs cuando una superficie tiene varios).

### 5.2 Cómo aparecen

Como tabs horizontales dentro de una Surface Home (§4.1.4), **solo los domains que tienen al menos una capability visible en esa superficie para ese caso** — el mismo criterio de "presente, no taxonomía completa" que CA aplica a Investigation Surfaces (CA §05).

### 5.3 Cómo navega el analista

Domain tab → lista de capabilities de ese domain → click en capability → Capability Page (§6). El domain nunca es un destino con URL propia más allá de un query/segmento de selección de tab dentro de la Surface Home; no es una "página" independiente con su propio breadcrumb-root.

### 5.4 Cómo cambian entre superficies / cómo reutilizan componentes

El *mismo* componente de tab bar y el *mismo* componente de capability-card se reutilizan sin importar la superficie — la única variable es qué domains y capabilities trae el payload del registry para ese `surface_id` + caso. Esto ya es cierto hoy para el patrón de coverage-card (§1.1); el cambio es de layout (grid → tabs), no de arquitectura de datos.

---

## 6. Arquitectura de Capabilities

### 6.1 Qué es una capability (ya definido, se reutiliza y se completa)

Ya existe una forma sólida (`CAPABILITY_REGISTRY`, §1 auditoría): `id`, `surface_id` (hoy `platform`), `domain`, `title`, `route`, `artifact_families`, metadata de nav/overview/search. Se completa con lo que falta para cubrir los estados pedidos en este RFC:

- `availability`: se extiende de solo `"shipped"` a `shipped | preview | planned` — necesario para poder renderizar un estado "Not implemented" (§14) sin hardcodear excepciones en frontend.
- Referencia a **canonical entity type** cuando aplique (§7) — hoy la aproximación más cercana es `artifact_families`; se añade un campo explícito de qué entidad canónica resuelve esta capability, cuando exista una.

### 6.2 Representación en pantalla (Capability Card)

Genérica para cualquier capability (Authentication, Running Processes, Installed Packages, Autoruns, Memory Process Inventory, Network Connections, …), compuesta de los widgets reutilizables de §13:

- Título + domain al que pertenece.
- **Coverage widget** (cuántos registros, de qué familias de artefacto).
- **Readiness widget** (reutiliza los 5 estados ya implementados: `not_applicable`, `not_collected`, `empty`, `has_data`, `degraded` — ver reconciliación con Estados Comunes en §14).
- **Health widget** (nuevo — ver §14.3, marcado como decisión de backend pendiente sobre su fuente exacta).
- Acción principal (`quick_action`, ya existe).
- Empty / Loading / Error state (§14).

### 6.3 Genericidad

Ninguna Capability Card se diseña pensando en una plataforma concreta. La prueba de diseño: la misma card debe poder representar tanto "Authentication" (Linux) como "Memory Process Inventory" (Memory) como "Autoruns" (Windows, hoy no registrado, ver §1.4) sin cambiar de forma — solo cambia el dato.

---

## 7. Arquitectura de entidades canónicas

### 7.1 Punto de partida real (no se inventa desde cero)

La auditoría (§1.3) encontró que Kairon **ya implementó dos veces**, de forma independiente, el mismo patrón de entidad canónica:

1. **Host**: `CaseHost` + `CaseHostAlias` + `CaseHostIdentityAudit`, con merge/split explícito y auditoría.
2. **Host Facts / Host Users**: un patrón genérico de **observación → hecho resuelto**, ya documentado como intencionalmente genérico ("Reusable infrastructure for future consumers... this endpoint does not assume `host.timezone` is the only fact_type that will ever exist" — comentario literal en `routes_host_facts.py`).
3. **Memory Process**: `MemoryProcessEntity` + `MemoryProcessObservation` + `MemoryProcessEdge`, con reglas de identidad (`(case_id, evidence_id, pid, create_time)`), precedencia de merge por campo y clasificación de árbol (root/orphan/cycle) — documentado extensamente en `docs/memory_process_model.md`.

Estas dos implementaciones, hechas para dominios distintos (identidad de host sobre SQL; identidad de proceso sobre OpenSearch) y sin coordinarse entre sí, llegaron al **mismo patrón**: entidad canónica + observaciones crudas preservadas + reglas de identidad + reglas de precedencia de merge. Esa convergencia es la señal más fuerte de que es el patrón correcto para generalizar, no una casualidad a ignorar.

### 7.2 Generalización propuesta

Un tipo de entidad canónica (Host, User, Process, File, Service, Package, Connection, Scheduled Task, Authentication Event, Browser Session, …) se define, siguiendo el patrón ya probado, como:

- **Identidad determinista**, con jerarquía de identidad fuerte → identidad por nombre → identidad débil marcada explícitamente (`identity_provisional`) — el mismo esquema de tres niveles que ya usa Memory Process.
- **Observaciones preservadas**, nunca descartadas — cada entidad es la fusión de N observaciones de distintos artefactos/parsers, con procedencia (`sources`) visible.
- **Reglas de precedencia de merge explícitas por campo**, documentadas por tipo de entidad (igual que la tabla de precedencia de `docs/memory_process_model.md`).
- **Nunca fusiona identidades en conflicto silenciosamente** — un conflicto se marca como *finding* de la propia entidad (`name_conflict`, etc.), no se resuelve arbitrariamente.

### 7.3 Cómo se abren, inspeccionan, relacionan y vuelven atrás

- **Abrir:** desde una Capability Card (§6.2) o desde un pivot de Search (§8) — nunca desde un artefacto crudo directamente; el artefacto resuelve a una entidad y se navega a la entidad.
- **Inspeccionar:** una página de detalle de entidad (Entity Header + observaciones, reutilizando el patrón de `ProcessDetailModal`/`HostInformationPage` ya existentes) muestra el estado resuelto arriba y la procedencia (observaciones individuales) disponible pero secundaria.
- **Relacionar:** las relaciones entre entidades (host↔proceso, proceso↔archivo, proceso↔conexión) se modelan como edges explícitos, igual que `MemoryProcessEdge` — no como coincidencia de texto libre entre campos de eventos (que es lo que hace hoy el pivot de Search, §7.4).
- **Volver atrás:** desde una entidad, el breadcrumb (§2.4) sube a la capability/domain de origen; desde ahí, a la Surface Home.

### 7.4 Relación con el estado actual de Search (tensión real, no oculta)

El pivot de entidad de Search hoy (`/api/cases/{case_id}/search/entity`) es una traducción de "tipo + valor" a un filtro de campo (host/user/process_name/file_path/domain/ip) sobre el índice de eventos — **no** una resolución contra una entidad canónica real, salvo para Host (donde sí existe resolución real) y para Memory Process (donde sí existen edges reales). Este RFC no propone migrar el motor de Search fuera del índice de eventos (`Search/Timeline` está marcado como *completado* en `docs/roadmap.md` y no se reabre) — propone que la **capa de resolución de entidades** (§7.2) se generalice y se interponga entre Search y las páginas de entidad, igual que ya lo hace Host Facts hoy. Search sigue consultando el índice de eventos; lo que cambia es que un pivot desde Search puede aterrizar en una página de entidad resuelta cuando existe una, no solo en un filtro de campo.

---

## 8. Search

Search **ya existe y ya funciona** (`Search.tsx`, `routes_search.py`) — no se rediseña su motor. Se diseña su relación con entidades canónicas y superficies.

- **Consume:** el índice de eventos normalizados (sin cambio) para la búsqueda en sí; la capa de entidad (§7) para pivotes que aterrizan en una página de entidad en lugar de un filtro adicional.
- **Nunca debe:** exponer nombres de artefacto/herramienta como la forma primaria de navegación de resultados (hoy ya usa `artifact.type` como filtro técnico, no como taxonomía de navegación — correcto, se mantiene).
- **Filtros:** los ya existentes (caso, evidencia, host, tiempo, artifact type, parser, backend variant, markings, riesgo) se mantienen; se añade `domain` y `surface` como filtros de alto nivel, alimentados por el mismo Capability Registry (`search.default_filters`/`search.facets`, que **ya existe** parcialmente — Phase 3 de `docs/capability-registry.md`).
- **Facetas:** ya derivadas del registry (`search.facets.workbench/domain/capability`) — se renombran conceptualmente a `surface`/`domain`/`capability` para consistencia terminológica con este RFC, sin cambio de mecanismo.
- **Pivoting:** field-value pivot (hoy) se conserva para campos sin entidad resuelta; pivot-a-entidad (§7.4) se añade como camino adicional, no como reemplazo.
- **Navegación:** Search sigue siendo Tier 1 — nunca se convierte en una vista scoped a una sola superficie.

---

## 9. Timeline / Incident Timeline

Ambas **ya existen y ya están correctamente separadas** en el código (`TimelinePage.tsx` vs `IncidentTimelinePage.tsx`) siguiendo exactamente la distinción de CA §04 ("Raw and broad vs. curated and narrative"). Este RFC no cambia su relación de datos.

- **Timeline:** vista de Search ordenada por tiempo (ya es así); consume el índice de eventos, con exclusión por defecto de MFT/filesystem (ya implementado) para evitar inundar la vista.
- **Incident Timeline:** narrativa curada (ya es así); consume findings, eventos marcados, command history y fuentes de alta señal — no todos los eventos indexados.
- **Enlace entre ambas:** ya existe (`around-event`, `around-finding`) — se mantiene como mecanismo de pivote bidireccional.
- **Cambio de este RFC:** ninguno funcional. Solo su posición en Tier 1 y su breadcrumb-root (§2.4) cambian para reflejar que ambas son lentes globales, nunca vistas de una superficie.

---

## 10. Findings

Detections y Findings **ya están modelados exactamente como pide CA §03** (§1.1). Este RFC formaliza lo existente en vez de rediseñarlo:

- **Detections:** señal automática (`DetectionResult`), un registro por match de regla/evento.
- **Findings:** juicio del analista (`Finding`), con workflow de estado ya implementado (`draft/review/confirmed/false_positive/archived` según `docs/findings-notes.md`, o el workflow de correlación `new→triaged→…` según el modelo — ambos coexisten hoy, ver nota de coherencia en Riesgos §18).
- **Promoción:** ya implementada (`CreateFindingDialog`, `Finding.detection_ids`) — se mantiene como el único camino Detection→Finding, nunca fusión automática.
- **Relación con entidades:** un Finding ya enlaza a evidencia, host, artifact id/family, evento origen (`docs/findings-notes.md`) — se extiende (no se reemplaza) para enlazar también a una entidad canónica (§7) cuando exista, en vez de solo al artefacto/evento crudo que lo originó.
- **Prioridades:** severidad ya existe (`info/low/medium/high/critical`); no se propone un sistema nuevo.

---

## 11. Reports

Reports **ya existe y ya está marcado como completado** en `docs/roadmap.md`. Este RFC define solo su lugar en la navegación, no su contenido:

- **Flujo:** Tier 1 → `Reports` → selección de fuentes (findings, key events, incident timeline, process chains, notas) → preview → export. Ya es así hoy (`CaseReportsPage.tsx`, `routes_reports.py`).
- **Estados:** draft → preview → exportado, ya modelado (`case_report.py`).
- **Relación con entidades:** cuando Reports cita un host/proceso/entidad, debe citar la entidad canónica resuelta (§7), no el artefacto crudo — hoy ya tiende a esto para Host ("el informe debe referirse al Canonical Host", `docs/timeline_reports.md`); se generaliza el mismo principio a otras entidades a medida que existan.
- **Nunca:** Reports no genera hallazgos nuevos ni edita evidencia — es un consumidor puro de Findings/Timeline/Host Information.

---

## 12. Host Information

Host Information **ya existe** como página Tier 1 con Host Facts + Host User Inventory (§1.1, §7.1). Este RFC amplía su camino de crecimiento, exactamente como lo deja abierto CA §08, sin sacarlo de Tier 1:

- **Forma de crecimiento:** adopta el mismo patrón Home + domain-tabs que usa Tier 2 (CA §08 lo permite explícitamente: "the Home-page-plus-domain-tabs shape... was never actually specific to platform surfaces"). Tabs propuestos, siguiendo la lista ya abierta por CA y el modelo `HostFact`/`HostUserFact` ya existente: **Identity, Users, Network, Storage, Services, Software, Hardware, Virtualization**.
- **Fuente de datos:** cada tab consume la capa de Host Facts genérica (`fact_type` ya es un parámetro genérico del endpoint actual — trivial de extender a nuevos `fact_type`s sin tocar el contrato de API).
- **Se mantiene:** una sola línea en el rail, una sola URL raíz (`/host-information`), cross-platform por definición — nada de esto cambia.
- **Relación con Surface Home:** Host Information nunca duplica contenido de una Surface Home; una Surface Home puede *enlazar* a Host Information para el host relevante, nunca al revés en profundidad.

---

## 13. Componentes reutilizables (nivel de arquitectura de información, no de implementación)

Se listan por lo que deben hacer, no por cómo se construyen. Varios ya existen con otro nombre (se indica su análogo actual).

| Componente | Función | Análogo ya existente |
|---|---|---|
| **Page template — Surface Home** | Header + quick actions + domain tabs + capabilities + actividad + warnings, genérico por `surface_id` | `WorkbenchOverview.tsx` (§4) |
| **Page template — Entity Detail** | Header de entidad + observaciones + relaciones + acciones | Parcial: `HostInformationPage.tsx`, `ProcessDetailModal` |
| **Capability Card** | Título, domain, Coverage/Readiness/Health, acción principal, estado | Parcial: `CoverageCard` en `WorkbenchOverview.tsx` |
| **Coverage widget** | Cuántos registros / qué familias de artefacto | `coverage.status_counts` (backend) ya existe como dato; falta el widget dedicado |
| **Readiness widget** | Badge de uno de los estados de §14 | Ya existe como badge de estado en coverage cards |
| **Health widget** | Estado de salud de pipeline/procesamiento para esa capability/superficie | No existe (§14.3, decisión pendiente sobre su fuente) |
| **Entity header** | Identidad resuelta + badges de confianza/hallazgos | `MemoryProcessEntity` ya expone estos campos (`confidence`, `findings`) — falta el componente visual genérico |
| **Breadcrumbs** | Deriva de ruta + registry (§2.4) | `InvestigationBreadcrumbs` (render), falta la derivación automática |
| **Tables / Split views / Drawers / Inspector** | Listas de registros con detalle lateral o modal | Ya extensamente usados en `Search.tsx`, `ArtifactExplorer.tsx`, `MemoryEvidencePage.tsx` — se consolidan como vocabulario común, no se reinventan |
| **Action bars / Context panels** | Acciones contextuales (crear finding, abrir en Search, etc.) | `InvestigationContext.tsx` ya es esto — se generaliza su uso a todas las páginas Tier 1/Tier 2 |
| **Filters** | Filtros compartidos entre Search/Capability pages | Ya existen en Search; se exponen como vocabulario reutilizable para capability pages nuevas |

**Regla de reutilización:** ningún componente nuevo se diseña específico de una plataforma. Si un widget necesita una rama `if surface === "memory"`, esa rama debe vivir en el punto de extensión declarado (§4.1.8), no dispersa por el componente.

---

## 14. Estados comunes

### 14.1 Estados pedidos por este RFC

`Loading, Empty, Partial, Blocked, Ready, Error, Unavailable, Permission denied, Not implemented`

### 14.2 Reconciliación con lo que ya existe

El backend ya implementa 5 estados de Readiness (§1.3): `not_applicable`, `not_collected`, `empty`, `has_data`, `degraded`. Mapeo propuesto (sin romper el contrato actual — se añade, no se renombra en backend):

| Estado UI (§14.1) | Origen |
|---|---|
| Ready | `readiness = has_data` |
| Empty | `readiness = empty` o `not_collected` (con copy distinto: "sin evidencia todavía" vs "no hay registros en la evidencia presente") |
| Partial | `readiness = degraded` |
| Unavailable | `readiness = not_applicable` (la superficie/domain no aplica a este caso) |
| Not implemented | **nuevo** — requiere `availability = planned` en el registry (§6.1); no existe hoy |
| Blocked | **nuevo** — deriva de `overview.warnings` ya existente (bloqueadores de investigación), no de readiness |
| Loading | Estado de carga de red estándar, sin dato de backend |
| Error | Fallo de red/API, sin dato de backend |
| Permission denied | **no soportado hoy** — el modelo de roles actual (Administrator/Standard, ver `docs/roadmap.md`) no tiene permisos por capability; se marca como *decisión pendiente*, no se implementa un sistema de permisos nuevo en este RFC (§18) |

### 14.3 Health — decisión de diseño pendiente

Este RFC pide un widget de Health por capability/superficie, pero el backend no tiene ese concepto separado de Readiness hoy (§1.3). Dos opciones quedan abiertas para el sprint de implementación, **no decididas aquí**:

(a) Health es un alias visual de `degraded`/`status_counts.failed` ya existente — sin nuevo campo de backend.
(b) Health es un concepto nuevo (fallos de parser/plugin, no solo ausencia de datos) que requiere extender `case_capabilities.py`.

Se registra como **decisión pendiente** (ver §18) porque cambia el contrato de API si se elige (b).

### 14.4 Reutilización

El mismo conjunto de estados se usa en Capability Cards, Surface Home, Entity pages y Search — un único vocabulario, un único componente visual por estado, sin variantes por plataforma.

---

## 15. Diseño basado en Capability Registry

Principio explícito, ya parcialmente enforced hoy (`docs/architecture/information-architecture.md`: "No frontend component should maintain its own list of Windows, Linux or Memory capabilities") y que este RFC extiende a todas las piezas nuevas:

- **Surface Registry** (§2.2) gobierna qué superficies existen y su orden — el sidebar y la Surface Home nunca hardcodean una lista de superficies.
- **Capability Registry** gobierna qué capabilities existen, su domain, su readiness/coverage — ninguna página de dominio o capability mantiene su propia lista.
- **Canonical Entities** (§7) se registran (qué tipos de entidad existen, qué capabilities las resuelven) — no se hardcodea qué capability "sabe" mostrar una entidad.
- **Consecuencia de auditoría (§1.4):** este principio ya se sigue en el frontend hoy; lo que falta es que el *contenido* del registry (número de domains/capabilities) alcance la profundidad real de ingesta ya soportada por el backend.

---

## 16. Arquitectura de crecimiento

Prueba de diseño explícita: añadir Identity, Threat Intelligence, EDR o Mobile dentro de varios años debe costar exactamente:

1. Una entrada en **Surface Registry** (§2.2).
2. N entradas en **Capability Registry** (§6), cada una con su `domain` (reutilizando el vocabulario existente — Access/Execution/Persistence/Network/Files/Logs/Software — o extendiéndolo si el dominio es genuinamente nuevo, p. ej. `Identity` o `Alerts` para EDR).
3. Si la superficie necesita un panel de extensión (como Memory hoy con `MemoryImagesPanel`), un único punto de extensión declarado (§4.1.8) — nunca ramas dispersas por componente.
4. Cero cambios al Sidebar, cero cambios a la Surface Home genérica, cero cambios al modelo de breadcrumbs — todos ya son genéricos por construcción (§4.2, §15).

Esto es literalmente lo que CA §05/§06 exige matemáticamente (rail en ~12 ítems para siempre, profundidad absorbida por Tier 2) y lo que la auditoría (§1.1) confirma que ya funciona así para el 80% del mecanismo — el 20% que falta es exactamente lo que este RFC formaliza (Surface Registry declarado, domains controlados, breadcrumb derivado).

---

## 17. Roadmap

Cada fase es desplegable de forma independiente y no mezcla capas (dato de registry vs. componente de UI vs. contenido de capability).

### Fase 0 — Fundaciones de registry (backend, sin cambio visible de UI)
- Declarar Surface Registry (§2.2) como capa nueva, poblada inicialmente con exactamente las 3 superficies actuales (Windows, Linux, Memory) — sin cambio de comportamiento.
- Añadir `availability: planned` al Capability Registry como valor válido (sin uso todavía).
- Formalizar el vocabulario de Domain controlado (§5.1) con los 5 valores ya en uso — sin añadir dominios nuevos todavía.

### Fase 1 — Nueva navegación (Tier 1)
- Sidebar: colapsar la sección "Investigation Surfaces" de árbol de 3 niveles a una línea por surface (consume Surface Registry de Fase 0).
- Breadcrumb derivado de ruta/registry (§2.4), reemplazando el prop manual.
- Redirects de un solo salto para cualquier ruta que cambie de forma en esta fase (reutilizando el mecanismo ya existente y testeado).

### Fase 2 — Surface Home (Tier 2, capa de layout)
- Reformular `WorkbenchOverview` de grid de coverage-cards a domain-tabs horizontales (§4.1.4), mismo dato, mismo componente base.
- Extraer el punto de extensión de superficie (§4.1.8) como mecanismo declarado y documentado, migrando `MemoryImagesPanel` a usarlo explícitamente (sin cambio funcional).

### Fase 3 — Ampliación de Capability Registry (contenido, no navegación)
- Registrar las capabilities ya soportadas por ingesta pero no expuestas hoy (Windows: Registry Persistence detallado, Autoruns, USB, Defender, SRUM, Shellbags donde aplique; Linux: cron/systemd, network config, filesystem, journal) — acoplado al *Linux parity program* / expansión de dominios Windows ya identificados en `docs/roadmap.md`.
- Cada capability nueva llega con su Coverage/Readiness — Health queda pendiente de la decisión de §14.3.
- Decisión explícita sobre `MemoryWorkspace`/`MEMORY_TABS` (§4.4).

### Fase 4 — Entity pages (Canonical Entities)
- Generalizar el patrón entidad+observación (§7.2) a un segundo tipo además de Host/Process — candidato natural: File o Service, por volumen de artefactos ya ingeridos que lo alimentan.
- Página de detalle de entidad genérica (Entity Header + observaciones + relaciones).
- Pivotes desde Search y desde Capability Cards hacia páginas de entidad, en paralelo al pivot de campo ya existente (no lo reemplaza en esta fase).

### Fase 5 — Search / Timeline / Findings / Reports (integración, no reconstrucción)
- Facetas de Search renombradas conceptualmente a `surface`/`domain`/`capability` (§8).
- Enlace de Findings/Reports a entidades canónicas cuando existan (§10, §11), adicional al enlace a artefacto/evento crudo ya existente.
- Sin cambios al motor de indexación ni al modelo de datos de eventos.

### Fase 6 — Estados comunes y Health
- Implementar el vocabulario unificado de estados (§14) en Capability Cards y Surface Home.
- Resolver la decisión pendiente de Health (§14.3) y, si se elige la opción (b), extender el contrato de `case_capabilities.py`.

### Dependencia externa a este roadmap
- El ítem P1 "Frontend capability state" de `docs/architecture/backlog.md` (señal de capability habilitada/deshabilitada al frontend) debe completarse **antes o durante** la Fase 1, porque el nuevo Sidebar debe poder ocultar una superficie deshabilitada (p. ej. Memory con `memory_enabled=false`) sin lógica ad hoc — se apoya en el mismo Surface Registry de Fase 0 añadiendo el campo `status`.

---

## 18. Riesgos

### Riesgos técnicos
- **Acoplamiento con el trabajo de Optional Capability Boundary de Memory** (`docs/architecture/backlog.md`, P0/P1): si la navegación se implementa antes de que el backend exponga el estado de activación de Memory, el Surface Registry puede mostrar una superficie que en realidad está desactivada a nivel de proceso. Mitigación: secuenciar Fase 0/1 después (o junto con) el ítem P1 "Frontend capability state".
- **Decisión de Health sin resolver (§14.3)** puede bloquear Fase 6 si se descubre tarde que requiere migración de esquema.
- **Doble modelo de estado de Finding** (workflow `draft/review/confirmed/…` de `docs/findings-notes.md` vs. workflow de correlación `new/triaged/…` mencionado en el modelo `Finding`) — no es un riesgo introducido por este RFC, pero cualquier widget de estado reutilizable (§13) que muestre "estado de Finding" debe verificar cuál de los dos vocabularios es vigente antes de construirse, o construirse contra ambos explícitamente.

### Riesgos de UX
- **Colapsar el árbol del sidebar reduce visibilidad inmediata** de capabilities que hoy son visibles de un vistazo (3 por superficie, hoy). Con solo 9 capabilities totales, el "costo" de un click adicional (rail → Surface Home → capability) es perceptible aunque el registry sea pequeño. Mitigación: Quick Actions en la Surface Home (ya existe) debe compensar el acceso directo a las capabilities más usadas.
- **`MemoryWorkspace`/`MEMORY_TABS` sin resolver (§4.4)** puede generar dos "shapes" de navegación distintas conviviendo dentro de Memory si Fase 3 no lo aborda explícitamente.

### Deuda técnica
- Iconografía hardcodeada por superficie en `WorkbenchOverview.tsx` (§1.2) — se resuelve en Fase 0/2 al mover el icono al Surface Registry.
- Orden de workbench hardcodeado como diccionario Python (§2.2) — mismo tratamiento.
- `domain` como string libre sin enum — Fase 0 lo formaliza sin forzar aún una migración de datos (los 5 valores actuales ya son válidos bajo el vocabulario nuevo).

### Migraciones y compatibilidad
- Toda ruta que cambie de forma debe pasar por el mecanismo de redirect de un solo salto ya existente y testeado (§2.5) — no se introduce un mecanismo de redirect nuevo.
- Bookmarks existentes de analistas (rutas `/w`, `/l`, `/m` ya canónicas) no cambian de raíz en ninguna fase de este roadmap.

### Regresiones
- Cualquier capability hoy alcanzable en un solo click desde el árbol expandido del sidebar pasa a requerir dos clicks (rail → Surface Home). Esto es una regresión de conveniencia aceptada explícitamente por CA §07 ("trade a real problem for an extra click on the common path" es exactamente lo que CA descarta evitar a toda costa) — se documenta aquí para que Validación (§19) la mida, no para reabrirla.

---

## 19. Validación

### Qué demostrar
1. El rail (Tier 1) permanece en ~12 ítems visibles con 3 superficies presentes y, simulando el registro ampliado de Fase 3, con las 3 superficies a profundidad completa — la prueba de CA §05 de que el conteo de Tier 1 es independiente de la profundidad de superficie.
2. Ninguna página de Tier 2 (Surface Home, Capability page, Entity page) referencia el nombre de una superficie de forma hardcodeada fuera del punto de extensión declarado (§4.1.8) — auditable por grep sobre el código de UI (`"memory"`, `"windows"`, `"linux"` como literal fuera de los archivos de registry/extensión).
3. Añadir una superficie de prueba ficticia (p. ej. `"cloud"`) solo mediante entradas de Surface Registry + Capability Registry produce una Surface Home funcional sin tocar componentes — prueba directa de §16.
4. Cada redirect introducido por la migración es de un solo salto y termina en ruta canónica — reutilizando los tests de contrato ya existentes para `App.tsx`.
5. Breadcrumb distingue visualmente Tier 1 de Tier 2 en cada página nueva (§2.4) — checklist manual página por página.

### Escenarios a cubrir
- Caso con una sola superficie presente (el caso común, según CA §07: "an analyst who works a Linux web-server case all day").
- Caso con las 3 superficies presentes simultáneamente (Windows + Linux + Memory).
- Caso sin ninguna superficie presente todavía (solo evidencia en cola de procesamiento) — Investigation Surfaces debe quedar vacío sin romper el rail.
- Memory desactivada a nivel de proceso (dependiente del ítem P1 de backlog, §17) — la superficie no debe aparecer en absoluto, no aparecer deshabilitada.
- Navegación profunda (capability → entidad → back) preserva el historial de forma que "atrás" del navegador se comporta de forma predecible.
- Bookmark antiguo de una ruta pre-migración resuelve correctamente tras cada fase.

### Métricas a observar
- Clicks-hasta-capability para el caso común de una sola superficie (objetivo: no debe superar en más de 1 click el camino actual, compensado por Quick Actions).
- Conteo de ítems de Tier 1 antes/después (objetivo: constante, ~12).
- Ausencia de scroll vertical en el rail permanente en cualquier escenario de caso (criterio duro de CA §06).
- Número de capabilities registradas vs. familias de artefacto realmente ingeridas (mide el cierre de la brecha identificada en §1.4 a lo largo de las fases).

---

*Kairon DFIR — RFC de arquitectura de implementación de navegación · Construye sobre "Kairon Navigation — The Committed Architecture" sin reabrir sus decisiones · Auditoría basada en código real, no solo en documentación · Propuesta de diseño, implementación no iniciada.*
