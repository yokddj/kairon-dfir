"""Language of the text the case report generates (English or Spanish).

Only Kairon's own wording is translated: section titles, table headers, labels
and fixed sentences. Evidence values (paths, commands, names), rule titles and
the analyst's own text are reported as written.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

SUPPORTED_LANGUAGES = ("en", "es")
_LANGUAGE: ContextVar[str] = ContextVar("report_language", default="en")


def normalize_language(value: Any) -> str:
    language = str(value or "en").strip().lower()[:2]
    return language if language in SUPPORTED_LANGUAGES else "en"


@contextmanager
def report_language(value: Any) -> Iterator[str]:
    token = _LANGUAGE.set(normalize_language(value))
    try:
        yield _LANGUAGE.get()
    finally:
        _LANGUAGE.reset(token)


def current_language() -> str:
    return _LANGUAGE.get()


def tr(text: str, **values: Any) -> str:
    """Translate a fixed English string (or template) into the report language."""
    template = _SPANISH.get(text, text) if _LANGUAGE.get() == "es" else text
    return template.format(**values) if values else template


_SPANISH: dict[str, str] = {
    # Section titles
    "Executive Summary": "Resumen ejecutivo",
    "Scope": "Alcance",
    "Evidence Processed": "Evidencias procesadas",
    "Hosts": "Equipos",
    "Findings": "Hallazgos",
    "MITRE ATT&CK": "MITRE ATT&CK",
    "Detections": "Detecciones",
    "Investigation Timeline": "Cronología de la investigación",
    "Incident Timeline": "Cronología del incidente",
    "Process Chains": "Cadenas de procesos",
    "Suspicious Command History": "Historial de comandos sospechosos",
    "Microsoft Defender": "Microsoft Defender",
    "Email Artifacts": "Artefactos de correo",
    "MOTW / Downloaded Files": "MOTW / Ficheros descargados",
    "SRUM Application and Network Usage": "Uso de aplicaciones y red (SRUM)",
    "Memory Analysis": "Análisis de memoria",
    "Lateral Movement": "Movimiento lateral",
    "IOCs": "IOCs",
    "Startup & Persistence": "Arranque y persistencia",
    "Network / Cloud / USB": "Red / Nube / USB",
    "Recommendations": "Recomendaciones",
    "Appendix": "Apéndice",
    "Attack Narrative": "Narrativa del ataque",
    "Use of AI": "Uso de IA",
    "the analyst": "el analista",
    "The executive summary, attack narrative, recommendations and limitations were drafted with AI ({provider}, model {model}, {when} UTC) from the curated findings and timeline of this report, then reviewed and edited by {author}.":
        "El resumen ejecutivo, la narrativa del ataque, las recomendaciones y las limitaciones se redactaron con IA ({provider}, modelo {model}, {when} UTC) a partir de los hallazgos y la cronología curados de este informe, y después los revisó y editó {author}.",
    # Table headers
    "Action / result": "Acción / resultado", "Analysis": "Análisis", "Application": "Aplicación", "Command": "Comando",
    "Confidence": "Confianza", "Details": "Detalles", "Event": "Evento", "Event ID": "ID de evento", "Events": "Eventos",
    "Evidence": "Evidencia", "Field": "Campo", "Finding": "Hallazgo", "First event (UTC)": "Primer evento (UTC)",
    "First seen (UTC)": "Visto por primera vez (UTC)", "High/critical": "Alta/crítica", "Host": "Equipo",
    "Importance": "Importancia", "Indicators": "Indicadores", "Item": "Elemento", "Items": "Elementos",
    "Last event (UTC)": "Último evento (UTC)", "Last seen (UTC)": "Visto por última vez (UTC)", "Mark": "Marca",
    "Matches": "Coincidencias", "Mechanism": "Mecanismo", "Note": "Nota", "Notes": "Notas",
    "Observed (UTC)": "Observado (UTC)", "Parameter": "Parámetro", "Parser errors": "Errores de parser", "Path": "Ruta",
    "Path / Command": "Ruta / comando", "Phase": "Fase", "Process": "Proceso", "Received": "Recibidos",
    "Related": "Relacionado", "Related domains / IPs / files": "Dominios / IPs / ficheros relacionados",
    "Result": "Resultado", "Risk": "Riesgo", "Role": "Rol", "Rule": "Regla", "Sent": "Enviados", "Severity": "Severidad",
    "Size": "Tamaño", "Source": "Origen", "Status": "Estado", "Tactic": "Táctica", "Technique": "Técnica",
    "Threat": "Amenaza", "Time (UTC)": "Hora (UTC)", "Top priority": "Prioridad máx.", "Total": "Total", "Type": "Tipo",
    "Types": "Tipos", "User": "Usuario", "User / SID": "Usuario / SID", "Value": "Valor", "Values": "Valores",
    "Client": "Cliente", "Account hint": "Pista de cuenta", "Path / URL": "Ruta / URL", "Parsed": "Analizado",
    "File": "Fichero", "Zone": "Zona", "Name": "Nombre", "Command / Target": "Comando / destino",
    # Labels in key/value tables
    "Case": "Caso", "Case ID": "ID del caso", "Period": "Periodo", "Timezone": "Zona horaria",
    "Findings included": "Hallazgos incluidos", "All hosts": "Todos los equipos", "All evidence": "Todas las evidencias",
    "All available data": "Todos los datos disponibles", "System": "Sistema", "Format": "Formato",
    "Captured at (system time in the image, UTC)": "Capturada (hora del sistema en la imagen, UTC)",
    "Findings linked to this image": "Hallazgos vinculados a esta imagen", "Users": "Usuarios", "Files": "Ficheros",
    "Domains": "Dominios", "IP addresses": "Direcciones IP", "Marked events": "Eventos marcados",
    "Command history": "Historial de comandos", "Key events": "Eventos clave",
    "Account": "Cuenta", "Domain": "Dominio", "Hash": "Hash", "IP address": "Dirección IP", "URL": "URL",
    # Tactics / phases (humanized) and severities
    "Initial access": "Acceso inicial", "Execution": "Ejecución", "Persistence": "Persistencia",
    "Privilege escalation": "Escalada de privilegios", "Defense evasion": "Evasión de defensas",
    "Credential access": "Acceso a credenciales", "Discovery": "Descubrimiento", "Lateral movement": "Movimiento lateral",
    "Collection": "Recopilación", "Command and control": "Mando y control", "Exfiltration": "Exfiltración",
    "Impact": "Impacto", "Cleanup": "Limpieza", "Other": "Otras",
    "critical": "crítica", "high": "alta", "medium": "media", "low": "baja", "info": "informativa",
    # Labels and short sentences
    "Coverage notes:": "Notas de cobertura:", "Key findings:": "Hallazgos principales:",
    "Why it matters:": "Por qué importa:", "Supporting events:": "Eventos de soporte:",
    "Recommended next steps:": "Siguientes pasos recomendados:", "Command details": "Detalle de comandos",
    "Additional general recommendations:": "Recomendaciones generales adicionales:",
    "Report parameters": "Parámetros del informe", "Sections without matching data": "Secciones sin datos",
    "Limitations": "Limitaciones", "Event references": "Referencias de eventos", "Report metadata": "Metadatos del informe",
    "No findings are included in this report.": "Este informe no incluye hallazgos.",
    "No findings selected for this report.": "No hay hallazgos seleccionados para este informe.",
    "Process chain": "Cadena de procesos", "Script": "Script", "Family": "Familia", "Launcher": "Lanzador",
    "Seen in": "Visto en", "Why it is suspicious": "Por qué es sospechoso", "Analyst marking": "Marca del analista",
    "Analyst notes": "Notas del analista",
    # Lateral movement
    "No remote logons between machines were found in the authentication logs.":
        "No se encontraron inicios de sesión remotos entre equipos en los registros de autenticación.",
    "Remote logons between machines, from the authentication logs of every host, in the order they began. "
    "A source is named as a case host only when its address was observed on that host. "
    "These are authentications, not proof of intent: read them with the findings and the timeline.":
        "Inicios de sesión remotos entre equipos, tomados de los registros de autenticación de cada equipo, en el orden en que empezaron. "
        "Un origen se identifica como equipo del caso solo cuando su dirección se observó en ese equipo. "
        "Son autenticaciones, no prueba de intención: deben leerse junto con los hallazgos y la cronología.",
    "{count} routine connections (machine, anonymous and built-in accounts) are left out.":
        "Se omiten {count} conexiones rutinarias (cuentas de equipo, anónimas e integradas).",
    "From": "Origen", "To": "Destino", "Method": "Método",
    "not a case host": "no es un equipo del caso",
    "workstation name: {names}": "nombre de estación: {names}",
    "address seen on several hosts": "dirección vista en varios equipos",
    "{count} succeeded": "{count} correctos", "{count} failed": "{count} fallidos",
    "{shown} of {total} connections are shown; the Lateral Movement view lists them all.":
        "Se muestran {shown} de {total} conexiones; la vista Lateral Movement las lista todas.",
    "Network logon (type 3: SMB, WinRM, PsExec, WMI...)": "Inicio de sesión de red (tipo 3: SMB, WinRM, PsExec, WMI...)",
    "Network cleartext logon (type 8)": "Inicio de sesión de red en texto claro (tipo 8)",
    "Remote Desktop (type 10)": "Escritorio remoto (tipo 10)",
    "Detected by": "Detectado por", "Target": "Objetivo",
    "real-time protection": "protección en tiempo real", "system scan": "análisis del sistema",
    "AMSI (script scan)": "AMSI (análisis de scripts)", "download/attachment scan": "análisis de descargas/adjuntos",
    "behaviour monitoring": "supervisión de comportamiento", "on-demand scan": "análisis bajo demanda",
    "**Antivirus detections still in memory** ({count}): what the antivirus detected and when, recovered from the image even if the event logs were cleared.":
        "**Detecciones antivirus que siguen en memoria** ({count}): qué detectó el antivirus y cuándo, recuperado de la imagen aunque se hayan borrado los registros de eventos.",
    # Templates
    "This report covers case **{case}**. {evidence}{hosts} {verb} processed and {events} events were indexed.":
        "Este informe cubre el caso **{case}**. Se procesaron {evidence}{hosts} y se indexaron {events} eventos.",
    "{count} evidence item": "{count} evidencia", "{count} evidence items": "{count} evidencias",
    " from {count} host ({names})": " de {count} equipo ({names})", " from {count} hosts ({names})": " de {count} equipos ({names})",
    "**{count} finding** is reported ({breakdown}).": "Se informa de **{count} hallazgo** ({breakdown}).",
    "**{count} findings** are reported ({breakdown}).": "Se informa de **{count} hallazgos** ({breakdown}).",
    "{count} further finding is still awaiting analyst review and not included; confirm or dismiss it in Findings before issuing the report.":
        "{count} hallazgo más sigue pendiente de revisión y no se incluye; confírmalo o descártalo en Hallazgos antes de emitir el informe.",
    "{count} further findings are still awaiting analyst review and not included; confirm or dismiss them in Findings before issuing the report.":
        "{count} hallazgos más siguen pendientes de revisión y no se incluyen; confírmalos o descártalos en Hallazgos antes de emitir el informe.",
    "{severity} severity, risk {risk}": "severidad {severity}, riesgo {risk}",
    "{techniques} across {tactics}, from the MITRE tags of the reported findings.":
        "{techniques} en {tactics}, según las etiquetas MITRE de los hallazgos del informe.",
    "{status}; minimum severity {severity}": "{status}; severidad mínima {severity}",
    "These sections were checked and had no matching data for this case and these parameters, so they are left out of the exported report: {sections}.":
        "Estas secciones se comprobaron y no tienen datos para este caso con estos parámetros, así que no se incluyen en el informe exportado: {sections}.",
    "These are automated rule matches; {count} of them have not been reviewed by an analyst and should be read as leads, not conclusions.":
        "Son coincidencias automáticas de reglas; {count} no han sido revisadas por un analista y deben leerse como pistas, no como conclusiones.",
    # PDF chrome
    "DIGITAL FORENSIC INVESTIGATION REPORT": "INFORME DE INVESTIGACIÓN FORENSE DIGITAL",
    "Contents": "Índice", "Case: {case}": "Caso: {case}", "Prepared by": "Elaborado por", "Report date": "Fecha del informe",
    "Report reference": "Referencia del informe", "Not specified": "No indicado", "All times in UTC": "Todas las horas en UTC",
    "Case {case} · Investigation report": "Caso {case} · Informe de investigación",
    "Generated {when} UTC · Confidential": "Generado {when} UTC · Confidencial", "Page {page} of {pages}": "Página {page} de {pages}",
    "This report contains information from a forensic investigation. Handle it according to your organisation's classification policy and share it only with authorised recipients.":
        "Este informe contiene información de una investigación forense. Trátalo según la política de clasificación de tu organización y compártelo solo con destinatarios autorizados.",
    "Evidence items": "Evidencias", "Events indexed": "Eventos indexados", "Findings reported": "Hallazgos en el informe",
    "Rule matches": "Coincidencias de reglas",
    "Generated {when} UTC · all times UTC": "Generado {when} UTC · todas las horas en UTC", " · Prepared by {author}": " · Elaborado por {author}",
}
