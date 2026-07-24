# Kairon — Instrucciones de proyecto

## Autonomía y permisos

El usuario ha otorgado permiso absoluto para operar en este equipo y este repositorio. No pidas confirmación antes de acciones normales de desarrollo dentro del checkout local del proyecto (ediciones, commits, comandos locales, reinicios, etc.).

Excepción: usa criterio ante acciones verdaderamente destructivas o de alcance mucho mayor al del proyecto (p. ej. force-push destructivo sobre trabajo ajeno, borrar todo el repo, tocar sistemas fuera de este checkout o del servidor de despliegue designado). Ahí un aviso breve está bien, pero por defecto: actuar, no preguntar.

## Despliegue

Tras cualquier cambio de impacto real, despliega siempre al servidor remoto configurado (vía `scripts/deploy_remote.sh`, que requiere `REMOTE_HOST` — ver la configuración de despliegue local, no un valor fijo en este repositorio) como parte de dar la tarea por terminada — no esperes a que se te pida.

Flujo esperado para cambios no triviales:
1. Modificar código localmente.
2. Ejecutar tests locales.
3. Compilar frontend.
4. Validar backend.
5. Commit.
6. Desplegar al servidor remoto configurado (vía SSH, usando `scripts/deploy_remote.sh`).
7. Validar el caso real en ese servidor.
8. Revisar logs.
9. Verificar que no hay regresiones.

No declares un cambio no trivial como "terminado" o "funcionando" basándote solo en validación local — el despliegue y la validación remota son parte de la definición de "hecho" en este proyecto.
