# Execution Story / Process Graph

The main process-investigation experience is `Execution Story`. The advanced graph remains available for broader graph/debug work.

## Execution Story answers

- Who launched this process?
- What did it launch?
- What did it do?
- Why is it suspicious?
- What evidence supports it?

## Identity model

Exact pivots use stable identity in this order:

1. `source_event_id`
2. process GUID / entity ID
3. PID + timestamp + host + evidence
4. text query only as last fallback

Opening a story from Search or Command History should target the exact selected event/process, not a similar command line.

## UI behavior

- Header, canvas, fallback tree and selected detail share one story target.
- Clicking a node previews it only.
- `Make target` intentionally rebuilds the story for that node.
- Suspicious chains are secondary and must not steal focus from an exact story.
- Diagnostics stay collapsed unless needed.

## What it shows

- investigation target
- parent sentence
- children sentence
- activity summary
- visual tree
- source events
- commands
- risk reasons
- parent/child diagnostics when expanded

## Noise controls

Activity edges are grouped/collapsed by default:

- file activity
- registry activity
- network activity
- DNS activity

The advanced graph exposes controls for node caps, activity caps, edge types and diagnostics.

## Limitations

- Parent links depend on available Sysmon/Security/process fields.
- PID-only pivots can be ambiguous without timestamp/host/evidence.
- Graph edges are investigative context, not proof by themselves.
- Advanced full graph can be noisy; prefer Execution Story for analyst workflow.

