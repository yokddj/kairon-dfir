# Quickstart

## 1. Start the Application

1. Copy `.env.example` to `.env`.
2. Run:

```bash
docker compose up --build
```

3. Open:
   - frontend: `http://localhost:5173`
   - API: `http://localhost:8000`
   - OpenSearch: `http://localhost:9200`

## 2. Create or Open a Case

1. Go to `Cases`.
2. Create a new case or open an existing one.
3. If you're going to work on a specific investigation, set it as the **active case**.

## 3. What Evidence to Upload Today

The most recommended evidence to upload today is:

- parsed KAPE/EZ Tools collections
- parsed Velociraptor folders
- especially `*_EvtxECmd_Output.csv`

## 4. How to Upload Evidence

1. Open the case.
2. Use `Upload files` or `Upload folder`.
3. Wait for the ingest status to change to `completed`.

## 5. How to Tell If Parsing Finished Correctly

Check:

1. Evidence status.
2. The case's `Artifact Views`.
3. `Activity`, in case there were parsing/indexing errors.
4. `Search`, to confirm the case's events appear.

## 6. How to Search for an EventID

Practical examples:

- `4624` -> successful logons
- `4625` -> failed logons
- `4104` -> PowerShell script blocks
- `4688` -> process creation
- `7045` -> service creation
- `4698` -> scheduled task creation
- `1116` -> Defender detection

Tip:

1. Open `Search`.
2. Leave the query empty to see overall volume.
3. Use `Search mode = IOC` or `smart` for specific EventIDs.
4. If you need extra precision, filter by `artifact.type = evtx`.

## 7. How to Open an Event's Detail

You can reach the event from:

- `Search`
- `Artifact Explorer`
- `Detections`, if the detection points to an event
- `Timeline`

In the detail view, look for:

- `event.type`
- `windows.event_id`
- `windows.channel`
- `windows.provider`
- `raw`
- `windows.event_data`
- `windows.payload`

## 8. How to Review Semi-Automatic Analysis

1. Go to `Semi-automatic Analysis`.
2. Select the case.
3. If the summary comes up empty, first click `Clear time filter`.
4. Review:
   - Logons
   - PowerShell
   - Services
   - Tasks
   - Network
   - Defender
   - Suspicious findings

## 9. How to Review Rules and Detections

### Rules

Use `Rules` to:

- view individual rules
- view rule packs
- import Sigma/YARA/heuristic rules
- enable/disable rules
- run rules against a case

### Detections

Use `Detections` to:

- view automatic signals
- filter by engine, severity, status, and case
- mark as reviewed or false positive
- delete selections or filtered sets

## 10. How to Create a Finding from Events or Detections

Today you can create findings from:

- `Search`
- `Artifact Explorer`
- `Investigation Timeline`
- `Detections`

Recommended flow:

1. Select one or more events, or one or more detections from the same case.
2. Click `Create finding`.
3. Adjust the title, severity, and description.
4. Save the finding and review it in `Findings`.

Use `Promote to finding` in `Detections` for a quick promotion without editing too much context.

## 11. What to Do If No Results Appear

1. Check that the ingest actually finished.
2. Check that the active case is the correct one.
3. Check `Activity` in case there were bulk indexing errors.
4. Check whether you're using a time filter that's too narrow.
5. If you just changed mappings or the EVTX parser, consider reimporting the case.
