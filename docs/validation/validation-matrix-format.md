# Validation Matrix Format

A validation matrix is a metadata-only checklist used to evaluate whether a demo or QA case covers expected findings.

Suggested JSON shape:

```json
{
  "validation_id": "example-validation-v1",
  "source_name": "Internal synthetic scenario",
  "source_urls": {},
  "source_parts": ["scenario"],
  "items": [
    {
      "finding_id": "GT-001",
      "title": "Initial execution from downloaded lure",
      "description": "Synthetic expected behavior for training.",
      "phase": "execution",
      "host": "HOST-A",
      "result": "found",
      "confidence": "high",
      "expected_indicators": ["sample.iso", "script.ps1"],
      "expected_artifacts": ["browser", "mft", "windows_event"],
      "source_part": ["scenario"],
      "memory_required": false
    }
  ]
}
```

Keep validation packages outside `main` unless they are fully synthetic and cleared for redistribution.
