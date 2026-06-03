# Demo Evidence

This directory is reserved for generated MVP demo packs.

Use:

```bash
python3 tools/demo/generate_demo_evidence.py
```

That command generates:

- `demo/evidence/acme_incident_001.zip`

The generated pack is synthetic and uses only generic names such as:

- `TEST-WIN10-01`
- `user01`
- `example.local`
- `suspicious.example`

The ZIP itself is not versioned to avoid committing generated artifacts.
