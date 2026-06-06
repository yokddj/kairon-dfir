# Demo And Lab Documentation

Kairon DFIR ships with demo and validation capabilities. Demo material is intended for controlled training, QA and product demonstrations, not for normal investigations.

Kairon DFIR is built to support, not replace, the analyst. It provides a clear lens over forensic evidence so critical moments can be interpreted faster and with more context.

Demo mode is intended for:

- internal training;
- QA validation;
- controlled product demonstrations;
- customer-provided synthetic datasets.

Enable demo features only in environments where users expect training or validation content. Normal beta investigations should run with demo features disabled.

## Runtime flags

```bash
DFIR_ENABLE_DEMO_CASES=false
DFIR_ENABLE_VALIDATION_FEATURES=false
DFIR_DEFAULT_CASE_MODE=investigation
```

Set the first two values to `true` only for a demo/training environment. After enabling them, import your own validation metadata or upload a separate demo package maintained outside `main`.

## Demo Index

- [Kairon Lab 01 - Suspicious PowerShell Activity](kairon-lab01/README.md): controlled Windows DFIR lab based on a Velociraptor collection. It is designed to test ingest, Search, timeline reconstruction, artifact pivots, detections and evidence-backed conclusions.
- [Generic demo guide](generic-demo-guide.md): neutral guide for showing the platform with your own synthetic or cleared dataset.
- [MVP demo guide](mvp-demo-guide.md): legacy synthetic demo route for broad product walkthroughs.
- [MVP demo checklist](mvp-demo-checklist.md): pre-flight checklist for the synthetic demo.
- [MVP demo quick route](mvp-demo-route-quick.md): short walkthrough for a generated demo case.
- [Local demo evidence folder](../../demo/evidence/README.md): operational note for placing local demo archives outside version control.

Public demo cases must clearly state whether evidence is bundled, externally provided or generated separately. They should not be presented as real malware investigations.

This repository does not version heavy evidence archives, processed case data, OpenSearch indexes, Postgres dumps or answer keys for real investigations.
