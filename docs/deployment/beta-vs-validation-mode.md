# Beta vs Validation Mode

Kairon DFIR separates real investigations from optional QA/training validation material.

## Default beta mode

Default installs use:

```bash
DFIR_ENABLE_DEMO_CASES=false
DFIR_ENABLE_VALIDATION_FEATURES=false
DFIR_DEFAULT_CASE_MODE=investigation
```

In this mode:

- new cases are investigation cases;
- validation datasets are not auto-loaded;
- Validation Matrix navigation is hidden;
- ground truth cards and timeline seeds are hidden;
- reports do not include validation coverage;
- validation material is separated from normal investigations.

This prevents testers from seeing expected answers during real triage.

## Validation/training mode

Validation mode is explicit:

```bash
DFIR_ENABLE_DEMO_CASES=true
DFIR_ENABLE_VALIDATION_FEATURES=true
```

Use a case mode of `training` or `validation` to expose validation features for that case. In validation mode, imported validation matrices can be shown and reports can include validation coverage. UI badges identify that training ground truth is enabled.

## Data boundary

Validation metadata is kept separate from evidence:

- `docs/validation/` describes matrix format and import expectations;
- no evidence archives, OpenSearch indexes, DB dumps, generated reports, public challenge datasets or answer keys are bundled in main.

Evidence and validation metadata must be uploaded or imported by the analyst as separate actions.
