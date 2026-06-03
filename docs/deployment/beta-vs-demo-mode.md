# Beta vs Demo Mode

Kairon DFIR separates real investigations from demo/training validation material.

## Default beta mode

Default installs use:

```bash
DFIR_ENABLE_DEMO_CASES=false
DFIR_ENABLE_VALIDATION_FEATURES=false
DFIR_DEFAULT_CASE_MODE=investigation
```

In this mode:

- new cases are investigation cases;
- demo datasets are not auto-loaded;
- Validation Matrix navigation is hidden;
- ground truth cards and timeline seeds are hidden;
- reports do not include validation coverage;
- demo docs are hidden or separated from the normal docs catalog.

This prevents testers from seeing expected answers during real triage.

## Demo/training mode

Demo mode is explicit:

```bash
DFIR_ENABLE_DEMO_CASES=true
DFIR_ENABLE_VALIDATION_FEATURES=true
```

Use a case mode of `demo`, `training`, or `validation` to expose validation features for that case. In demo mode, imported validation matrices can be shown and reports can include validation coverage. UI badges identify that demo/training ground truth is enabled.

## Data boundary

Demo metadata is kept separate from evidence:

- `docs/demo/` contains generic demo guidance;
- `docs/validation/` describes matrix format and import expectations;
- no evidence archives, OpenSearch indexes, DB dumps, generated reports, public challenge datasets or answer keys are bundled in main.

Evidence and validation metadata must be uploaded or imported by the analyst as separate actions.
