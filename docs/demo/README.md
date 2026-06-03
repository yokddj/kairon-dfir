# Demo Mode

Kairon DFIR ships with demo and validation capabilities, but the main branch does not include any case-specific dataset, evidence archive, ground-truth matrix, or training answer key.

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
