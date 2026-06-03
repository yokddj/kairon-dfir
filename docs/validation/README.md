# Validation Features

Validation Matrix is a generic QA/training feature. It is not part of normal investigations and this repository does not include a bundled ground-truth dataset.

Kairon DFIR is built to support, not replace, the analyst. It provides a clear lens over forensic evidence so critical moments can be interpreted faster and with more context.

A validation dataset should be imported separately and should contain only metadata that the organization is allowed to distribute.

Recommended contents:

- expected finding IDs and titles;
- phase, host and confidence;
- expected indicators and artifact classes;
- source references owned by the organization;
- optional timeline seed metadata;
- no evidence archives, database dumps, or indexed documents.

Validation features are hidden by default in investigation mode.
