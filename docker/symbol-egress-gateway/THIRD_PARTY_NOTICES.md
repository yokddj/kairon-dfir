# Third-party notices for the symbol egress gateway image

This image contains only first-party Kairon code.  The runtime dependencies
(`fastapi`, `uvicorn`) are pulled from PyPI at build time and are governed
by their own licenses:

* FastAPI — MIT
* Uvicorn — BSD-3-Clause

The container itself does not bundle or distribute any third-party
content.  The HTTPS requests it makes at runtime fetch Microsoft debugging
symbols from `msdl.microsoft.com` (and `*.blob.core.windows.net` redirect
targets), which are subject to Microsoft's symbol distribution terms.  The
content is not committed to the repository and is cached only on local
storage controlled by the operator.
