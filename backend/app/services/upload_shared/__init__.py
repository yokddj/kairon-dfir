"""Shared primitives for chunked upload session backends.

Phase 2.5 of the upload backend consolidation: these modules extract the
workflow-agnostic mechanics of Memory's upload pipeline (the mature
implementation) so both Memory and, eventually, Evidence can consume the
same code without either backend's database schema, HTTP protocol, or
feature flags changing yet. Persistence stays split (``memory_uploads`` vs
``evidence_upload_sessions``) until the service-layer consolidation proven
here is validated end to end.

Distributed locking already lived in its own shared module before this
package existed -- see ``app.services.upload_locks`` -- and is unchanged.
"""
