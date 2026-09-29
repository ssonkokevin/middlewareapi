"""
Superseded by app.services.db in the v2.0.0 migration.

The v1.x eligibility_token model (single-use, in-memory, 10-minute TTL) is
gone entirely — v2.0.0 replaces it with a verification_reference that is
valid for 24 hours and reusable, backed by SQLite (see app/services/db.py
for the rationale). Nothing in this codebase should import from here; kept
only so old imports fail loudly instead of silently resurrecting v1 state.
"""

from app.services.db import store  # noqa: F401  (re-exported for safety only)
