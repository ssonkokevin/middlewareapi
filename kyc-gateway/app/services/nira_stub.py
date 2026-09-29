"""
Superseded by app.services.provider_stub in the v2.0.0 migration.

v2.0.0 branches provider simulation by id_type (NIRA/UNHCR/NCIC/URSB) rather
than always calling NIRA — see provider_stub.py.
"""

from app.services.provider_stub import verify_with_provider  # noqa: F401
