"""
SQLite-backed persistence for the KYC gateway.

Deliberately not in-memory: verification_reference is valid and reusable for
24 hours, but local dev runs uvicorn with --reload, which restarts the
process on every file save. An in-memory dict would silently wipe every
reference on each hot-reload, making the store's own headline behaviour (a
reference staying valid across a long window) impossible to exercise during
normal iteration. A single SQLite file is enough — no ORM, no migrations.

All access goes through the repository-style methods on `Store` below, so a
future swap to Redis/Postgres touches this file only.
"""

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings

_DB_PATH = Path(settings.SQLITE_PATH)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verification_references (
    reference TEXT PRIMARY KEY,
    id_type TEXT NOT NULL,
    id_number TEXT NOT NULL,
    provider TEXT NOT NULL,
    verified INTEGER NOT NULL,
    reason_code TEXT NOT NULL,
    verified_at TEXT,
    expires_at REAL NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS registrations (
    msisdn TEXT PRIMARY KEY,
    kind TEXT NOT NULL,               -- individual | corporate
    status TEXT NOT NULL,             -- active | deregistered
    id_type TEXT,
    id_number TEXT,                   -- individual id_number OR corporate registration_number
    mno TEXT,
    surname TEXT,
    given_name TEXT,
    gender TEXT,
    id_validity TEXT,
    visa_validity TEXT,
    visa_permit_number TEXT,
    last_verification_reference TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriber_overrides (
    subscriber_key TEXT PRIMARY KEY,
    limit_value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS batch_jobs (
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,               -- individual | corporate
    status TEXT NOT NULL DEFAULT 'pending',
    total_records INTEGER NOT NULL DEFAULT 0,
    processed_records INTEGER NOT NULL DEFAULT 0,
    successful_records INTEGER NOT NULL DEFAULT 0,
    failed_records INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS batch_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    msisdn TEXT NOT NULL,
    status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    verification_reference TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    idem_key TEXT PRIMARY KEY,
    job_id TEXT NOT NULL
);
"""


@dataclass
class VerificationReference:
    reference: str
    id_type: str
    id_number: str
    provider: str
    verified: bool
    reason_code: str
    expires_at: float
    verified_at: Optional[str] = None
    use_count: int = 0


@dataclass
class BatchJob:
    job_id: str
    kind: str
    status: str = "pending"
    total_records: int = 0
    processed_records: int = 0
    successful_records: int = 0
    failed_records: int = 0
    results: List[dict] = field(default_factory=list)


class Store:
    def __init__(self, db_path: Path = _DB_PATH):
        self._lock = threading.Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Adds columns introduced after initial table creation to a
        pre-existing SQLite file. CREATE TABLE IF NOT EXISTS does not alter
        an already-created table, so new columns must be added explicitly."""
        existing_columns = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(registrations)").fetchall()
        }
        if "last_verification_reference" not in existing_columns:
            self._conn.execute(
                "ALTER TABLE registrations ADD COLUMN last_verification_reference TEXT"
            )

    # --------------------------------------------------------- verification_references

    def create_verification_reference(
        self,
        id_type: str,
        id_number: str,
        provider: str,
        verified: bool,
        reason_code: str,
        ttl_hours: float,
        verified_at: Optional[str] = None,
    ) -> "VerificationReference":
        reference = "vrf_" + uuid.uuid4().hex[:20].upper()
        expires_at = time.time() + ttl_hours * 3600
        with self._lock:
            self._conn.execute(
                """INSERT INTO verification_references
                   (reference, id_type, id_number, provider, verified, reason_code,
                    verified_at, expires_at, use_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                (reference, id_type, id_number, provider, int(verified), reason_code,
                 verified_at, expires_at),
            )
            self._conn.commit()
        return VerificationReference(
            reference=reference, id_type=id_type, id_number=id_number, provider=provider,
            verified=verified, reason_code=reason_code, expires_at=expires_at,
            verified_at=verified_at,
        )

    def get_verification_reference(self, reference: str) -> Optional[VerificationReference]:
        row = self._conn.execute(
            "SELECT * FROM verification_references WHERE reference = ?", (reference,)
        ).fetchone()
        if row is None:
            return None
        return VerificationReference(
            reference=row["reference"], id_type=row["id_type"], id_number=row["id_number"],
            provider=row["provider"], verified=bool(row["verified"]),
            reason_code=row["reason_code"], expires_at=float(row["expires_at"]),
            verified_at=row["verified_at"], use_count=row["use_count"],
        )

    def validate_reference(self, reference: Optional[str], id_type: str, id_number: str) -> Optional[str]:
        """
        Validates a verification_reference against an incoming identity.
        Returns None on success, or one of:
          VERIFICATION_REQUIRED | VERIFICATION_REFERENCE_INVALID |
          VERIFICATION_REFERENCE_EXPIRED | VERIFICATION_REFERENCE_MISMATCH

        Never single-use: on success, increments use_count but leaves the
        reference valid for repeated use until expires_at.
        """
        if not reference:
            return "VERIFICATION_REQUIRED"
        entry = self.get_verification_reference(reference)
        if entry is None:
            return "VERIFICATION_REFERENCE_INVALID"
        if entry.expires_at < time.time():
            return "VERIFICATION_REFERENCE_EXPIRED"
        if entry.id_type != id_type or entry.id_number != id_number:
            return "VERIFICATION_REFERENCE_MISMATCH"
        with self._lock:
            self._conn.execute(
                "UPDATE verification_references SET use_count = use_count + 1 WHERE reference = ?",
                (reference,),
            )
            self._conn.commit()
        return None

    # --------------------------------------------------------- ownership counts

    def individual_ownership_count(self, id_type: str, id_number: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) c FROM registrations WHERE kind='individual' AND status='active' "
            "AND id_type=? AND id_number=?",
            (id_type, id_number),
        ).fetchone()
        return row["c"]

    def corporate_ownership_count(self, registration_number: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) c FROM registrations WHERE kind='corporate' AND status='active' "
            "AND id_number=?",
            (registration_number,),
        ).fetchone()
        return row["c"]

    def resolve_limit(self, subscriber_key: str, global_default: int) -> int:
        row = self._conn.execute(
            "SELECT limit_value FROM subscriber_overrides WHERE subscriber_key=?",
            (subscriber_key,),
        ).fetchone()
        return row["limit_value"] if row else global_default

    # --------------------------------------------------------- registrations

    def get_registration(self, msisdn: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM registrations WHERE msisdn=?", (msisdn,)
        ).fetchone()

    def is_active_registration(self, msisdn: str) -> bool:
        row = self.get_registration(msisdn)
        return row is not None and row["status"] == "active"

    def is_active_registration_for_mno(self, msisdn: str, mno: str) -> bool:
        row = self.get_registration(msisdn)
        return row is not None and row["status"] == "active" and row["mno"] == mno

    def upsert_registration(
        self, msisdn: str, kind: str, id_type: str, id_number: str, mno: str,
        surname: str = "", given_name: str = "", gender: Optional[str] = None,
        id_validity: Optional[str] = None, visa_validity: Optional[str] = None,
        visa_permit_number: Optional[str] = None,
        last_verification_reference: Optional[str] = None,
    ) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                """INSERT INTO registrations
                       (msisdn, kind, status, id_type, id_number, mno, surname, given_name,
                        gender, id_validity, visa_validity, visa_permit_number,
                        last_verification_reference, created_at, updated_at)
                   VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(msisdn) DO UPDATE SET
                       kind=excluded.kind, status='active', id_type=excluded.id_type,
                       id_number=excluded.id_number, mno=excluded.mno,
                       surname=excluded.surname, given_name=excluded.given_name,
                       gender=excluded.gender, id_validity=excluded.id_validity,
                       visa_validity=excluded.visa_validity,
                       visa_permit_number=excluded.visa_permit_number,
                       last_verification_reference=excluded.last_verification_reference,
                       updated_at=excluded.updated_at""",
                (msisdn, kind, id_type, id_number, mno, surname, given_name, gender,
                 id_validity, visa_validity, visa_permit_number,
                 last_verification_reference, now, now),
            )
            self._conn.commit()

    def amend_registration_fields(self, msisdn: str, **fields: Any) -> Dict[str, Any]:
        """Applies partial field updates (PATCH). Returns the previous values
        of the fields that changed."""
        row = self.get_registration(msisdn)
        previous = {}
        set_clauses = []
        params: List[Any] = []
        for key, value in fields.items():
            if value is None:
                continue
            previous[key] = row[key] if row and key in row.keys() else None
            set_clauses.append(f"{key} = ?")
            params.append(value)
        if not set_clauses:
            return previous
        params.append(time.time())
        params.append(msisdn)
        with self._lock:
            self._conn.execute(
                f"UPDATE registrations SET {', '.join(set_clauses)}, updated_at = ? WHERE msisdn = ?",
                params,
            )
            self._conn.commit()
        return previous

    def deregister(self, msisdn: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE registrations SET status='deregistered', updated_at=? WHERE msisdn=?",
                (time.time(), msisdn),
            )
            self._conn.commit()

    # --------------------------------------------------------- batch jobs

    def create_batch_job(self, total_records: int, kind: str, prefix: str = "batch") -> BatchJob:
        job_id = f"{prefix}_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._conn.execute(
                """INSERT INTO batch_jobs (job_id, kind, status, total_records, created_at)
                   VALUES (?, ?, 'pending', ?, ?)""",
                (job_id, kind, total_records, time.time()),
            )
            self._conn.commit()
        return BatchJob(job_id=job_id, kind=kind, total_records=total_records)

    def set_batch_status(self, job_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE batch_jobs SET status=? WHERE job_id=?", (status, job_id))
            self._conn.commit()

    def append_batch_result(
        self, job_id: str, msisdn: str, status: str, reason_code: str,
        verification_reference: Optional[str], error_message: Optional[str],
        success: bool,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO batch_results
                   (job_id, msisdn, status, reason_code, verification_reference, error_message)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (job_id, msisdn, status, reason_code, verification_reference, error_message),
            )
            self._conn.execute(
                """UPDATE batch_jobs SET
                       processed_records = processed_records + 1,
                       successful_records = successful_records + ?,
                       failed_records = failed_records + ?
                   WHERE job_id = ?""",
                (1 if success else 0, 0 if success else 1, job_id),
            )
            self._conn.commit()

    def get_batch_job(self, job_id: str) -> Optional[BatchJob]:
        row = self._conn.execute("SELECT * FROM batch_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        results = [
            dict(r) for r in self._conn.execute(
                "SELECT msisdn, status, reason_code, verification_reference, error_message "
                "FROM batch_results WHERE job_id=? ORDER BY id", (job_id,),
            ).fetchall()
        ]
        return BatchJob(
            job_id=row["job_id"], kind=row["kind"], status=row["status"],
            total_records=row["total_records"], processed_records=row["processed_records"],
            successful_records=row["successful_records"], failed_records=row["failed_records"],
            results=results,
        )

    # --------------------------------------------------------- idempotency

    def get_idempotent_job(self, idem_key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT job_id FROM idempotency_keys WHERE idem_key=?", (idem_key,)
        ).fetchone()
        return row["job_id"] if row else None

    def record_idempotency_key(self, idem_key: str, job_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO idempotency_keys (idem_key, job_id) VALUES (?, ?)",
                (idem_key, job_id),
            )
            self._conn.commit()

    # --------------------------------------------------------- compliance

    def compliance_counts(self, mno: str) -> dict:
        row = self._conn.execute(
            "SELECT COUNT(*) c FROM registrations WHERE mno=? AND status='active'", (mno,)
        ).fetchone()
        return {"valid_records": row["c"], "invalid_records": 0, "missing_information": 0}


# Single application-wide store instance
store = Store()
