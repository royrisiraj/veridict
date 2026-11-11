"""Private immutable Blob objects; packaged passports remain independent assets.

The official SDK resolves Vercel OIDC + BLOB_STORE_ID, with read/write token
fallback. No storage URL, credential, or raw signing payload is returned to users.
"""
import hashlib
import json
import re
from contextlib import contextmanager
from datetime import datetime, timezone

from app.canonical import canonical_json, SCHEMA_HASH_HEX
from app.chain.registry import Anchor
from app.deployment import FixtureRegistry, FixtureReportStore
from app.models import InvestigationReport
from app.sealing import seal_bundle

MAX_OBJECT_BYTES = 1_048_576


class StorageUnavailableError(RuntimeError):
    """Private durable storage cannot establish a successful operation."""


class ObjectExistsError(RuntimeError):
    """An immutable key already exists."""


class QuotaExceededError(RuntimeError):
    """A durable limit or lease was exhausted."""


class PrivateBlobObjects:
    def __init__(self, sdk=None):
        if sdk is None:
            from vercel.blob import sync as sdk
        self.sdk = sdk

    def get(self, key):
        from vercel.blob.errors import BlobNotFoundError
        try:
            with self.sdk.stream_blob("veridict/v1/" + key, access="private") as response:
                if response.metadata.size is not None and response.metadata.size > MAX_OBJECT_BYTES:
                    raise StorageUnavailableError("Stored object exceeds limits")
                body = bytearray()
                for chunk in response:
                    body.extend(chunk)
                    if len(body) > MAX_OBJECT_BYTES:
                        raise StorageUnavailableError("Stored object exceeds limits")
                return bytes(body)
        except BlobNotFoundError:
            return None
        except Exception:
            raise StorageUnavailableError("Private storage read unavailable") from None

    def create(self, key, data):
        if len(data) > MAX_OBJECT_BYTES:
            raise StorageUnavailableError("Stored object exceeds limits")
        try:
            result = self.sdk.put_blob("veridict/v1/" + key, data, access="private",
                content_type="application/json", add_random_suffix=False, allow_overwrite=False)
            return result.etag
        except Exception as exc:
            # A provider conflict is distinct from transport/authentication failure.
            if getattr(exc, "status_code", None) in {409, 412} or getattr(exc, "code", None) in {"blob_already_exists", "already_exists"}:
                raise ObjectExistsError("Immutable key exists") from None
            # SDK versions may report conflicts as 400. Read the exact key to
            # distinguish an existing object without treating outages as success.
            if getattr(exc, "status_code", None) == 400 and self.get(key) is not None:
                raise ObjectExistsError("Immutable key exists") from None
            raise StorageUnavailableError("Private storage write unavailable") from None

    def delete(self, key, etag):
        try:
            self.sdk.delete_blob("veridict/v1/" + key, if_match=etag)
        except Exception:
            raise StorageUnavailableError("Private lease release unavailable") from None

    def available(self):
        try:
            self.get("storage-readiness.json")
            return True
        except StorageUnavailableError:
            return False


def report_key(report_id):
    if not isinstance(report_id, str) or not re.fullmatch(r"0x[0-9a-f]{64}", report_id):
        raise ValueError("Invalid report ID")
    return report_id


class BlobReportStore:
    """Two independently addressed immutable records; no overwrite path."""
    def __init__(self, objects=None, fixtures=None):
        self.objects = objects or PrivateBlobObjects()
        self.fixtures = fixtures or FixtureReportStore()

    def get(self, report_id):
        report_key(report_id)
        packaged = self.fixtures.get(report_id)
        if packaged:
            return packaged
        data = self.objects.get(f"reports/{report_id}.json")
        if data is None:
            return None
        try:
            report = InvestigationReport.model_validate_json(data)
            if report.bundle.report_id != report_id:
                raise ValueError("Incorrect storage key")
            return report
        except ValueError:
            raise StorageUnavailableError("Stored passport is invalid") from None

    def put_once(self, key, value):
        data = canonical_json(value)
        try:
            return self.objects.create(key, data)
        except ObjectExistsError:
            if self.objects.get(key) != data:
                raise StorageUnavailableError("Immutable storage conflict") from None
            return None

    def save(self, report):
        report_id = report_key(report.bundle.report_id)
        if self.fixtures.get(report_id) or seal_bundle(report.bundle) != report.merkle:
            raise StorageUnavailableError("Passport conflicts with its seal or packaged ID")
        self.save_reference(report.bundle, report.merkle)
        self.put_once(f"reports/{report_id}.json", report.model_dump(mode="json", by_alias=True))

    def save_reference(self, bundle, merkle):
        report_id = report_key(bundle.report_id)
        if self.fixtures.get(report_id) or seal_bundle(bundle) != merkle:
            raise StorageUnavailableError("Invalid immutable reference")
        reference = {"root": merkle.root, "schema_hash": SCHEMA_HASH_HEX,
            "timestamp": int(datetime.fromisoformat(bundle.created_at.replace("Z", "+00:00")).timestamp())}
        self.put_once(f"references/{report_id}.json", reference)

    def reference(self, report_id):
        report_key(report_id)
        if self.fixtures.get(report_id):
            return FixtureRegistry(self.fixtures.root).read(report_id)
        data = self.objects.get(f"references/{report_id}.json")
        if data is None:
            raise StorageUnavailableError("Independent storage reference missing")
        try:
            value = json.loads(data)
            return Anchor(value["root"], value["schema_hash"], value["timestamp"])
        except (ValueError, KeyError, TypeError):
            raise StorageUnavailableError("Independent storage reference invalid") from None

    def close(self):
        return None


class DurableControls:
    def __init__(self, objects):
        self.objects = objects

    def consume(self, bucket, limit):
        # Each slot is an atomic immutable create at the provider, across instances.
        for slot in range(limit):
            key = f"controls/quotas/{bucket}/{slot}.json"
            if self.objects.get(key) is not None:
                continue
            try:
                self.objects.create(key, b"{}")
                return
            except ObjectExistsError:
                continue
        raise QuotaExceededError("Durable quota exhausted")

    def scan(self, client, settings):
        hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
        client_hash = hashlib.sha256(client.encode()).hexdigest()
        self.consume(f"scan-client/{hour}/{client_hash}", settings.scan_client_limit)
        self.consume(f"scan-global/{hour}", settings.scan_hourly_limit)

    @contextmanager
    def lease(self, key):
        key = f"controls/leases/{key}.json"
        try:
            etag = self.objects.create(key, b"{}")
        except ObjectExistsError:
            raise QuotaExceededError("Operation already active; retry later") from None
        try:
            yield
        finally:
            self.objects.delete(key, etag)
