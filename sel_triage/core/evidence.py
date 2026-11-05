"""Redacted, hashed evidence artifacts for triage runs."""

import hashlib
import io
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


_SAFE_NAME = re.compile(r"[^a-z0-9]+")
_SAFE_EXTENSION = re.compile(r"^[a-z0-9]+$")


def default_evidence_root() -> Path:
    """Return a private user-data location outside the working directory."""

    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(
            os.environ.get(
                "LOCALAPPDATA",
                str(Path.home() / "AppData" / "Local"),
            )
        )
    else:
        base = Path(
            os.environ.get(
                "XDG_DATA_HOME",
                str(Path.home() / ".local" / "share"),
            )
        )
    return (base / "sel-triage" / "evidence").resolve()


@dataclass(frozen=True)
class EvidenceRef:
    """A relative reference to one immutable evidence artifact."""

    path: str
    sha256: str
    bytes: int
    media_type: str

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "media_type": self.media_type,
        }


def _safe_directory_name(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("{0} must be nonempty".format(field))
    safe = _SAFE_NAME.sub("-", value.lower()).strip("-")
    if not safe:
        raise ValueError("{0} has no safe filename characters".format(field))
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return "{0}-{1}".format(safe, digest)


def _validate_kind(kind: str) -> str:
    if not isinstance(kind, str) or not kind.strip():
        raise ValueError("kind must be nonempty")
    if "/" in kind or "\\" in kind:
        raise ValueError("kind must not contain path separators")
    safe = _SAFE_NAME.sub("-", kind.lower()).strip("-")
    if not safe:
        raise ValueError("kind has no safe filename characters")
    return safe


class EvidenceStore:
    """Store one target's evidence beneath a safe run-specific directory."""

    def __init__(
        self,
        root: Path,
        run_id: str,
        target_name: str,
        max_artifact_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        if (
            isinstance(max_artifact_bytes, bool)
            or not isinstance(max_artifact_bytes, int)
            or max_artifact_bytes < 1
        ):
            raise ValueError("max artifact bytes must be a positive integer")
        self.root = Path(root)
        self.max_artifact_bytes = max_artifact_bytes
        self._relative_directory = Path(
            _safe_directory_name(run_id, "run id"),
            _safe_directory_name(target_name, "target name"),
        )
        self.directory = self.root / self._relative_directory
        self._directory_fd = None
        self._prepare_directories()
        self._evidence: List[EvidenceRef] = []

    def close(self) -> None:
        descriptor = self._directory_fd
        self._directory_fd = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def write_text(
        self, kind: str, text: str, secrets: Tuple[str, ...] = ()
    ) -> EvidenceRef:
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        redacted = text
        for secret in secrets:
            if not isinstance(secret, str):
                raise ValueError("secrets must contain strings")
            if secret:
                redacted = redacted.replace(secret, "[REDACTED]")
        return self._write(kind, redacted.encode("utf-8"), "txt", "text/plain; charset=utf-8")

    def write_bytes(
        self,
        kind: str,
        data: bytes,
        extension: str = "bin",
        media_type: str = "application/octet-stream",
    ) -> EvidenceRef:
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")
        if not isinstance(extension, str) or not _SAFE_EXTENSION.fullmatch(extension):
            raise ValueError("extension must contain only lowercase letters and digits")
        if not isinstance(media_type, str) or not media_type.strip():
            raise ValueError("media type must be nonempty")
        return self._write(kind, data, extension, media_type)

    def write_manifest(self) -> Path:
        payload = {"evidence": [ref.as_dict() for ref in self._evidence]}
        serialized = io.StringIO()
        json.dump(payload, serialized, sort_keys=True)
        encoded = serialized.getvalue().encode("utf-8")
        number = 1
        while True:
            suffix = "" if number == 1 else "-{0}".format(number)
            manifest = self.directory / "manifest{0}.json".format(suffix)
            if self._write_exclusive(manifest, encoded):
                return manifest
            number += 1

    def _write(self, kind: str, data: bytes, extension: str, media_type: str) -> EvidenceRef:
        stem = _validate_kind(kind)
        if len(data) > self.max_artifact_bytes:
            raise ValueError(
                "artifact exceeds maximum size of {0} bytes".format(
                    self.max_artifact_bytes
                )
            )
        number = 1
        while True:
            path = self._candidate_path(stem, extension, number)
            if self._write_exclusive(path, data):
                break
            number += 1
        relative_path = path.relative_to(self.root).as_posix()
        reference = EvidenceRef(
            path=relative_path,
            sha256=hashlib.sha256(data).hexdigest(),
            bytes=len(data),
            media_type=media_type,
        )
        self._evidence.append(reference)
        return reference

    def _candidate_path(self, stem: str, extension: str, number: int) -> Path:
        suffix = "" if number == 1 else "-{0}".format(number)
        return self.directory / "{0}{1}.{2}".format(stem, suffix, extension)

    def _write_exclusive(self, path: Path, data: bytes) -> bool:
        temporary = self._write_temporary(path, data)
        try:
            try:
                if self._directory_fd is None:
                    os.link(str(temporary), str(path))
                else:
                    os.link(
                        temporary,
                        path.name,
                        src_dir_fd=self._directory_fd,
                        dst_dir_fd=self._directory_fd,
                        follow_symlinks=False,
                    )
            except FileExistsError:
                return False
            if os.name != "nt":
                if self._directory_fd is None:
                    os.chmod(str(path), 0o600)
                else:
                    os.chmod(
                        path.name,
                        0o600,
                        dir_fd=self._directory_fd,
                        follow_symlinks=False,
                    )
            return True
        finally:
            try:
                if self._directory_fd is None:
                    Path(temporary).unlink()
                else:
                    os.unlink(temporary, dir_fd=self._directory_fd)
            except FileNotFoundError:
                pass

    def _write_temporary(self, path: Path, data: bytes) -> object:
        temporary_name = ".{0}.{1}.tmp".format(path.name, uuid.uuid4().hex)
        temporary = path.parent / temporary_name
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if self._directory_fd is None:
                descriptor = os.open(str(temporary), flags, 0o600)
            else:
                descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=self._directory_fd,
                )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
        except Exception:
            try:
                if self._directory_fd is None:
                    temporary.unlink()
                else:
                    os.unlink(temporary_name, dir_fd=self._directory_fd)
            except FileNotFoundError:
                pass
            raise
        return temporary if self._directory_fd is None else temporary_name

    def _prepare_directories(self) -> None:
        if self.root.is_symlink():
            raise ValueError("evidence root must not be a symlink")
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("evidence root must not be a symlink")

        if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
            self._prepare_directories_fallback()
            return

        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        root_fd = None
        run_fd = None
        try:
            root_fd = os.open(str(self.root), flags)
            os.fchmod(root_fd, 0o700)
            run_name, target_name = self._relative_directory.parts
            run_fd = self._open_private_directory(root_fd, run_name, flags)
            self._directory_fd = self._open_private_directory(
                run_fd, target_name, flags
            )
        except OSError as exc:
            self.close()
            raise ValueError(
                "evidence path contains a symlink or unsafe component"
            ) from exc
        finally:
            if run_fd is not None:
                os.close(run_fd)
            if root_fd is not None:
                os.close(root_fd)

        self._verify_containment()

    def _open_private_directory(
        self, parent_fd: int, name: str, flags: int
    ) -> int:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("evidence path component must not be a symlink")
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o700)
        return descriptor

    def _prepare_directories_fallback(self) -> None:
        current = self.root
        if os.name != "nt":
            os.chmod(str(current), 0o700)
        for component in self._relative_directory.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("evidence path component must not be a symlink")
            current.mkdir(mode=0o700, exist_ok=True)
            if current.is_symlink() or not current.is_dir():
                raise ValueError("evidence path component must not be a symlink")
            if os.name != "nt":
                os.chmod(str(current), 0o700)
        self._verify_containment()

    def _verify_containment(self) -> None:
        resolved_root = self.root.resolve(strict=True)
        resolved_directory = self.directory.resolve(strict=True)
        try:
            resolved_directory.relative_to(resolved_root)
        except ValueError:
            self.close()
            raise ValueError("evidence directory escaped its configured root")
