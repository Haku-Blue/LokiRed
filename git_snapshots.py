"""Read-only Git ref snapshot materialization for LokiRed comparisons."""

from __future__ import annotations

import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator

from policy import DEFAULT_POLICY_FILENAMES
from security_file_scanner import classify_config_file


class GitSnapshotError(ValueError):
    """Raised when a Git ref cannot be safely materialized for scanning."""


@dataclass(frozen=True)
class GitRefSnapshot:
    """Materialized read-only view of supported LokiRed files at one Git ref."""

    ref: str
    commit: str
    root_path: Path
    files: tuple[str, ...]


@dataclass(frozen=True)
class GitRefPair:
    """Base/head snapshot pair from the same repository."""

    repository_path: Path
    base: GitRefSnapshot
    head: GitRefSnapshot


@contextmanager
def materialize_git_ref_pair(
    repository_path: str,
    base_ref: str,
    head_ref: str,
) -> Iterator[GitRefPair]:
    """Materialize supported static artifacts from two Git refs into temp dirs."""
    repo = resolve_repository_path(repository_path)
    base_commit = resolve_ref(repo, base_ref)
    head_commit = resolve_ref(repo, head_ref)

    with tempfile.TemporaryDirectory(prefix="lokired-git-refs-") as temp_dir:
        temp_root = Path(temp_dir)
        base_root = temp_root / "base"
        head_root = temp_root / "head"
        base_files = _materialize_ref(repo, base_commit, base_root)
        head_files = _materialize_ref(repo, head_commit, head_root)
        yield GitRefPair(
            repository_path=repo,
            base=GitRefSnapshot(base_ref, base_commit, base_root, tuple(base_files)),
            head=GitRefSnapshot(head_ref, head_commit, head_root, tuple(head_files)),
        )


def resolve_repository_path(repository_path: str) -> Path:
    """Return the repository top-level path for a Git worktree."""
    requested = Path(repository_path).expanduser()
    if not requested.exists():
        raise GitSnapshotError(f"Repository path does not exist: {requested}")
    result = _run_git_text(requested, ["rev-parse", "--show-toplevel"])
    return Path(result.strip()).resolve()


def resolve_ref(repository_path: Path, ref: str) -> str:
    """Resolve a user-supplied ref to a commit SHA without checking it out."""
    if not ref or ref.strip() != ref:
        raise GitSnapshotError(f"Malformed Git ref: {ref!r}")
    try:
        return _run_git_text(repository_path, ["rev-parse", "--verify", f"{ref}^{{commit}}"]).strip()
    except GitSnapshotError as error:
        raise GitSnapshotError(f"Unable to resolve Git ref {ref!r}: {error}") from error


def _materialize_ref(repository_path: Path, commit: str, output_root: Path) -> list[str]:
    output_root.mkdir(parents=True, exist_ok=True)
    files = _supported_tree_paths(repository_path, commit)
    for relative_path in files:
        destination = _safe_destination(output_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_read_blob(repository_path, commit, relative_path))
    return files


def _supported_tree_paths(repository_path: Path, commit: str) -> list[str]:
    result = _run_git_bytes(repository_path, ["ls-tree", "-r", "-z", "--name-only", commit])
    paths = [
        path.decode("utf-8", errors="surrogateescape")
        for path in result.split(b"\0")
        if path
    ]
    return sorted(path for path in paths if _is_supported_static_artifact(path))


def _is_supported_static_artifact(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    if normalized in DEFAULT_POLICY_FILENAMES:
        return True
    return classify_config_file(PurePosixPath(normalized)) is not None


def _read_blob(repository_path: Path, commit: str, relative_path: str) -> bytes:
    return _run_git_bytes(repository_path, ["cat-file", "-p", f"{commit}:{relative_path}"])


def _safe_destination(output_root: Path, relative_path: str) -> Path:
    posix_path = PurePosixPath(relative_path)
    if posix_path.is_absolute() or any(part in {"", ".", ".."} for part in posix_path.parts):
        raise GitSnapshotError(f"Unsafe Git tree path: {relative_path!r}")
    destination = output_root.joinpath(*posix_path.parts).resolve()
    root = output_root.resolve()
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise GitSnapshotError(f"Unsafe Git tree path: {relative_path!r}") from error
    return destination


def _run_git_text(cwd: Path, args: list[str]) -> str:
    return _run_git(cwd, args, text=True)


def _run_git_bytes(cwd: Path, args: list[str]) -> bytes:
    return _run_git(cwd, args, text=False)


def _run_git(cwd: Path, args: list[str], *, text: bool) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(cwd), *args],
            check=False,
            capture_output=True,
            text=text,
        )
    except OSError as error:
        raise GitSnapshotError(f"Unable to run git: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode("utf-8", errors="replace")
        message = stderr.strip() or f"git exited with status {completed.returncode}"
        raise GitSnapshotError(message)
    return completed.stdout
