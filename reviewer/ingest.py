from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from git import Git, Repo

MAX_PYTHON_FILES = 400
MAX_PYTHON_BYTES = 25 * 1024 * 1024
MAX_CHECKOUT_BYTES = 100 * 1024 * 1024
MAX_REPOSITORY_FILES = 5000
CLONE_TIMEOUT_SECONDS = 90


@dataclass(frozen=True)
class RepositorySnapshot:
	url: str
	root: Path
	python_files: list[Path]


def validate_github_url(repository_url: str) -> str:
	parsed = urlparse(repository_url.strip())
	parts = [part for part in parsed.path.strip("/").split("/") if part]
	if (
		parsed.scheme != "https"
		or parsed.hostname != "github.com"
		or parsed.username
		or parsed.password
		or parsed.query
		or parsed.fragment
		or len(parts) != 2
		or any(part in {".", ".."} for part in parts)
	):
		raise ValueError("Enter a public GitHub URL in the form https://github.com/owner/repository.")
	repository = parts[1].removesuffix(".git")
	if not repository or not parts[0]:
		raise ValueError("The GitHub URL must include an owner and repository name.")
	return f"https://github.com/{parts[0]}/{repository}.git"


def _collect_python_files(root: Path) -> tuple[list[Path], int]:
	files: list[Path] = []
	python_bytes = 0
	checkout_bytes = 0
	for current, directories, filenames in os.walk(root, followlinks=False):
		directories[:] = [name for name in directories if name != ".git"]
		current_path = Path(current)
		for filename in filenames:
			path = current_path / filename
			if path.is_symlink() or not path.is_file():
				continue
			size = path.stat().st_size
			checkout_bytes += size
			if checkout_bytes > MAX_CHECKOUT_BYTES:
				raise ValueError("Repository checkout exceeds the 100 MB size limit.")
			if path.suffix.lower() == ".py":
				files.append(path)
				python_bytes += size
				if len(files) > MAX_PYTHON_FILES:
					raise ValueError("Repository exceeds the 400 Python-file limit.")
				if python_bytes > MAX_PYTHON_BYTES:
					raise ValueError("Python source files exceed the 25 MB size limit.")
	return sorted(files), python_bytes


def _tracked_python_paths(repo: Repo) -> list[str]:
	python_paths: list[str] = []
	python_bytes = 0
	repository_bytes = 0
	repository_files = 0
	for entry in repo.head.commit.tree.traverse():
		if entry.type != "blob":
			continue
		repository_files += 1
		repository_bytes += entry.size
		if repository_files > MAX_REPOSITORY_FILES:
			raise ValueError("Repository exceeds the 5,000 tracked-file limit.")
		if repository_bytes > MAX_CHECKOUT_BYTES:
			raise ValueError("Repository tracked files exceed the 100 MB size limit.")
		if entry.mode == 0o120000 or not entry.path.lower().endswith(".py"):
			continue
		python_paths.append(entry.path)
		python_bytes += entry.size
		if len(python_paths) > MAX_PYTHON_FILES:
			raise ValueError("Repository exceeds the 400 Python-file limit.")
		if python_bytes > MAX_PYTHON_BYTES:
			raise ValueError("Python source files exceed the 25 MB size limit.")
	return python_paths


@contextmanager
def repository_workspace(repository_url: str):
	normalized_url = validate_github_url(repository_url)
	with tempfile.TemporaryDirectory(prefix="ai-code-review-") as temporary_directory:
		destination = Path(temporary_directory) / "repository"
		environment = os.environ.copy()
		environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https"})
		try:
			Git().execute(
				[
					"git",
					"clone",
					"--depth=1",
					"--filter=blob:limit=2m",
					"--no-tags",
					"--no-checkout",
					"--",
					normalized_url,
					str(destination),
				],
				env=environment,
				kill_after_timeout=CLONE_TIMEOUT_SECONDS,
			)
		except Exception as error:
			raise RuntimeError(f"Could not clone the repository: {error}") from error

		try:
			repo = Repo(destination, search_parent_directories=False)
			python_paths = _tracked_python_paths(repo)
		except (OSError, ValueError) as error:
			raise RuntimeError(str(error)) from error
		except Exception as error:
			raise RuntimeError(f"Could not inspect the cloned repository: {error}") from error

		if python_paths:
			try:
				repo.git.execute(
					["git", "checkout", "HEAD", "--", *python_paths],
					kill_after_timeout=CLONE_TIMEOUT_SECONDS,
				)
			except Exception as error:
				raise RuntimeError(f"Could not check out Python source files: {error}") from error
		try:
			python_files, _ = _collect_python_files(destination)
		except (OSError, ValueError) as error:
			raise RuntimeError(str(error)) from error
		yield RepositorySnapshot(normalized_url, destination, python_files)
