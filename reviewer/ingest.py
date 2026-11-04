from __future__ import annotations

import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests
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
	description: str = ""


@dataclass(frozen=True)
class GitHubTarget:
	owner: str
	repo: str
	ref: str | None = None
	pull_request: int | None = None

	@property
	def clone_url(self) -> str:
		return f"https://github.com/{self.owner}/{self.repo}.git"

	@property
	def description(self) -> str:
		if self.pull_request:
			return f"Pull request #{self.pull_request} (changed Python files only)"
		if self.ref:
			return f"Branch/ref: {self.ref}"
		return "Default branch"


_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9._/-]+$")


def parse_github_target(repository_url: str) -> GitHubTarget:
	"""Accepts repo URLs, /tree/<branch> URLs and /pull/<n> URLs on github.com over HTTPS."""
	message = "Enter a public GitHub URL: https://github.com/owner/repo, .../tree/branch or .../pull/123."
	parsed = urlparse(repository_url.strip())
	parts = [part for part in parsed.path.strip("/").split("/") if part]
	if (
		parsed.scheme != "https"
		or parsed.hostname != "github.com"
		or parsed.username
		or parsed.password
		or parsed.query
		or parsed.fragment
		or len(parts) < 2
		or any(part in {".", ".."} for part in parts)
	):
		raise ValueError(message)
	owner, repository = parts[0], parts[1].removesuffix(".git")
	if not _SAFE_NAME.match(owner) or not _SAFE_NAME.match(repository):
		raise ValueError("The GitHub owner or repository name contains unsupported characters.")
	rest = parts[2:]
	if not rest:
		return GitHubTarget(owner, repository)
	if rest[0] == "pull" and len(rest) >= 2 and rest[1].isdigit():
		return GitHubTarget(owner, repository, pull_request=int(rest[1]))
	if rest[0] == "tree" and len(rest) >= 2:
		ref = "/".join(rest[1:])
		if not _SAFE_REF.match(ref) or ref.startswith("-") or ".." in ref:
			raise ValueError("The branch name contains unsupported characters.")
		return GitHubTarget(owner, repository, ref=ref)
	raise ValueError(message)


def validate_github_url(repository_url: str) -> str:
	return parse_github_target(repository_url).clone_url


def _pull_request_files(target: GitHubTarget) -> set[str] | None:
	"""Changed .py files of a PR via the public GitHub API. None if the API is unavailable."""
	changed: set[str] = set()
	headers = {"Accept": "application/vnd.github+json"}
	if os.getenv("GITHUB_TOKEN"):  # optional: lifts the 60 requests/hour anonymous API limit
		headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
	try:
		for page in range(1, 4):
			response = requests.get(
				f"https://api.github.com/repos/{target.owner}/{target.repo}/pulls/{target.pull_request}/files",
				params={"per_page": 100, "page": page},
				headers=headers,
				timeout=15,
			)
			if response.status_code != 200:
				return None
			batch = response.json()
			for item in batch:
				if item.get("status") != "removed" and str(item.get("filename", "")).lower().endswith(".py"):
					changed.add(item["filename"])
			if len(batch) < 100:
				break
	except (requests.RequestException, ValueError):
		return None
	return changed


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


def _tracked_python_paths(repo: Repo, commit: str = "HEAD") -> list[str]:
	python_paths: list[str] = []
	python_bytes = 0
	repository_bytes = 0
	repository_files = 0
	for entry in repo.commit(commit).tree.traverse():
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
	target = parse_github_target(repository_url)
	with tempfile.TemporaryDirectory(prefix="ai-code-review-") as temporary_directory:
		destination = Path(temporary_directory) / "repository"
		environment = os.environ.copy()
		environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https"})
		command = ["git", "clone", "--depth=1", "--filter=blob:limit=2m", "--no-tags", "--no-checkout"]
		if target.ref:
			command += ["--branch", target.ref]
		command += ["--", target.clone_url, str(destination)]
		try:
			Git().execute(command, env=environment, kill_after_timeout=CLONE_TIMEOUT_SECONDS)
		except Exception as error:
			raise RuntimeError(f"Could not clone the repository: {error}") from error

		description = target.description
		commit = "HEAD"
		try:
			repo = Repo(destination, search_parent_directories=False)
			if target.pull_request:
				repo.git.execute(
					["git", "fetch", "--depth=1", "origin", f"pull/{target.pull_request}/head"],
					env=environment,
					kill_after_timeout=CLONE_TIMEOUT_SECONDS,
				)
				commit = "FETCH_HEAD"
			python_paths = _tracked_python_paths(repo, commit)
			if target.pull_request:
				changed = _pull_request_files(target)
				if changed is None:
					description = f"Pull request #{target.pull_request} (changed-file list unavailable; scanned all Python files)"
				else:
					python_paths = [path for path in python_paths if path in changed]
		except (OSError, ValueError) as error:
			raise RuntimeError(str(error)) from error
		except Exception as error:
			raise RuntimeError(f"Could not inspect the cloned repository: {error}") from error

		checkout_paths = list(python_paths)
		try:
			repo.commit(commit).tree / "requirements.txt"
			checkout_paths.append("requirements.txt")
		except KeyError:
			pass
		if checkout_paths:
			try:
				repo.git.execute(
					["git", "checkout", commit, "--", *checkout_paths],
					kill_after_timeout=CLONE_TIMEOUT_SECONDS,
				)
			except Exception as error:
				raise RuntimeError(f"Could not check out Python source files: {error}") from error
		try:
			python_files, _ = _collect_python_files(destination)
		except (OSError, ValueError) as error:
			raise RuntimeError(str(error)) from error
		yield RepositorySnapshot(target.clone_url, destination, python_files, description)
