"""Git utility functions."""

import subprocess
from typing import Optional


def is_git_repo(path: str = ".") -> bool:
    """Check if path is a git repository."""
    try:
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=path,
            capture_output=True,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_git_sha(path: str = ".", short: bool = True) -> Optional[str]:
    """Get current Git SHA."""
    try:
        cmd = ["git", "rev-parse"]
        if short:
            cmd.append("--short")
        cmd.append("HEAD")

        result = subprocess.run(
            cmd,
            cwd=path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def get_git_branch(path: str = ".") -> Optional[str]:
    """Get current Git branch."""
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None
