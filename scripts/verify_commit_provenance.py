from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.request


APPROVED_NAME = "Krishna"
APPROVED_EMAIL = "krishna0605@users.noreply.github.com"
FORBIDDEN_TRAILER = re.compile(
    r"^Co-Authored-By:.*(?:Claude|Anthropic|Codex|OpenAI|AI assistant)",
    re.IGNORECASE | re.MULTILINE,
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, encoding="utf-8").strip()


def github_verified(repository: str, commit: str, token: str) -> bool:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/commits/{commit}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Netra-Commit-Provenance/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        document = json.load(response)
    return bool(document.get("commit", {}).get("verification", {}).get("verified"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the newly pushed Netra commit range.")
    parser.add_argument("--before", default="")
    parser.add_argument("--after", required=True)
    parser.add_argument("--github-repository", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN", ""))
    args = parser.parse_args()

    before = args.before.strip().lower()
    after = args.after.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", after):
        raise ValueError("after must be a full Git SHA")
    revision = after if not before or set(before) == {"0"} else f"{before}..{after}"
    commits = git("rev-list", "--reverse", revision).splitlines()
    if not commits:
        raise RuntimeError("No commits were selected for provenance verification")

    for commit in commits:
        fields = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%G?%x00%B", commit).split("\x00", 5)
        author_name, author_email, committer_name, committer_email, signature, message = fields
        if (author_name, author_email) != (APPROVED_NAME, APPROVED_EMAIL):
            raise RuntimeError(f"{commit}: unapproved author {author_name} <{author_email}>")
        if (committer_name, committer_email) != (APPROVED_NAME, APPROVED_EMAIL):
            raise RuntimeError(f"{commit}: unapproved committer {committer_name} <{committer_email}>")
        if FORBIDDEN_TRAILER.search(message):
            raise RuntimeError(f"{commit}: forbidden AI co-author trailer")
        if args.github_repository and args.github_token:
            verified = github_verified(args.github_repository, commit, args.github_token)
        else:
            verified = signature == "G"
        if not verified:
            raise RuntimeError(f"{commit}: signature is not verified")

    print(f"Verified {len(commits)} signed Krishna-only commit(s) through {after}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
