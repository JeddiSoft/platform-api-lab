import os
import time
import subprocess
from pathlib import Path

import jwt
import requests


GITHUB_API_URL = "https://api.github.com"

GITHUB_ORG = os.environ["GITHUB_ORG"]
GITHUB_APP_ID = os.environ["GITHUB_APP_ID"]
GITHUB_APP_PRIVATE_KEY_PATH = os.environ["GITHUB_APP_PRIVATE_KEY_PATH"]


def build_github_app_jwt() -> str:
    with open(GITHUB_APP_PRIVATE_KEY_PATH, "r") as key_file:
        private_key = key_file.read()

    now = int(time.time())

    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": GITHUB_APP_ID,
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )


def get_installation_token() -> str:
    app_jwt = build_github_app_jwt()

    installation_response = requests.get(
        f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}/installation",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )

    installation_response.raise_for_status()

    installation_id = installation_response.json()["id"]

    token_response = requests.post(
        f"{GITHUB_API_URL}/app/installations/"
        f"{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )

    token_response.raise_for_status()

    return token_response.json()["token"]


def create_repository(repository_name: str) -> dict:
    token = get_installation_token()

    response = requests.post(
        f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}/repos",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={
            "name": repository_name,
            "description": "Application provisioned by Platform API",
            "private": False,
            "auto_init": False,
        },
        timeout=10,
    )

    response.raise_for_status()

    return response.json()


def push_repository(
    source_dir: Path,
    repository_name: str,
) -> None:
    token = get_installation_token()

    repository_url = (
        f"https://x-access-token:{token}"
        f"@github.com/{GITHUB_ORG}/{repository_name}.git"
    )

    commands = [
        ["git", "init", "-b", "main"],
        [
            "git", "config",
            "user.name",
            "jeddisoft-platform-automation",
        ],
        [
            "git", "config",
            "user.email",
            "platform-automation@users.noreply.github.com",
        ],
        ["git", "add", "."],
        [
            "git", "commit",
            "-m",
            "Bootstrap application from Golden Path",
        ],
        ["git", "remote", "add", "origin", repository_url],
        ["git", "push", "-u", "origin", "main"],
    ]

    try:
        for command in commands:
            subprocess.run(
                command,
                cwd=source_dir,
                check=True,
                capture_output=True,
                text=True,
            )

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Git command failed: {exc.stderr}"
        ) from exc

def list_organization_teams() -> list:
    token = get_installation_token()

    response = requests.get(
        f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}/teams",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )

    response.raise_for_status()

    return [
        {
            "name": team["name"],
            "slug": team["slug"],
        }
        for team in response.json()
    ]        

def grant_team_repository_permission(
    team_slug: str,
    repository_name: str,
    permission: str,
) -> None:

    token = get_installation_token()

    response = requests.put(
        (
            f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}"
            f"/teams/{team_slug}/repos/{GITHUB_ORG}/{repository_name}"
        ),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={
            "permission": permission,
        },
        timeout=10,
    )

    response.raise_for_status()

def list_organization_rulesets() -> list:
    token = get_installation_token()

    response = requests.get(
        f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}/rulesets",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )

    response.raise_for_status()

    return [
        {
            "id": ruleset["id"],
            "name": ruleset["name"],
            "enforcement": ruleset["enforcement"],
            "target": ruleset["target"],
        }
        for ruleset in response.json()
    ]

def get_organization_ruleset(ruleset_id: int) -> dict:
    token = get_installation_token()

    response = requests.get(
        f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}/rulesets/{ruleset_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )

    response.raise_for_status()

    return response.json()


def build_ruleset_update_payload(
    ruleset: dict,
    repository_id: int,
) -> dict:

    conditions = ruleset["conditions"].copy()

    repository_ids = list(
        conditions["repository_id"]["repository_ids"]
    )

    if repository_id not in repository_ids:
        repository_ids.append(repository_id)

    conditions["repository_id"] = {
        "repository_ids": repository_ids
    }

    return {
        "name": ruleset["name"],
        "target": ruleset["target"],
        "enforcement": ruleset["enforcement"],
        "conditions": conditions,
        "rules": ruleset["rules"],
        "bypass_actors": ruleset["bypass_actors"],
    }

def update_organization_ruleset(
    ruleset_id: int,
    payload: dict,
) -> dict:

    token = get_installation_token()

    response = requests.put(
        f"{GITHUB_API_URL}/orgs/{GITHUB_ORG}/rulesets/{ruleset_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json=payload,
        timeout=10,
    )

    response.raise_for_status()

    return response.json()

APPLICATION_RULESET_IDS = [
    22359466,  # Develop protegida
    22308000,  # Main protegida
    22306234,  # dev-pre-checks
    22389677,  # prod-pre-checks
]


def enroll_repository_in_governance(repository_id: int) -> None:
    for ruleset_id in APPLICATION_RULESET_IDS:
        ruleset = get_organization_ruleset(ruleset_id)

        payload = build_ruleset_update_payload(
            ruleset,
            repository_id,
        )

        update_organization_ruleset(
            ruleset_id,
            payload,
        )