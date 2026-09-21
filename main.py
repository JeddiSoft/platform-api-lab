from typing import Literal

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from kubernetes import client, config

from pathlib import Path
import shutil

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from github_client import (
    create_repository,
    push_repository,
    grant_team_repository_permission,
    enroll_repository_in_governance,
)
from tempfile import TemporaryDirectory
from kubernetes.client.rest import ApiException


QUOTA_PROFILES = {
    "small": {
        "cpu": "2",
        "memory": "4Gi",
        "pods": "10"
    },
    "medium": {
        "cpu": "8",
        "memory": "16Gi",
        "pods": "30"
    },
    "large": {
        "cpu": "16",
        "memory": "32Gi",
        "pods": "60"
    }
}

GITHUB_ORG = "JeddiSoft"

TEMPLATES_ROOT = Path("../platform-templates")


# ============================================================
# 1. FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Platform API",
    version="0.2.0",
    description="Internal Platform API for governed Kubernetes capabilities"
)


# ============================================================
# 2. KUBERNETES CONNECTION
# ============================================================
#
# The Platform API uses its own Kubernetes identity.
#
# platform-api.kubeconfig contains the token associated with:
#
#   ServiceAccount:
#       platform-system / platform-api
#
# Kubernetes RBAC restricts that identity to the operations
# explicitly granted to the Platform API.
#

config.load_kube_config(
    config_file="platform-api.kubeconfig"
)

k8s = client.CoreV1Api()


# ============================================================
# 3. API AUTHENTICATION
# ============================================================
#
# Protected endpoints expect:
#
#   Authorization: Bearer <token>
#
# These tokens are intentionally simple for the laboratory.
# In production this layer would normally be replaced by
# OIDC / OAuth2 and a corporate Identity Provider.
#

security = HTTPBearer()


# ============================================================
# 4. LAB USERS / TOKENS
# ============================================================
#
# Northbound authentication:
#
#   Consumer -> Platform API
#
# These are NOT Kubernetes tokens.
# They only authenticate consumers against our Platform API.
#

TOKENS = {
    "viewer-token": {
        "username": "viewer-user",
        "role": "viewer"
    },

    "developer-token": {
        "username": "developer-user",
        "role": "developer"
    }
}


# ============================================================
# 5. PLATFORM REQUEST MODEL
# ============================================================
#
# IMPORTANT:
#
# The consumer no longer chooses the Kubernetes namespace name.
#
# Instead, the consumer expresses intent:
#
#   application
#   team
#   environment
#   size
#
# The Platform API derives the Kubernetes implementation.
#
# Literal automatically restricts environment and size to the
# supported Golden Path values.
#

class NamespaceRequest(BaseModel):

    application: str = Field(
        min_length=3,
        max_length=30,
        description="Application name"
    )

    team: str = Field(
        min_length=3,
        max_length=30,
        description="Owning team"
    )

    environment: Literal[
        "dev",
        "test",
        "prod"
    ]

    size: Literal[
        "small",
        "medium",
        "large"
    ]

class ApplicationRequest(BaseModel):

    application: str = Field(
        min_length=3,
        max_length=30,
        description="Application name"
    )

    repository: str = Field(
        min_length=3,
        max_length=100,
        description="GitHub repository name"
    )

    team: str = Field(
        min_length=3,
        max_length=30,
        description="Owning team"
    )

    template: Literal[
        "python-kubernetes"
    ] = "python-kubernetes"



# ============================================================
# 6. AUTHENTICATION
# ============================================================
#
# Authentication answers:
#
#   "Who are you?"
#
# The Bearer Token identifies the Platform API consumer.
#

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    user = TOKENS.get(token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )

    return user


# ============================================================
# 7. AUTHORIZATION
# ============================================================
#
# Authorization answers:
#
#   "What are you allowed to do?"
#
# viewer:
#   GET namespaces
#
# developer:
#   GET namespaces
#   POST namespaces
#

def require_developer(
    user=Depends(get_current_user)
):

    if user["role"] != "developer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )

    return user


# ============================================================
# 8. PLATFORM NAMING POLICY
# ============================================================
#
# Namespace names are generated by the platform.
#
# The consumer requests:
#
#   application = payments
#   environment = dev
#
# The platform generates:
#
#   payments-dev
#
# This prevents consumers from defining arbitrary Kubernetes
# namespace names and establishes a predictable convention.
#

def build_namespace_name(
    request: NamespaceRequest
) -> str:

    return f"{request.application}-{request.environment}".lower()

def provision_namespace(
    application: str,
    team: str,
    environment: str,
    size: str
):

    namespace_name = f"{application}-{environment}".lower()
    quota_profile = QUOTA_PROFILES[size]

    namespace = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace_name,
            labels={
                "platform.company/application": application,
                "platform.company/team": team,
                "platform.company/environment": environment,
                "platform.company/size": size,
                "platform.company/managed-by": "platform-api"
            }
        )
    )

    quota = client.V1ResourceQuota(
        metadata=client.V1ObjectMeta(
            name="platform-quota",
            namespace=namespace_name,
            labels={
                "platform.company/managed-by": "platform-api",
                "platform.company/profile": size
            }
        ),
        spec=client.V1ResourceQuotaSpec(
            hard={
                "requests.cpu": quota_profile["cpu"],
                "requests.memory": quota_profile["memory"],
                "pods": quota_profile["pods"]
            }
        )
    )

    try:
        k8s.create_namespace(namespace)

    except ApiException as exc:
        if exc.status != 409:
            raise

        existing = k8s.read_namespace(namespace_name)

        labels = existing.metadata.labels or {}

        if labels.get("platform.company/managed-by") != "platform-api":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Namespace '{namespace_name}' already exists "
                    "and is not managed by Platform API"
                )
            )

    try:
        k8s.create_namespaced_resource_quota(
            namespace=namespace_name,
            body=quota
        )

    except ApiException as exc:
        if exc.status != 409:
            raise

        existing_quota = k8s.read_namespaced_resource_quota(
            name="platform-quota",
            namespace=namespace_name
        )

        labels = existing_quota.metadata.labels or {}

        if labels.get("platform.company/managed-by") != "platform-api":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"ResourceQuota in '{namespace_name}' already exists "
                    "and is not managed by Platform API"
                )
            )

    return {
        "namespace": namespace_name,
        "size": size,
        "quota": {
            "cpu": quota_profile["cpu"],
            "memory": quota_profile["memory"],
            "pods": quota_profile["pods"]
        }
    }


def render_application(
    request: ApplicationRequest,
    output_root: Path
) -> Path:

    template_dir = TEMPLATES_ROOT / request.template
    output_dir = output_root / request.repository

    if not template_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Template '{request.template}' does not exist"
        )

    if output_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Application '{request.repository}' already exists"
        )

    env = Environment(
        loader=FileSystemLoader(template_dir),
        keep_trailing_newline=True,
        undefined=StrictUndefined
    )

    context = {
        "application_name": request.application,
        "repository_name": request.repository,
        "github_org": GITHUB_ORG
    }

    try:

        for source_path in template_dir.rglob("*"):

            if source_path.is_dir():
                continue

            relative_path = source_path.relative_to(template_dir)

            template = env.get_template(str(relative_path))
            rendered = template.render(**context)

            destination = output_dir / relative_path
            destination.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            destination.write_text(rendered)

    except Exception:

        # Avoid leaving a partially rendered application.
        if output_dir.exists():
            shutil.rmtree(output_dir)

        raise

    return output_dir



# ============================================================
# 9. HEALTH ENDPOINT
# ============================================================
#
# Public endpoint.
#
# This endpoint intentionally does not require authentication.
# It can later be used by:
#
#   - monitoring
#   - Kubernetes probes
#   - load balancers
#

@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# ============================================================
# 10. LIST NAMESPACES
# ============================================================
#
# Any authenticated Platform API consumer can list namespaces.
#
# The Kubernetes operation itself is executed using the
# ServiceAccount configured in platform-api.kubeconfig.
#

@app.get("/api/v1/namespaces")
def list_namespaces(
    user=Depends(get_current_user)
):

    namespaces = k8s.list_namespace()

    return {
        "requested_by": user["username"],
        "items": [
            {
                "name": ns.metadata.name,
                "status": ns.status.phase
            }
            for ns in namespaces.items
        ]
    }


# ============================================================
# 11. CREATE NAMESPACE
# ============================================================
#
# Only consumers with the developer role can use this endpoint.
#
# Notice the separation of responsibilities:
#
# Consumer:
#   expresses intent
#
# Platform API:
#   validates request
#   applies naming policy
#   generates Kubernetes metadata
#
# Kubernetes:
#   enforces RBAC and creates the resource
#

@app.post(
    "/api/v1/namespaces",
    status_code=status.HTTP_201_CREATED
)
def create_namespace(
    request: NamespaceRequest,
    user=Depends(require_developer)
):

    result = provision_namespace(
        application=request.application,
        team=request.team,
        environment=request.environment,
        size=request.size
    )

    return {
        "status": "created",
        "namespace": result["namespace"],
        "application": request.application,
        "team": request.team,
        "environment": request.environment,
        "size": result["size"],
        "quota": result["quota"],
        "requested_by": user["username"]
    }
@app.post(
    "/api/v1/applications",
    status_code=status.HTTP_201_CREATED
)
def create_application(
    request: ApplicationRequest,
    user=Depends(require_developer)
):

    with TemporaryDirectory(
        prefix="platform-"
    ) as temp_dir:

        output_root = Path(temp_dir)

        # 1. Render Golden Path
        output_dir = render_application(
            request,
            output_root
        )

        # 2. Provision runtime environments
        dev_namespace = provision_namespace(
            application=request.application,
            team=request.team,
            environment="dev",
            size="small"
        )

        prod_namespace = provision_namespace(
            application=request.application,
            team=request.team,
            environment="prod",
            size="medium"
        )

        # 3. Create GitHub repository
        github_repository = create_repository(
            request.repository
        )

        grant_team_repository_permission(
            team_slug="developers",
            repository_name=request.repository,
            permission="push",
        )

        grant_team_repository_permission(
            team_slug="platform-team",
            repository_name=request.repository,
            permission="maintain",
        )

        enroll_repository_in_governance(
            github_repository["id"]
        )

        # 4. Bootstrap repository
        push_repository(
            output_dir,
            request.repository
        )

        github_repository_url = github_repository["html_url"]

    return {
        "status": "created",
        "application": request.application,
        "repository": request.repository,
        "team": request.team,
        "template": request.template,
        "github_org": GITHUB_ORG,
        "github_repository": github_repository_url,
        "namespaces": {
            "dev": dev_namespace,
            "prod": prod_namespace
        },
        "requested_by": user["username"]
    }