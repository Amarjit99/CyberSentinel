"""CyberSentinel AI — Authentication & Authorization Interfaces (ADR-0004)"""

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from schemas.enums import RBACRoleEnum

_revoked_tokens: Dict[str, float] = {}
_revocation_lock = threading.Lock()


def _purge_revocations(now: Optional[float] = None) -> None:
    current = now if now is not None else time.time()
    with _revocation_lock:
        expired = [jti for jti, expires_at in _revoked_tokens.items() if expires_at <= current]
        for jti in expired:
            del _revoked_tokens[jti]


def _b64url_encode(data: bytes) -> str:
    """Base64url encode bytes without trailing padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data_str: str) -> bytes:
    """Base64url decode ASCII string with restored padding."""
    padding = "=" * (4 - (len(data_str) % 4)) if len(data_str) % 4 != 0 else ""
    return base64.urlsafe_b64decode((data_str + padding).encode("ascii"))


def create_access_token(
    subject: str,
    role: RBACRoleEnum,
    expires_in_seconds: int = 3600,
    secret_key: Optional[str] = None,
) -> str:
    """Generate a cryptographically signed HMAC-SHA256 (HS256) JWT access token."""
    secret: str = str(
        secret_key
        or os.getenv(
            "SECRET_KEY", "local_insecure_development_secret_key_minimum_32_chars_long"
        )
    )
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role.value,
        "jti": uuid4().hex,
        "iat": now,
        "exp": now + expires_in_seconds,
        "iss": "cybersentinel",
    }
    h_str = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_str = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    msg = f"{h_str}.{p_str}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    sig_str = _b64url_encode(sig)
    return f"{h_str}.{p_str}.{sig_str}"


def revoke_access_token(token: str, secret_key: Optional[str] = None) -> None:
    """Revoke a valid access token until its natural expiration time."""
    payload = verify_access_token(token, secret_key=secret_key)
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not isinstance(jti, str) or not isinstance(exp, (int, float)):
        raise ValueError("Token must contain jti and exp claims for revocation")
    _purge_revocations()
    with _revocation_lock:
        _revoked_tokens[jti] = float(exp)


def clear_revoked_tokens() -> None:
    """Clear process-local revocations for controlled test and development resets."""
    with _revocation_lock:
        _revoked_tokens.clear()


def verify_access_token(
    token: str,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify and decode a cryptographically signed HMAC-SHA256 (HS256) JWT access token.

    Raises HTTPException(401) on invalid signature, malformed structure, or expired token.
    """
    from fastapi import HTTPException, status

    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token structure. Expected standard 3-part JWT (header.payload.signature).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    h_str, p_str, sig_str = parts
    secret: str = str(
        secret_key
        or os.getenv(
            "SECRET_KEY", "local_insecure_development_secret_key_minimum_32_chars_long"
        )
    )

    # 1. Verify cryptographic signature
    msg = f"{h_str}.{p_str}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    expected_sig_str = _b64url_encode(expected_sig)

    if not hmac.compare_digest(expected_sig_str, sig_str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature. Token authenticity could not be verified.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Decode header and payload
    try:
        header = json.loads(_b64url_decode(h_str).decode("utf-8"))
        payload_data = json.loads(_b64url_decode(p_str).decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to decode token payload JSON.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not isinstance(payload_data, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload must be a valid JSON dictionary.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _purge_revocations()
    jti = payload_data.get("jti")
    if isinstance(jti, str):
        with _revocation_lock:
            if jti in _revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked. Re-authentication required.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

    if header.get("alg") != "HS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported token algorithm '{header.get('alg')}'. Expected HS256.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Check expiration
    exp = payload_data.get("exp")
    if exp is not None and time.time() > float(exp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Re-authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Check subject and role presence
    has_role_claim = (
        "role" in payload_data
        or "roles" in payload_data
        or "groups" in payload_data
    )
    if "sub" not in payload_data or not has_role_claim:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing required 'sub' or role/groups claims.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return dict(payload_data)


class Principal(BaseModel):
    """Authenticated entity (human user or autonomous agent system)."""

    id: str = Field(..., description="Unique subject identifier (user UUID or agent key)")
    name: str = Field(..., description="Human or service account display name")
    roles: List[RBACRoleEnum] = Field(default_factory=list, description="Assigned RBAC roles")
    is_active: bool = Field(default=True, description="Account active status")

    def has_role(self, role: RBACRoleEnum) -> bool:
        """Check if principal possesses the specified role or superuser admin role."""
        if RBACRoleEnum.ADMIN in self.roles:
            return True
        return role in self.roles


class AuthorizationContext(BaseModel):
    """Contextual metadata passed to policy decisions."""

    principal: Principal
    action: str = Field(
        ..., description="Action identifier, e.g., 'incident:read', 'response:approve'"
    )
    resource_type: str = Field(
        ..., description="Target resource type, e.g., 'incident', 'evidence'"
    )
    resource_id: Optional[str] = Field(default=None, description="Target resource ID")


def get_current_principal(
    authorization: Optional[str] = None,
    x_api_key: Optional[str] = None,
    x_operator_role: Optional[str] = None,
) -> Principal:
    """Extract and validate principal identity from request headers.

    Supports:
    - Authorization: Bearer <token> (Cryptographic HS256 JWT in production; dev tokens in dev/test)
    - X-API-Key: <api_key>
    - X-Operator-Role: <role_name> (testing/internal integration when explicitly permitted)
    """
    from fastapi import HTTPException, status

    is_test = "PYTEST_CURRENT_TEST" in os.environ or os.getenv("TESTING") == "1"

    # 1. Check for Bearer token
    if authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format. Expected Bearer <token>",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if the token is a standard cryptographically signed JWT (3 parts)
        if token.count(".") == 2:
            payload = verify_access_token(token)
            role: Optional[RBACRoleEnum] = None
            if "role" in payload:
                try:
                    role = RBACRoleEnum(payload["role"])
                except ValueError:
                    pass
            if not role:
                # Enterprise OIDC / IdP claims resolution (groups, roles, scopes)
                raw_roles = payload.get("roles") or payload.get("groups") or []
                if isinstance(raw_roles, str):
                    raw_roles = [raw_roles]
                for r in raw_roles:
                    r_clean = str(r).strip().lower()
                    for r_enum in RBACRoleEnum:
                        if r_clean in (r_enum.value.lower(), r_enum.name.lower()):
                            role = r_enum
                            break
                    if role:
                        break

            if not role:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token contains unrecognized role or groups: '{payload.get('role') or payload.get('groups')}'.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            user_id = str(payload.get("sub") or payload.get("email") or "oidc-user")
            user_name = str(payload.get("name") or payload.get("email") or "Authorized Operator")
            return Principal(
                id=user_id,
                name=user_name,
                roles=[role],
                is_active=True,
            )

        # Non-JWT / mock token handling:
        # Enforce that predictable mock tokens (e.g. operator-${role}-token)
        # are STRICTLY rejected in production and only accepted when development tokens are explicitly enabled.
        allow_dev_tokens = os.getenv(
            "ALLOW_DEV_TOKENS", "true" if is_test else "false"
        ).lower() in ("true", "1")

        if not allow_dev_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Unsigned mock tokens are disabled in production. Provide a valid cryptographically signed Bearer JWT token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Parse token subject and role (for local test fixtures)
        lower_token = token.lower()
        if "admin" in lower_token:
            role = RBACRoleEnum.ADMIN
        elif "manager" in lower_token:
            role = RBACRoleEnum.SOC_MANAGER
        elif "analyst" in lower_token:
            role = RBACRoleEnum.SOC_ANALYST
        elif "hunter" in lower_token:
            role = RBACRoleEnum.THREAT_HUNTER
        elif "researcher" in lower_token:
            role = RBACRoleEnum.RESEARCHER
        elif "detection" in lower_token:
            role = RBACRoleEnum.DETECTION_ENGINEER
        elif "viewer" in lower_token:
            role = RBACRoleEnum.VIEWER
        else:
            role = RBACRoleEnum.SECURITY_ENGINEER

        user_id = token if token.startswith("user-") else f"user-{token}"
        return Principal(
            id=user_id,
            name="Authorized Operator",
            roles=[role],
            is_active=True,
        )

    # 2. Check for X-API-Key
    if x_api_key:
        if len(x_api_key) < 8:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        allow_dev_api_keys = os.getenv(
            "ALLOW_DEV_API_KEYS", "true" if is_test else "false"
        ).lower() in ("true", "1")
        if not allow_dev_api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Development API keys are disabled in production.",
            )
        role = RBACRoleEnum.ADMIN if "admin" in x_api_key.lower() else RBACRoleEnum.SECURITY_ENGINEER
        return Principal(
            id=f"api-key-{x_api_key[:6]}",
            name="API Key Principal",
            roles=[role],
            is_active=True,
        )

    # 3. Check for X-Operator-Role
    if x_operator_role:
        # Enforce server-side control: client headers like X-Operator-Role cannot independently
        # grant privileges in production or when dev operator role is disabled.
        allow_dev_header = os.getenv(
            "ALLOW_DEV_OPERATOR_ROLE", "true" if is_test else "false"
        ).lower() in ("true", "1")
        if not allow_dev_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Client-controlled header 'X-Operator-Role' is disabled in production.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            assigned_role = RBACRoleEnum(x_operator_role.upper())
            elevated_roles = {
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
            }
            allow_elevated = os.getenv(
                "ALLOW_ELEVATED_DEV_HEADERS", "true" if is_test else "false"
            ).lower() in ("true", "1")
            if assigned_role in elevated_roles and not allow_elevated:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Client-controlled header 'X-Operator-Role' cannot independently grant elevated role '{assigned_role.value}'.",
                )

            return Principal(
                id="dev-operator",
                name="Development Operator",
                roles=[assigned_role],
                is_active=True,
            )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unknown operator role: {x_operator_role}",
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Authorization: Bearer <token> or X-API-Key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_roles(allowed_roles: List[RBACRoleEnum]):
    """FastAPI dependency factory enforcing that the authenticated principal possesses at least one allowed role."""
    from fastapi import Header, HTTPException, status

    def dependency(
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None),
        x_operator_role: Optional[str] = Header(default=None),
    ) -> Principal:
        principal = get_current_principal(
            authorization=authorization,
            x_api_key=x_api_key,
            x_operator_role=x_operator_role,
        )
        if not any(principal.has_role(r) for r in allowed_roles):
            allowed_names = [r.value for r in allowed_roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required one of: {allowed_names}",
            )
        return principal

    return dependency


__all__ = [
    "Principal",
    "AuthorizationContext",
    "create_access_token",
    "verify_access_token",
    "revoke_access_token",
    "clear_revoked_tokens",
    "get_current_principal",
    "require_roles",
]
