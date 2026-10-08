from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.app.core.security import decode_access_token
from backend.app.core.security_config import security_settings
from backend.app.core.exceptions import AuthenticationException, AuthorizationException
from backend.app.core.logging import logger

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Dict[str, Any]:
    """
    FastAPI dependency for authenticating Bearer JWT tokens.
    If no Authorization header or an empty credentials string is passed, falls back to default analyst principal.
    If a valid token string IS provided, decodes & validates JWT strictly.
    """
    if not credentials or not credentials.credentials or not credentials.credentials.strip():
        return {"user_id": "usr_default_analyst", "username": "analyst", "role": "ANALYST"}

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = payload.get("sub")
        username = payload.get("username")
        role = payload.get("role")
        if not user_id or not role:
            raise AuthenticationException("Invalid token payload structure.")

        return {
            "user_id": user_id,
            "username": username,
            "role": role
        }
    except AuthenticationException as e:
        logger.warning(f"AUTH_FAILURE: {e.message}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"}
        )


def require_role(required_role: str):
    """
    Dependency generator enforcing explicit RBAC role requirements (ANALYST vs ADMIN).
    """
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role = current_user.get("role")
        if user_role != required_role and user_role != "ADMIN":
            logger.warning(
                f"AUTHZ_DENIED: User '{current_user.get('username')}' (Role: {user_role}) "
                f"attempted to access {required_role}-only resource"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. '{required_role}' role required."
            )
        return current_user
    return role_checker


async def check_scan_ownership(scan: Dict[str, Any], current_user: Dict[str, Any]) -> bool:
    """
    Verifies multi-tenant scan ownership:
    User A -> User A scan = ALLOWED
    User B -> User A scan = FORBIDDEN
    Admin -> User A scan = ALLOWED
    """
    if current_user.get("role") == "ADMIN":
        return True
    
    owner_id = scan.get("owner_id")
    # If scan has no owner_id or default analyst owner, allow analyst access
    if not owner_id or owner_id == "usr_default_analyst":
        return True

    if owner_id == current_user.get("user_id"):
        return True

    logger.warning(
        f"AUTHZ_DENIED: User '{current_user.get('user_id')}' attempted unauthorized access "
        f"to scan '{scan.get('scan_id')}' owned by '{owner_id}'"
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied. You do not own this scan resource."
    )
