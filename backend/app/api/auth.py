import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, Depends
from backend.app.schemas.auth import UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse, RoleEnum
from backend.app.core.security import hash_password, verify_password, create_access_token, sanitize_log_input
from backend.app.core.logging import logger
from backend.app.repositories.user_repository import in_memory_user_repo

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(request: UserRegisterRequest):
    """
    Registers a new user (ANALYST or ADMIN). Hashes password with PBKDF2-HMAC-SHA256.
    """
    clean_username = sanitize_log_input(request.username)
    existing = await in_memory_user_repo.get_by_username(request.username)
    if existing:
        logger.warning(f"AUTH_FAILURE: Registration attempted with existing username '{clean_username}'")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered."
        )

    user_id = f"usr_{uuid.uuid4().hex[:12]}"
    user_data = {
        "user_id": user_id,
        "username": request.username,
        "email": request.email,
        "hashed_password": hash_password(request.password),
        "role": request.role.value,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await in_memory_user_repo.create_user(user_data)
    logger.info(f"AUTH_SUCCESS: Registered user '{clean_username}' with role '{request.role.value}' (ID: {user_id})")

    return UserResponse(
        user_id=user_id,
        username=request.username,
        email=request.email,
        role=request.role
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: UserLoginRequest):
    """
    Authenticates user and returns a signed Bearer JWT access token.
    """
    clean_username = sanitize_log_input(request.username)
    user = await in_memory_user_repo.get_by_username(request.username)
    if not user or not verify_password(request.password, user["hashed_password"]):
        logger.warning(f"AUTH_FAILURE: Invalid login credentials for username '{clean_username}'")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token_data = {
        "sub": user["user_id"],
        "username": user["username"],
        "role": user["role"]
    }
    access_token = create_access_token(token_data)
    logger.info(f"AUTH_SUCCESS: User '{clean_username}' authenticated successfully")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user_id=user["user_id"],
        username=user["username"],
        role=RoleEnum(user["role"])
    )
