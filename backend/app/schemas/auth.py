from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, EmailStr


class RoleEnum(str, Enum):
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, description="User's unique username")
    email: str = Field(..., max_length=128, description="User's email address")
    password: str = Field(..., min_length=8, max_length=128, description="User's password")
    role: RoleEnum = Field(default=RoleEnum.ANALYST, description="Role: ANALYST or ADMIN")


class UserLoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: RoleEnum


class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    role: RoleEnum
