# OrderFlow: Authentication module
# Handles token creation, verification, and the login endpoint.

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration (do not modify)

SECRET_KEY = "orderflow-secret-key-do-not-use-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(prefix="/auth", tags=["auth"])

# Simulated user store — passwords are bcrypt hash of "secret"
USERS_DB = {
    "alice@orderflow.com": {
        "email": "alice@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "admin",
    },
    "bob@orderflow.com": {
        "email": "bob@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "viewer",
    },
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Pydantic models (do not modify)

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    email: str
    role: str


# Helper utilities (do not modify)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_user(email: str) -> Optional[dict]:
    """Return the user dict from USERS_DB or None if not found."""
    return USERS_DB.get(email)


# Token creation

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a signed JWT for an authenticated user.

    Copies the caller's claims, adds an "exp" claim, and signs with SECRET_KEY.
    Falls back to ACCESS_TOKEN_EXPIRE_MINUTES when no window is given.
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Token verification

def decode_access_token(token: str) -> TokenData:
    """Verify an incoming token and extract the user identity from it.

    Raises 401 if the token is expired, tampered with, or missing the "sub" claim.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise credentials_exception

    email: Optional[str] = payload.get("sub")
    if email is None:
        raise credentials_exception

    return TokenData(email=email, role=payload.get("role"))


# Authentication dependency

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Reusable auth check. Any route can depend on this to protect itself.

    Reads the bearer token from the request, verifies it, and returns the user.
    Rejects the request if the token is invalid or the user no longer exists.
    """
    token_data = decode_access_token(token)

    user = get_user(token_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return User(email=user["email"], role=user["role"])


# Login endpoint

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Validate credentials and issue a signed token.

    OAuth2PasswordRequestForm sends the email in the "username" field.
    """
    user = get_user(form_data.username)

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user["email"], "role": user["role"]}
    )

    return {"access_token": access_token, "token_type": "bearer"}
