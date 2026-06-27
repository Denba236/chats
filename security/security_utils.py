import bcrypt
import pyotp
import secrets
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional, Tuple
from jose import jwt, JWTError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Secure secret keys from environment variables
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "your-super-secret-key-change-this-in-production":
    import warnings
    warnings.warn(
        "WARNING: SECRET_KEY is not properly configured! "
        "Generate a secure key: python -c \"import secrets; print(secrets.token_urlsafe(64))\"",
        RuntimeWarning
    )
    # Fallback only for development
    SECRET_KEY = secrets.token_urlsafe(64)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
RESET_TOKEN_EXPIRE_HOURS = int(os.getenv("JWT_RESET_TOKEN_EXPIRE_HOURS", "24"))
EMAIL_VERIFY_EXPIRE_HOURS = int(os.getenv("JWT_EMAIL_VERIFY_EXPIRE_HOURS", "48"))


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_enc = hashed_password.encode('utf-8')
    try:
        return bcrypt.checkpw(password_byte_enc, hashed_password_enc)
    except Exception:
        return False


def generate_totp_secret() -> str:
    """Generate a new TOTP secret for 2FA"""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    """Generate TOTP URI for QR code"""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Chat App"
    )


def verify_totp(secret: str, code: str) -> bool:
    """Verify TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_reset_token() -> str:
    """Generate a secure reset token"""
    return secrets.token_urlsafe(32)


def generate_verification_token() -> str:
    """Generate email verification token"""
    return secrets.token_urlsafe(32)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Decode JWT access token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def hash_token(token: str) -> str:
    """Hash token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()


def verify_password_strength(password: str) -> Tuple[bool, str]:
    """Check password strength"""
    if len(password) < 8:
        return False, "Hasło musi mieć co najmniej 8 znaków"
    if not any(c.isupper() for c in password):
        return False, "Hasło musi zawierać wielką literę"
    if not any(c.islower() for c in password):
        return False, "Hasło musi zawierać małą literę"
    if not any(c.isdigit() for c in password):
        return False, "Hasło musi zawierać cyfrę"
    return True, "OK"


def censor_profanity(text: str, profanity_words: list) -> str:
    """Censor profanity in text"""
    result = text
    for word in profanity_words:
        if word.lower() in text.lower():
            result = result.replace(word, "*" * len(word))
            result = result.replace(word.lower(), "*" * len(word))
            result = result.replace(word.upper(), "*" * len(word))
    return result
