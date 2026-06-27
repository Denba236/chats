"""
CSRF protection middleware and API key authentication:
- CSRF token generation and validation
- API key management and validation
- Request validation and filtering
"""
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sqlalchemy import select
from db import AsyncSessionLocal, APIToken


# ==================== CSRF PROTECTION ====================

class CSRFTokenManager:
    """Manage CSRF tokens for form submissions"""

    def __init__(self):
        self.tokens: Dict[str, dict] = {}  # token -> {user, created_at, used}

    def generate_token(self, username: str) -> str:
        """Generate a new CSRF token"""
        token = secrets.token_urlsafe(32)
        self.tokens[token] = {
            'username': username,
            'created_at': datetime.utcnow(),
            'used': False
        }
        return token

    def validate_token(self, token: str, username: str) -> bool:
        """Validate a CSRF token"""
        if token not in self.tokens:
            return False

        token_info = self.tokens[token]

        # Check if already used (one-time use)
        if token_info['used']:
            return False

        # Check if token matches user
        if token_info['username'] != username:
            return False

        # Check expiration (1 hour)
        if datetime.utcnow() - token_info['created_at'] > timedelta(hours=1):
            del self.tokens[token]
            return False

        # Mark as used
        token_info['used'] = True

        # Clean up old tokens
        self._cleanup_expired()

        return True

    def _cleanup_expired(self):
        """Remove expired tokens"""
        expired = []
        for token, info in self.tokens.items():
            if datetime.utcnow() - info['created_at'] > timedelta(hours=1):
                expired.append(token)

        for token in expired:
            del self.tokens[token]

# Global CSRF manager
csrf_manager = CSRFTokenManager()


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """CSRF protection middleware for web forms"""

    EXEMPT_METHODS = {'GET', 'HEAD', 'OPTIONS'}
    EXEMPT_PATHS = ['/api/', '/ws/', '/static/', '/uploads/']

    async def dispatch(self, request: Request, call_next):
        # Skip CSRF for exempt methods and paths
        if request.method in self.EXEMPT_METHODS:
            return await call_next(request)

        for path in self.EXEMPT_PATHS:
            if request.url.path.startswith(path):
                return await call_next(request)

        # Check CSRF token for POST/PUT/DELETE requests
        if request.method in ('POST', 'PUT', 'DELETE'):
            user = request.session.get('user_name')
            if user:
                csrf_token = None

                # Get token from form data or header
                try:
                    form_data = await request.form()
                    csrf_token = form_data.get('csrf_token')
                except:
                    csrf_token = request.headers.get('X-CSRF-Token')

                if not csrf_token:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token missing"}
                    )

                if not csrf_manager.validate_token(csrf_token, user):
                    # Log CSRF violation
                    from security.advanced_security import log_security_event
                    await log_security_event(
                        event_type="CSRF_VIOLATION",
                        username=user,
                        ip_address=request.client.host if request.client else None,
                        details="Invalid or expired CSRF token",
                        severity="warning"
                    )

                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Invalid CSRF token"}
                    )

        return await call_next(request)


# ==================== API KEY AUTHENTICATION ====================

class APIKeyManager:
    """Manage API keys for programmatic access"""

    @staticmethod
    async def create_api_key(
        user_id: int,
        username: str,
        name: str,
        permissions: list = None,
        expires_in_days: int = None
    ) -> Tuple[str, str]:
        """
        Create a new API key
        Returns: (api_key, key_id)
        """
        import uuid
        from db import APIToken

        # Generate secure API key
        raw_key = f"{username}_{uuid.uuid4().hex}_{secrets.token_urlsafe(32)}"
        hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Store in database
        api_token = APIToken(
            user_id=user_id,
            token=hashed_key,
            name=name,
            permissions=permissions or ['read'],
            expires_at=expires_at,
            is_active=True
        )

        async with AsyncSessionLocal() as session:
            session.add(api_token)
            await session.commit()
            await session.refresh(api_token)

            # Log creation
            from security.advanced_security import log_security_event
            await log_security_event(
                event_type="API_KEY_CREATED",
                user_id=user_id,
                username=username,
                details=f"API key created: {name}",
                severity="info"
            )

        return raw_key, str(api_token.id)

    @staticmethod
    async def validate_api_key(api_key: str) -> Optional[dict]:
        """
        Validate an API key
        Returns: {user_id, username, permissions} or None
        """
        from db import APIToken, User

        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(APIToken).where(
                    APIToken.token == hashed_key,
                    APIToken.is_active == True
                )
            )
            token = result.scalars().first()

            if not token:
                return None

            # Check expiration
            if token.expires_at and datetime.utcnow() > token.expires_at:
                token.is_active = False
                await session.commit()
                return None

            # Get user info
            user_result = await session.execute(
                select(User).where(User.id == token.user_id)
            )
            user = user_result.scalars().first()

            if not user:
                return None

            # Update last used
            token.last_used = datetime.utcnow()
            await session.commit()

            return {
                'user_id': token.user_id,
                'username': user.user_name,
                'permissions': token.permissions or [],
                'token_id': token.id
            }

    @staticmethod
    async def revoke_api_key(user_id: int, token_id: int) -> bool:
        """Revoke an API key"""
        from db import APIToken

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(APIToken).where(
                    APIToken.id == token_id,
                    APIToken.user_id == user_id
                )
            )
            token = result.scalars().first()

            if token:
                token.is_active = False
                await session.commit()

                # Log revocation
                from security.advanced_security import log_security_event
                await log_security_event(
                    event_type="API_KEY_REVOKED",
                    user_id=user_id,
                    details=f"API key revoked: {token.name}",
                    severity="info"
                )
                return True

            return False

    @staticmethod
    async def list_user_api_keys(user_id: int) -> list:
        """List all API keys for a user"""
        from db import APIToken

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(APIToken)
                .where(APIToken.user_id == user_id)
                .order_by(APIToken.created_at.desc())
            )
            tokens = result.scalars().all()

            return [
                {
                    'id': token.id,
                    'name': token.name,
                    'permissions': token.permissions or [],
                    'created_at': token.created_at.isoformat(),
                    'expires_at': token.expires_at.isoformat() if token.expires_at else None,
                    'last_used': token.last_used.isoformat() if token.last_used else None,
                    'is_active': token.is_active
                }
                for token in tokens
            ]


# ==================== API KEY AUTHENTICATION DEPENDENCY ====================

async def get_api_key_user(request: Request) -> Optional[dict]:
    """
    FastAPI dependency to authenticate requests via API key
    Usage: user = Depends(get_api_key_user)
    """
    api_key = request.headers.get('X-API-Key')

    if not api_key:
        # Check query parameter as fallback
        api_key = request.query_params.get('api_key')

    if not api_key:
        return None

    user_info = await APIKeyManager.validate_api_key(api_key)
    return user_info


async def require_api_key(request: Request) -> dict:
    """
    FastAPI dependency that requires valid API key
    Usage: user = Depends(require_api_key)
    """
    user_info = await get_api_key_user(request)

    if not user_info:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

    return user_info


async def require_api_permission(permission: str):
    """
    FastAPI dependency that requires specific permission
    Usage: user = Depends(require_api_permission('write'))
    """
    async def permission_checker(request: Request) -> dict:
        user_info = await require_api_key(request)

        if permission not in user_info.get('permissions', []):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission}"
            )

        return user_info

    return permission_checker


# ==================== HELPER FUNCTIONS ====================

def generate_csrf_token(username: str) -> str:
    """Generate CSRF token for forms"""
    return csrf_manager.generate_token(username)


def include_csrf_token(username: str) -> dict:
    """Get CSRF token and manager info"""
    token = csrf_manager.generate_token(username)
    return {
        'csrf_token': token,
        'csrf_field': f'<input type="hidden" name="csrf_token" value="{token}">'
    }
