"""
Security enhancements module:
- Email verification system
- Rate limiting with file-based persistence
- Captcha verification with timing-safe comparison
- Suspicious activity logging & notifications
"""
import time
import secrets
import json
import os
import hmac
from datetime import datetime, timedelta
from typing import Dict
from collections import defaultdict

from fastapi import Request
from sqlalchemy import select, func

from db import (
    AsyncSessionLocal, User, EmailVerificationToken, LoginAttempt, LoginHistory
)
from security.security_utils import hash_token, generate_verification_token


# ==================== RATE LIMITING WITH PERSISTENCE ====================

class RateLimiter:
    """Rate limiter with file-based persistence"""

    def __init__(self, persist_file: str = "rate_limits.json"):
        self.persist_file = persist_file
        self.requests: Dict[str, list] = defaultdict(list)
        self._load_from_file()

    def _load_from_file(self):
        """Load rate limits from file on startup"""
        if os.path.exists(self.persist_file):
            try:
                with open(self.persist_file, 'r') as f:
                    data = json.load(f)
                    now = time.time()
                    # Only load non-expired entries
                    for key, timestamps in data.items():
                        self.requests[key] = [
                            ts for ts in timestamps if ts > now - 3600
                        ]
            except (json.JSONDecodeError, IOError):
                self.requests = defaultdict(list)

    def _save_to_file(self):
        """Persist rate limits to file"""
        try:
            with open(self.persist_file, 'w') as f:
                json.dump(dict(self.requests), f)
        except IOError:
            pass  # Ignore save errors

    def is_allowed(self, key: str, max_requests: int = 5, window_seconds: int = 300) -> tuple[bool, int]:
        """
        Check if request is allowed.
        Returns: (allowed, remaining_attempts)
        """
        now = time.time()
        window_start = now - window_seconds

        # Clean old requests outside window
        self.requests[key] = [
            ts for ts in self.requests[key]
            if ts > window_start
        ]

        current_count = len(self.requests[key])

        if current_count >= max_requests:
            remaining = 0
            return False, remaining

        # Record this request
        self.requests[key].append(now)
        remaining = max_requests - current_count - 1

        # Persist to file
        self._save_to_file()

        return True, remaining

    def get_remaining(self, key: str, max_requests: int = 5, window_seconds: int = 300) -> int:
        """Get remaining attempts without recording a request"""
        now = time.time()
        window_start = now - window_seconds

        self.requests[key] = [
            ts for ts in self.requests[key]
            if ts > window_start
        ]

        current_count = len(self.requests[key])
        return max(0, max_requests - current_count)

    def reset(self, key: str):
        """Reset rate limit for a key (e.g., after successful login)"""
        if key in self.requests:
            del self.requests[key]
            self._save_to_file()

# Global rate limiter instance
rate_limiter = RateLimiter()


# ==================== CAPTCHA SYSTEM ====================

class CaptchaManager:
    """Enhanced captcha system with timing-safe comparison"""

    def __init__(self):
        self.captchas: Dict[str, dict] = {}  # token -> {question, answer, created_at}

    def generate_captcha(self) -> dict:
        """Generate a new captcha challenge with increased complexity"""
        token = secrets.token_urlsafe(32)

        # Mix of operation types for increased security
        operations = [
            ('add', lambda a, b: a + b),
            ('subtract', lambda a, b: a - b),
            ('multiply', lambda a, b: a * b),
        ]

        op_name, op_func = secrets.choice(operations)

        # Increased number ranges for harder brute-forcing
        if op_name == 'multiply':
            a = secrets.randbelow(12) + 2  # 2-13
            b = secrets.randbelow(12) + 2  # 2-13
        elif op_name == 'subtract':
            a = secrets.randbelow(50) + 10  # 10-59
            b = secrets.randbelow(a) + 1   # 1 to a-1 (ensure positive result)
        else:  # add
            a = secrets.randbelow(50) + 10  # 10-59
            b = secrets.randbelow(50) + 10  # 10-59

        # Ensure subtraction doesn't result in negative
        if op_name == 'subtract' and a < b:
            a, b = b, a

        answer = op_func(a, b)

        # Format question
        op_symbols = {'add': '+', 'subtract': '-', 'multiply': '×'}
        question = f"Ile to {a} {op_symbols[op_name]} {b}?"

        self.captchas[token] = {
            'question': question,
            'answer': str(answer),
            'created_at': datetime.utcnow()
        }

        return {
            'token': token,
            'question': question
        }

    def verify_captcha(self, token: str, answer: str) -> bool:
        """Verify captcha answer with timing-safe comparison"""
        if token not in self.captchas:
            # Always perform a dummy comparison to prevent timing attacks
            dummy_answer = secrets.token_urlsafe(8)
            hmac.compare_digest(dummy_answer.encode(), dummy_answer.encode())
            return False

        captcha = self.captchas[token]

        # Check if expired (5 minutes)
        if datetime.utcnow() - captcha['created_at'] > timedelta(minutes=5):
            del self.captchas[token]
            return False

        # Verify with timing-safe comparison and delete (one-time use)
        is_correct = hmac.compare_digest(
            captcha['answer'].strip().encode(),
            answer.strip().encode()
        )
        del self.captchas[token]

        return is_correct

# Global captcha manager
captcha_manager = CaptchaManager()


# ==================== SUSPICIOUS ACTIVITY DETECTOR ====================

class SuspiciousActivityDetector:
    """Detect and log suspicious login patterns"""
    
    @staticmethod
    async def check_login_attempt(session, username: str, ip_address: str) -> dict:
        """
        Check if login attempt is suspicious.
        Returns: {'is_suspicious': bool, 'reason': str, 'risk_level': str}
        """
        now = datetime.utcnow()
        
        # Check 1: Too many failed attempts from this IP
        recent_ip_failures = await session.execute(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.success == False,
                LoginAttempt.created_at > now - timedelta(hours=1)
            )
        )
        ip_failure_count = recent_ip_failures.scalar() or 0
        
        if ip_failure_count > 10:
            return {
                'is_suspicious': True,
                'reason': f'Zbyt wiele nieudanych prób z tego IP ({ip_failure_count})',
                'risk_level': 'high'
            }
        
        # Check 2: Too many failed attempts for this username
        recent_user_failures = await session.execute(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.username == username,
                LoginAttempt.success == False,
                LoginAttempt.created_at > now - timedelta(hours=1)
            )
        )
        user_failure_count = recent_user_failures.scalar() or 0
        
        if user_failure_count > 8:
            return {
                'is_suspicious': True,
                'reason': f'Zbyt wiele nieudanych prób na konto "{username}" ({user_failure_count})',
                'risk_level': 'high'
            }
        
        # Check 3: Login from new location/device
        if ip_address:
            result = await session.execute(
                select(LoginHistory).where(
                    LoginHistory.ip_address == ip_address
                ).limit(1)
            )
            known_ip = result.scalars().first()
            
            if not known_ip:
                # New IP address for this user
                result = await session.execute(select(User).where(User.user_name == username))
                user = result.scalars().first()
                
                if user:
                    result = await session.execute(
                        select(LoginHistory).where(
                            LoginHistory.user_id == user.id,
                            LoginHistory.success == True
                        ).order_by(LoginHistory.created_at.desc()).limit(1)
                    )
                    last_login = result.scalars().first()
                    
                    if last_login and last_login.ip_address != ip_address:
                        return {
                            'is_suspicious': False,  # Not blocking, just logging
                            'reason': f'Nowe IP: {ip_address} (poprzednie: {last_login.ip_address})',
                            'risk_level': 'low'
                        }
        
        # Check 4: Rapid successive attempts (brute force indicator)
        result = await session.execute(
            select(LoginAttempt).where(
                LoginAttempt.username == username,
                LoginAttempt.created_at > now - timedelta(minutes=1)
            ).order_by(LoginAttempt.created_at.desc()).limit(5)
        )
        recent_attempts = result.scalars().all()
        
        if len(recent_attempts) >= 5:
            time_diff = (recent_attempts[0].created_at - recent_attempts[-1].created_at).total_seconds()
            if time_diff < 30:  # 5 attempts in 30 seconds
                return {
                    'is_suspicious': True,
                    'reason': 'Bardzo szybkie próby logowania (możliwy brute force)',
                    'risk_level': 'critical'
                }
        
        return {
            'is_suspicious': False,
            'reason': '',
            'risk_level': 'none'
        }
    
    @staticmethod
    async def log_suspicious_activity(session, user_id: int, username: str, 
                                     ip_address: str, reason: str, risk_level: str):
        """Log suspicious activity and potentially notify user"""
        from db import ActivityLog
        
        # Log to activity
        log = ActivityLog(
            user_id=user_id,
            action=f"SUSPICIOUS_LOGIN_{risk_level.upper()}",
            details=f"Podejrzana aktywność: {reason}",
            ip_address=ip_address
        )
        session.add(log)
        
        # For high/critical risk, could trigger email notification
        # This would integrate with email service
        if risk_level in ['high', 'critical']:
            # In production: send email to user
            print(f"[ALERT] Suspicious activity for {username}: {reason} (IP: {ip_address})")
        
        await session.commit()


# ==================== EMAIL VERIFICATION ====================

async def send_verification_email(email: str, token: str, username: str) -> bool:
    """
    Send verification email (mock implementation).
    In production, integrate with SMTP service (SendGrid, Mailgun, etc.)
    """
    # Mock: In production, send actual email
    verification_url = f"http://localhost:8000/api/verify-email?token={token}&username={username}"
    
    print(f"""
    {'='*60}
    WERYFIKACJA EMAILA (SYMULACJA)
    {'='*60}
    Do: {email}
    Temat: Zweryfikuj swój adres email
    
    Cześć {username}!
    
    Kliknij poniższy link, aby zweryfikować swój adres email:
    {verification_url}
    
    Link wygasa za 48 godzin.
    {'='*60}
    """)
    
    return True


async def send_email_verification(request: Request, email: str, username: str) -> dict:
    """Generate token and send verification email"""
    async with AsyncSessionLocal() as session:
        # Get user
        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()
        
        if not user:
            return {"ok": False, "error": "Użytkownik nie istnieje"}
        
        if user.email and user.email == email:
            # Check if already verified
            # Note: Would need email_verified field in User model
            pass
        
        # Check for existing unexpired token
        result = await session.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.verified == False,
                EmailVerificationToken.expires_at > datetime.utcnow()
            )
        )
        existing = result.scalars().first()
        
        if existing:
            return {
                "ok": False, 
                "error": "Token weryfikacyjny już istnieje. Poczekaj na email lub wygeneruj nowy za godzinę."
            }
        
        # Generate new token
        token = generate_verification_token()
        hashed_token = hash_token(token)
        expires_at = datetime.utcnow() + timedelta(hours=48)
        
        verification_token = EmailVerificationToken(
            user_id=user.id,
            token=hashed_token,
            expires_at=expires_at
        )
        session.add(verification_token)
        await session.commit()
        
        # Send email
        success = await send_verification_email(email, token, username)
        
        if success:
            return {
                "ok": True,
                "message": "Email weryfikacyjny został wysłany"
            }
        else:
            return {
                "ok": False,
                "error": "Nie udało się wysłać emaila. Spróbuj ponownie."
            }


async def verify_email_token(token: str, username: str) -> dict:
    """Verify email using token"""
    async with AsyncSessionLocal() as session:
        hashed_token = hash_token(token)
        
        result = await session.execute(
            select(EmailVerificationToken).join(User).where(
                EmailVerificationToken.token == hashed_token,
                User.user_name == username,
                EmailVerificationToken.verified == False,
                EmailVerificationToken.expires_at > datetime.utcnow()
            )
        )
        verification_token = result.scalars().first()
        
        if not verification_token:
            return {"ok": False, "error": "Nieprawidłowy lub wygasły token"}
        
        # Mark as verified
        verification_token.verified = True
        
        # Update user email if not set
        result_user = await session.execute(select(User).where(User.user_name == username))
        user = result_user.scalars().first()
        
        if user and not user.is_2fa_enabled:
            # Could set email_verified flag here if added to User model
            pass
        
        await session.commit()
        
        return {"ok": True, "message": "Email został zweryfikowany!"}


# ==================== SECURITY HEADERS MIDDLEWARE ====================

async def add_security_headers(request: Request, call_next):
    """Add security headers to responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    return response
