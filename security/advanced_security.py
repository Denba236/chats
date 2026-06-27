"""
Advanced security features:
- IP blocking/unblocking system
- Device fingerprinting
- Advanced session management
- Brute force protection with progressive delays
- Security audit logging
"""
import time
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from collections import defaultdict

from fastapi import Request
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from db import AsyncSessionLocal, User, LoginAttempt, ActivityLog, BlockedIP


# ==================== IP BLOCKING SYSTEM ====================

class IPBlocker:
    """Advanced IP blocking system with temporary and permanent blocks"""

    def __init__(self, persist_file: str = "blocked_ips.json"):
        self.persist_file = persist_file
        self.blocked_ips: Dict[str, dict] = {}  # IP -> {reason, blocked_at, expires_at, permanent}
        self._load_from_file()

    def _load_from_file(self):
        """Load blocked IPs from file on startup"""
        if os.path.exists(self.persist_file):
            try:
                with open(self.persist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    now = time.time()
                    # Only load non-expired temporary blocks
                    for ip, info in data.items():
                        if info.get('permanent', False):
                            self.blocked_ips[ip] = info
                        elif info.get('expires_at', 0) > now:
                            self.blocked_ips[ip] = info
            except (json.JSONDecodeError, IOError):
                self.blocked_ips = {}

    def _save_to_file(self):
        """Persist blocked IPs to file"""
        try:
            with open(self.persist_file, 'w', encoding='utf-8') as f:
                json.dump(self.blocked_ips, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    def block_ip(self, ip: str, reason: str = "", duration_hours: int = 0, permanent: bool = False):
        """Block an IP address"""
        now = datetime.utcnow()
        expires_at = None
        
        if permanent:
            expires_at = None
        elif duration_hours > 0:
            expires_at = (now + timedelta(hours=duration_hours)).timestamp()
        else:
            # Default 24 hours for temporary blocks
            expires_at = (now + timedelta(hours=24)).timestamp()

        self.blocked_ips[ip] = {
            'reason': reason,
            'blocked_at': now.isoformat(),
            'expires_at': expires_at,
            'permanent': permanent,
            'block_count': self.blocked_ips.get(ip, {}).get('block_count', 0) + 1
        }

        self._save_to_file()

    def is_blocked(self, ip: str) -> Tuple[bool, str]:
        """Check if IP is blocked. Returns (is_blocked, reason)"""
        if ip not in self.blocked_ips:
            return False, ""

        block_info = self.blocked_ips[ip]
        
        # Check if temporary block has expired
        if not block_info.get('permanent', False) and block_info.get('expires_at'):
            if time.time() > block_info['expires_at']:
                # Block expired, remove it
                del self.blocked_ips[ip]
                self._save_to_file()
                return False, ""

        return True, block_info.get('reason', 'IP zablokowany')

    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._save_to_file()

    def get_blocked_ips(self) -> list:
        """Get all currently blocked IPs"""
        result = []
        now = time.time()
        
        for ip, info in self.blocked_ips.items():
            # Filter out expired temporary blocks
            if not info.get('permanent', False) and info.get('expires_at'):
                if now > info['expires_at']:
                    continue
            
            result.append({
                'ip': ip,
                'reason': info.get('reason', ''),
                'blocked_at': info.get('blocked_at', ''),
                'expires_at': datetime.fromtimestamp(info['expires_at']).isoformat() if info.get('expires_at') and not info.get('permanent') else 'Permanent',
                'permanent': info.get('permanent', False),
                'block_count': info.get('block_count', 1)
            })
        
        return result

    def cleanup_expired(self):
        """Remove expired temporary blocks"""
        now = time.time()
        expired = []
        
        for ip, info in self.blocked_ips.items():
            if not info.get('permanent', False) and info.get('expires_at'):
                if now > info['expires_at']:
                    expired.append(ip)
        
        for ip in expired:
            del self.blocked_ips[ip]
        
        if expired:
            self._save_to_file()

# Global IP blocker instance
ip_blocker = IPBlocker()


# ==================== DEVICE FINGERPRINTING ====================

class DeviceFingerprinter:
    """Generate and verify device fingerprints"""

    @staticmethod
    def generate_fingerprint(request: Request) -> str:
        """
        Generate device fingerprint from request headers and properties
        Creates a unique identifier based on:
        - User-Agent
        - Accept-Language
        - Accept-Encoding
        - IP address (partial, for privacy)
        - Platform
        """
        user_agent = request.headers.get('user-agent', '')
        accept_language = request.headers.get('accept-language', '')
        accept_encoding = request.headers.get('accept-encoding', '')
        platform = request.headers.get('sec-ch-ua-platform', '')
        
        # Use partial IP for privacy (first 2 octets for IPv4)
        client_ip = request.client.host if request.client else ''
        partial_ip = '.'.join(client_ip.split('.')[:2]) if client_ip else ''

        # Create fingerprint string
        fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}|{platform}|{partial_ip}"
        
        # Hash the fingerprint
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        return fingerprint

    @staticmethod
    def is_new_device(fingerprint: str, known_fingerprints: list) -> bool:
        """Check if fingerprint is from a new/unknown device"""
        return fingerprint not in known_fingerprints


# ==================== BRUTE FORCE PROTECTION ====================

class BruteForceProtector:
    """Progressive delay brute force protection"""

    def __init__(self, persist_file: str = "brute_force.json"):
        self.persist_file = persist_file
        self.attempts: Dict[str, dict] = {}  # key -> {count, last_attempt, delay_until}
        self._load_from_file()

    def _load_from_file(self):
        """Load brute force data from file"""
        if os.path.exists(self.persist_file):
            try:
                with open(self.persist_file, 'r', encoding='utf-8') as f:
                    self.attempts = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.attempts = {}

    def _save_to_file(self):
        """Persist brute force data"""
        try:
            with open(self.persist_file, 'w', encoding='utf-8') as f:
                json.dump(self.attempts, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    def get_delay(self, key: str) -> Tuple[bool, int, str]:
        """
        Check if key should be delayed due to brute force.
        Returns: (is_delayed, delay_seconds, message)
        """
        if key not in self.attempts:
            return False, 0, ""

        attempt_info = self.attempts[key]
        count = attempt_info.get('count', 0)
        delay_until = attempt_info.get('delay_until', 0)

        # Check if currently in delay period
        if time.time() < delay_until:
            delay_remaining = int(delay_until - time.time())
            return True, delay_remaining, f"Zbyt wiele prób. Poczekaj {delay_remaining} sekund."

        # Reset if delay period has passed
        if delay_until > 0 and time.time() >= delay_until:
            self.attempts[key]['delay_until'] = 0
            self.attempts[key]['count'] = 0
            self._save_to_file()

        return False, 0, ""

    def record_attempt(self, key: str, success: bool = False):
        """Record a login attempt"""
        now = time.time()

        if key not in self.attempts:
            self.attempts[key] = {
                'count': 0,
                'last_attempt': now,
                'delay_until': 0,
                'failed_attempts': []
            }

        if success:
            # Reset on successful login
            del self.attempts[key]
        else:
            self.attempts[key]['count'] += 1
            self.attempts[key]['last_attempt'] = now
            
            # Track failed attempts
            if 'failed_attempts' not in self.attempts[key]:
                self.attempts[key]['failed_attempts'] = []
            self.attempts[key]['failed_attempts'].append(now)

            # Keep only recent attempts (last hour)
            cutoff = now - 3600
            self.attempts[key]['failed_attempts'] = [
                ts for ts in self.attempts[key]['failed_attempts']
                if ts > cutoff
            ]

            failed_count = len(self.attempts[key]['failed_attempts'])

            # Progressive delays based on failed attempt count
            delay_seconds = 0
            if failed_count >= 20:
                # After 20 failures: 10 minute delay
                delay_seconds = 600
            elif failed_count >= 15:
                # After 15 failures: 5 minute delay
                delay_seconds = 300
            elif failed_count >= 10:
                # After 10 failures: 2 minute delay
                delay_seconds = 120
            elif failed_count >= 7:
                # After 7 failures: 1 minute delay
                delay_seconds = 60
            elif failed_count >= 5:
                # After 5 failures: 30 second delay
                delay_seconds = 30
            elif failed_count >= 3:
                # After 3 failures: 10 second delay
                delay_seconds = 10

            if delay_seconds > 0:
                self.attempts[key]['delay_until'] = now + delay_seconds

        self._save_to_file()

    def reset(self, key: str):
        """Reset brute force tracking for a key"""
        if key in self.attempts:
            del self.attempts[key]
            self._save_to_file()

# Global brute force protector
brute_force_protector = BruteForceProtector()


# ==================== DEVICE FINGERPRINTING ====================

class DeviceFingerprint:
    """Generate device fingerprints for security tracking"""
    
    @staticmethod
    def generate_fingerprint(request) -> str:
        """
        Generate device fingerprint from request headers
        Creates a unique identifier based on User-Agent, IP, etc.
        """
        import hashlib
        
        user_agent = request.headers.get('user-agent', '')
        accept_lang = request.headers.get('accept-language', '')
        accept_enc = request.headers.get('accept-encoding', '')
        client_ip = request.client.host if request.client else ''
        
        # Create fingerprint from multiple factors
        fingerprint_data = f"{user_agent}|{accept_lang}|{accept_enc}|{client_ip}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        return fingerprint



# ==================== SECURITY AUDIT LOGGING ====================

class SecurityAuditLogger:
    """Comprehensive security audit logging"""

    @staticmethod
    async def log_event(
        event_type: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[str] = None,
        severity: str = "info",
        user_agent: Optional[str] = None,
        session: AsyncSession = None
    ):
        """
        Log security event to database
        
        Event types:
        - LOGIN_SUCCESS
        - LOGIN_FAILURE
        - LOGIN_2FA_FAILURE
        - LOGOUT
        - PASSWORD_CHANGE
        - PASSWORD_RESET_REQUEST
        - PASSWORD_RESET_COMPLETE
        - ACCOUNT_CREATED
        - ACCOUNT_DELETED
        - PERMISSION_CHANGE
        - IP_BLOCKED
        - IP_UNBLOCKED
        - SESSION_CREATED
        - SESSION_REVOKED
        - SUSPICIOUS_ACTIVITY
        - BRUTE_FORCE_DETECTED
        - API_KEY_CREATED
        - API_KEY_REVOKED
        - CSRF_VIOLATION
        """
        
        activity_log = ActivityLog(
            user_id=user_id,
            action=f"{event_type}_{severity.upper()}",
            details=details or "",
            ip_address=ip_address,
            created_at=datetime.utcnow()
        )
        
        session.add(activity_log)
        await session.commit()

    @staticmethod
    async def get_user_security_log(
        session: AsyncSession,
        user_id: int,
        limit: int = 100,
        offset: int = 0
    ) -> list:
        """Get security log entries for a specific user"""
        result = await session.execute(
            select(ActivityLog)
            .where(ActivityLog.user_id == user_id)
            .order_by(ActivityLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()

    @staticmethod
    async def get_security_events(
        session: AsyncSession,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        ip_address: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """Get filtered security events"""
        query = select(ActivityLog)
        
        if event_type:
            query = query.where(ActivityLog.action.like(f"%{event_type}%"))
        
        if severity:
            query = query.where(ActivityLog.action.like(f"%{severity.upper()}%"))
        
        if ip_address:
            query = query.where(ActivityLog.ip_address == ip_address)
        
        if start_date:
            query = query.where(ActivityLog.created_at >= start_date)
        
        if end_date:
            query = query.where(ActivityLog.created_at <= end_date)
        
        query = query.order_by(ActivityLog.created_at.desc()).limit(limit)
        
        result = await session.execute(query)
        return result.scalars().all()

# Global audit logger instance
audit_logger = SecurityAuditLogger()


# ==================== HELPER FUNCTIONS ====================

async def check_ip_blocked(ip: str, request: Request) -> Tuple[bool, str]:
    """Check if IP is blocked and return result"""
    return ip_blocker.is_blocked(ip)


async def log_security_event(
    event_type: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None,
    severity: str = "info"
):
    """Convenience function to log security events"""
    async with AsyncSessionLocal() as session:
        await SecurityAuditLogger.log_event(
            session=session,
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            details=details,
            severity=severity
        )
