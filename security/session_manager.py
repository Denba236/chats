"""
Advanced session management with timeout detection and security:
- Session timeout monitoring
- Idle session detection
- Concurrent session limits
- Session hijacking prevention
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from fastapi import Request, HTTPException
from sqlalchemy import select, func
from db import AsyncSessionLocal, User, UserSession


# ==================== SESSION TIMEOUT MANAGEMENT ====================

class SessionTimeoutManager:
    """Manage session timeouts and idle detection"""

    # Default timeout settings (in minutes)
    DEFAULT_TIMEOUT = 30  # 30 minutes
    ABSOLUTE_TIMEOUT = 480  # 8 hours maximum session
    IDLE_TIMEOUT = 15  # 15 minutes of inactivity

    @staticmethod
    async def create_session(
        user_id: int,
        session_token: str,
        device_info: str = None,
        ip_address: str = None,
        timeout_minutes: int = None
    ) -> UserSession:
        """Create a new user session"""
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=timeout_minutes or SessionTimeoutManager.DEFAULT_TIMEOUT)
        absolute_expires_at = now + timedelta(minutes=SessionTimeoutManager.ABSOLUTE_TIMEOUT)

        session = UserSession(
            user_id=user_id,
            session_token=session_token,
            device_info=device_info,
            ip_address=ip_address,
            created_at=now,
            last_activity=now,
            expires_at=min(expires_at, absolute_expires_at),
            is_active=True
        )

        async with AsyncSessionLocal() as db_session:
            db_session.add(session)
            await db_session.commit()
            await db_session.refresh(session)

        return session

    @staticmethod
    async def update_session_activity(session_token: str):
        """Update session last activity timestamp"""
        async with AsyncSessionLocal() as db_session:
            result = await db_session.execute(
                select(UserSession).where(
                    UserSession.session_token == session_token,
                    UserSession.is_active == True
                )
            )
            session = result.scalars().first()

            if session:
                # Check if session has expired
                now = datetime.utcnow()
                
                if now > session.expires_at:
                    # Session expired
                    session.is_active = False
                    await db_session.commit()
                    return False, "Session expired"
                
                # Update activity
                session.last_activity = now
                
                # Extend expiration if not at absolute max
                new_expires = now + timedelta(minutes=SessionTimeoutManager.DEFAULT_TIMEOUT)
                if new_expires < session.expires_at + timedelta(hours=1):
                    session.expires_at = new_expires
                
                await db_session.commit()
                return True, "Session updated"
            
            return False, "Session not found"

    @staticmethod
    async def check_session_timeout(session_token: str) -> Dict:
        """
        Check if session is timed out
        Returns: {is_valid, reason, expires_at, idle_time}
        """
        async with AsyncSessionLocal() as db_session:
            result = await db_session.execute(
                select(UserSession).where(
                    UserSession.session_token == session_token,
                    UserSession.is_active == True
                )
            )
            session = result.scalars().first()

            if not session:
                return {
                    'is_valid': False,
                    'reason': 'Session not found',
                    'expires_at': None,
                    'idle_time': 0
                }

            now = datetime.utcnow()
            idle_time = (now - session.last_activity).total_seconds() / 60  # minutes

            # Check absolute timeout
            if now > session.expires_at:
                return {
                    'is_valid': False,
                    'reason': 'Session expired (maximum duration exceeded)',
                    'expires_at': session.expires_at.isoformat(),
                    'idle_time': round(idle_time, 2)
                }

            # Check idle timeout
            if idle_time > SessionTimeoutManager.IDLE_TIMEOUT:
                return {
                    'is_valid': False,
                    'reason': f'Session idle for {idle_time:.1f} minutes (timeout: {SessionTimeoutManager.IDLE_TIMEOUT} min)',
                    'expires_at': session.expires_at.isoformat(),
                    'idle_time': round(idle_time, 2)
                }

            return {
                'is_valid': True,
                'reason': 'Session valid',
                'expires_at': session.expires_at.isoformat(),
                'idle_time': round(idle_time, 2)
            }

    @staticmethod
    async def get_user_sessions(user_id: int) -> List[UserSession]:
        """Get all active sessions for a user"""
        async with AsyncSessionLocal() as db_session:
            result = await db_session.execute(
                select(UserSession)
                .where(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True
                )
                .order_by(UserSession.created_at.desc())
            )
            return result.scalars().all()

    @staticmethod
    async def limit_concurrent_sessions(user_id: int, max_sessions: int = 5):
        """
        Limit concurrent sessions per user
        Automatically revoke oldest sessions if limit exceeded
        """
        sessions = await SessionTimeoutManager.get_user_sessions(user_id)

        if len(sessions) > max_sessions:
            # Sort by creation date (oldest first)
            sessions.sort(key=lambda s: s.created_at)
            
            # Revoke oldest sessions
            sessions_to_revoke = sessions[:len(sessions) - max_sessions]
            
            async with AsyncSessionLocal() as db_session:
                for session in sessions_to_revoke:
                    session.is_active = False
                
                await db_session.commit()

            return len(sessions_to_revoke)
        
        return 0

    @staticmethod
    async def revoke_session(session_token: str, user_id: int = None) -> bool:
        """Revoke a specific session"""
        async with AsyncSessionLocal() as db_session:
            query = select(UserSession).where(
                UserSession.session_token == session_token
            )
            
            if user_id:
                query = query.where(UserSession.user_id == user_id)
            
            result = await db_session.execute(query)
            session = result.scalars().first()

            if session:
                session.is_active = False
                await db_session.commit()
                return True
            
            return False

    @staticmethod
    async def revoke_all_sessions(user_id: int, except_token: str = None) -> int:
        """Revoke all sessions for a user"""
        async with AsyncSessionLocal() as db_session:
            query = select(UserSession).where(
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )
            
            if except_token:
                query = query.where(UserSession.session_token != except_token)
            
            result = await db_session.execute(query)
            sessions = result.scalars().all()

            for session in sessions:
                session.is_active = False
            
            await db_session.commit()
            return len(sessions)

    @staticmethod
    async def cleanup_expired_sessions():
        """Clean up expired sessions from database"""
        async with AsyncSessionLocal() as db_session:
            now = datetime.utcnow()
            
            result = await db_session.execute(
                select(UserSession).where(
                    UserSession.is_active == True,
                    UserSession.expires_at < now
                )
            )
            expired_sessions = result.scalars().all()

            for session in expired_sessions:
                session.is_active = False
            
            await db_session.commit()
            return len(expired_sessions)


# ==================== SESSION HIJACKING PREVENTION ====================

class SessionSecurity:
    """Prevent session hijacking and ensure session integrity"""

    @staticmethod
    def validate_session_context(request: Request, session_data: dict) -> bool:
        """
        Validate that session request context matches original session
        Checks IP consistency and user-agent
        """
        current_ip = request.client.host if request.client else None
        current_ua = request.headers.get('user-agent', '')

        # Check IP consistency (warning only, not blocking - users may switch networks)
        if 'ip_address' in session_data and session_data['ip_address']:
            if session_data['ip_address'] != current_ip:
                # Log suspicious IP change
                print(f"[SECURITY] IP change detected: {session_data['ip_address']} -> {current_ip}")
                # Could trigger additional verification here

        # Check user-agent consistency
        if 'user_agent' in session_data and session_data['user_agent']:
            if session_data['user_agent'] != current_ua:
                # User-agent change could indicate session hijacking
                print(f"[SECURITY] User-Agent change detected")
                return False

        return True

    @staticmethod
    def generate_session_token() -> str:
        """Generate a cryptographically secure session token"""
        import secrets
        return secrets.token_urlsafe(64)

    @staticmethod
    async def check_concurrent_access_anomaly(user_id: int, current_ip: str) -> Dict:
        """
        Detect anomalous concurrent access patterns
        (e.g., same user from multiple geolocations simultaneously)
        """
        sessions = await SessionTimeoutManager.get_user_sessions(user_id)
        
        active_ips = set()
        for session in sessions:
            if session.ip_address:
                active_ips.add(session.ip_address)
        
        # If user has sessions from multiple different IPs, log it
        if len(active_ips) > 2 and current_ip not in active_ips:
            return {
                'is_anomalous': True,
                'reason': f'User accessing from {len(active_ips) + 1} different IPs',
                'active_ips': list(active_ips),
                'current_ip': current_ip
            }
        
        return {
            'is_anomalous': False,
            'reason': '',
            'active_ips': list(active_ips),
            'current_ip': current_ip
        }


# ==================== HELPER FUNCTIONS ====================

async def require_active_session(request: Request) -> dict:
    """
    FastAPI dependency to require active session
    Usage: session = Depends(require_active_session)
    """
    session_token = request.session.get('session_token')
    
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    timeout_check = await SessionTimeoutManager.check_session_timeout(session_token)
    
    if not timeout_check['is_valid']:
        # Clear session
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail=f"Session expired: {timeout_check['reason']}"
        )
    
    # Update activity
    await SessionTimeoutManager.update_session_activity(session_token)
    
    return {
        'session_token': session_token,
        'expires_at': timeout_check['expires_at'],
        'idle_time': timeout_check['idle_time']
    }


async def get_session_info(user_id: int) -> List[Dict]:
    """Get formatted session information for a user"""
    sessions = await SessionTimeoutManager.get_user_sessions(user_id)
    
    session_list = []
    for session in sessions:
        idle_minutes = (datetime.utcnow() - session.last_activity).total_seconds() / 60
        
        session_list.append({
            'id': session.id,
            'device_info': session.device_info or 'Unknown device',
            'ip_address': session.ip_address,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'idle_minutes': round(idle_minutes, 1),
            'is_current': False  # Would need to compare with current session
        })
    
    return session_list
