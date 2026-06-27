import json
import os
import uuid
import re
import html
import time

import qrcode
import io
import base64
from datetime import datetime, timedelta
from classes import ConnectionManager
import uvicorn
from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware

from starlette.responses import RedirectResponse

from sqlalchemy import select, or_, and_, func, delete, update
from sqlalchemy.exc import IntegrityError

from urllib.parse import unquote
from contextlib import asynccontextmanager

from db import (
    engine, Base, AsyncSessionLocal, User, Message, Report,
    UserSession, PasswordResetToken, EmailVerificationToken, LoginAttempt,
    ActivityLog, UserWarning, Friendship, FriendRequest, MessageReaction,
    Group, GroupMember, GroupMessage, PushNotificationToken, ProfanityFilter,
    TwoFABackupCode, LoginHistory, BlockedUser, PinnedMessage, StarredMessage,
    VoiceMessage, VideoMessage, Poll, PollOption, PollVote, ChatTheme, UserTheme, MutedChat, ChatWallpaper, AutoDeleteSetting,
    UserLanguage, UserStatistic, BotIntegration, FocusMode, KeyboardShortcut,
    QRCodeData, FileStorage,
    # New security models
    BlockedIP, APIToken, SecurityEvent, DeviceFingerprint,
    # FAZA 1-10: Wszystkie nowe modele
)
from sqlalchemy.orm import selectinload
from security.security_utils import (
    hash_password, verify_password, generate_totp_secret, get_totp_uri,
    verify_totp, generate_reset_token, hash_token,
    verify_password_strength, censor_profanity, RESET_TOKEN_EXPIRE_HOURS
)

from security.security_enhancements import (
    rate_limiter, captcha_manager, SuspiciousActivityDetector,
    send_email_verification, verify_email_token, add_security_headers
)

from security.advanced_security import (
    ip_blocker, brute_force_protector, audit_logger,
    DeviceFingerprint as DeviceFingerprintGenerator,
    log_security_event, check_ip_blocked
)

from security.encryption import (
    get_message_encryptor, get_file_encryptor,
    DataAnonymizer, initialize_encryption
)

from security.csrf_and_api import (
    csrf_manager, CSRFProtectionMiddleware,
    APIKeyManager, generate_csrf_token
)

from security.session_manager import (
    SessionTimeoutManager, SessionSecurity,
    require_active_session, get_session_info
)

from authlib.integrations.starlette_client import OAuth, OAuthError
from dotenv import load_dotenv
load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        },
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Initialize encryption on startup
    initialize_encryption()
    
    # Start flood tracker cleanup task
    import asyncio
    async def cleanup_flood_tracker():
        """Periodically clean up expired flood tracker entries"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every 60 seconds
                current_time = time.time()
                expired_users = [
                    user for user, data in flood_tracker.items()
                    if data['banned_until'] > 0 and data['banned_until'] < current_time - 60
                    or data['first_message'] < current_time - 300  # Clean users inactive for 5 minutes
                ]
                for user in expired_users:
                    del flood_tracker[user]
            except Exception as e:
                print(f"Flood tracker cleanup error: {e}")
    
    cleanup_task = asyncio.create_task(cleanup_flood_tracker())
    
    yield
    cleanup_task.cancel()

app = FastAPI(lifespan=lifespan)

# Add security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return await add_security_headers(request, call_next)

app.add_middleware(SecurityHeadersMiddleware)

# Global dict for blocked ports - MUST be before middleware
blocked_ports_dict: dict = {}

# Track active sensor ports (for monitoring)
active_sensor_ports: dict = {}  # port -> {sensor_id, ip, last_seen, request_count}

# Add IP blocking middleware
class PortBlockMiddleware(BaseHTTPMiddleware):
    """Block specific source ports instead of entire IPs"""
    async def dispatch(self, request, call_next):
        # Skip check for static files
        if request.url.path.startswith("/static") or \
           request.url.path.startswith("/uploads") or \
           request.url.path == "/favicon.ico":
            return await call_next(request)

        client_port = request.client.port if request.client else None
        client_ip = request.client.host if request.client else "unknown"

        # Track ALL active ports (not just sensors)
        if client_port:
            if client_port not in active_sensor_ports:
                active_sensor_ports[client_port] = {
                    'sensor_id': 'unknown',
                    'ip': client_ip,
                    'first_seen': datetime.utcnow().isoformat(),
                    'request_count': 0,
                    'last_path': request.url.path
                }
            active_sensor_ports[client_port]['last_seen'] = datetime.utcnow().isoformat()
            active_sensor_ports[client_port]['request_count'] += 1
            active_sensor_ports[client_port]['ip'] = client_ip
            active_sensor_ports[client_port]['last_path'] = request.url.path

        if client_port and client_port in blocked_ports_dict:
            block_info = blocked_ports_dict[client_port]
            expires_at = block_info.get('expires_at')

            # Check if block expired
            if expires_at and time.time() > expires_at:
                del blocked_ports_dict[client_port]
            else:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Port blocked",
                        "reason": block_info.get('reason', 'Port zablokowany'),
                        "port": client_port
                    }
                )

        return await call_next(request)

app.add_middleware(PortBlockMiddleware)

# Add CSRF protection middleware
app.add_middleware(CSRFProtectionMiddleware)

# Load SECRET_KEY from environment (same as in security_utils.py)
from dotenv import load_dotenv
load_dotenv()
SESSION_SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(64).hex())

app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Security: Restrict CORS to specific origins
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"]
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# Helper function to sanitize user input
def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input to prevent XSS and injection attacks"""
    if not text:
        return ""
    # Truncate to prevent excessive length
    text = text[:max_length]
    # HTML escape to prevent XSS
    text = html.escape(text, quote=True)
    return text.strip()



manager = ConnectionManager()


# ==================== IoT SENSOR API ====================

# In-memory storage for sensor data (use database in production)
sensor_data_store: dict = {}
sensor_blocks: dict = {}  # sensor_id -> {blocked_until, reason, violations}
registered_devices: dict = {}  # device_id -> {headers, registered_at, ip}


@app.get("/api/sensor/register-device")
async def register_sensor_device(
    device_id: str,
    device_key: str,
    request: Request
):
    """Register a new device with authentication"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get('user-agent', '')
    
    registered_devices[device_id] = {
        'device_key': device_key,
        'registered_at': datetime.utcnow().isoformat(),
        'ip': client_ip,
        'user_agent': user_agent,
        'is_active': True
    }
    
    return {
        "ok": True,
        "message": "Device registered",
        "device_id": device_id,
        "headers_required": {
            "X-Device-ID": device_id,
            "X-Device-Key": device_key
        }
    }


@app.get("/api/sensor/telemetry")
async def receive_sensor_telemetry(
    id: str = None,
    temp: float = None,
    timestamp: int = None,
    request: Request = None
):
    """
    Dedicated endpoint for IoT sensor telemetry data.
    Accepts GET requests with query parameters: id, temp, timestamp

    Device Authentication via Headers:
    - X-Device-ID: Device identifier
    - X-Device-Key: Device authentication key
    - User-Agent: Device software info

    Rate limited: 60 requests per minute per sensor ID
    Auto-blocking: Sensor gets blocked for increasing time after violations
    """
    if not id:
        return {"error": "Missing sensor ID"}

    # Get client info early
    client_ip = request.client.host if request.client else "unknown"
    client_port = getattr(request.client, 'port', None)

    # ==================== BLOCK CHECK (MUST BE FIRST) ====================
    # Check if sensor is blocked BEFORE any other processing
    if id in sensor_blocks:
        block_info = sensor_blocks[id]
        blocked_until = block_info.get('blocked_until')
        
        # Check if sensor is currently blocked
        if blocked_until and datetime.utcnow() < blocked_until:
            remaining = (blocked_until - datetime.utcnow()).total_seconds()
            
            # Also block the port if it's a repeated violation
            if block_info.get('violations', 0) >= 3 and client_port:
                if client_port not in blocked_ports_dict:
                    block_minutes = block_info.get('block_duration_minutes', 30)
                    blocked_ports_dict[client_port] = {
                        'reason': f"Sensor blocked - {id}",
                        'blocked_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                        'expires_at': time.time() + (block_minutes * 60)
                    }
            
            return {
                "error": "Sensor blocked",
                "reason": block_info.get('reason', 'Rate limit exceeded'),
                "blocked_until": blocked_until.isoformat(),
                "remaining_seconds": int(remaining),
                "violations": block_info.get('violations', 0)
            }
        elif blocked_until and datetime.utcnow() >= blocked_until:
            # Block expired - clean up
            del sensor_blocks[id]

    # ==================== DEVICE HEADER VALIDATION ====================
    device_id = request.headers.get('X-Device-ID')
    device_key = request.headers.get('X-Device-Key')
    user_agent = request.headers.get('User-Agent', '')

    # Log device info
    device_info = {
        'user_agent': user_agent,
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'host': request.headers.get('Host', ''),
        'connection': request.headers.get('Connection', ''),
        'client_ip': client_ip
    }

    # Check if device headers match (possible spoofing)
    if device_id and device_id != id:
        # Device ID mismatch - possible spoofing
        if id not in sensor_blocks:
            sensor_blocks[id] = {'violations': 0}
        sensor_blocks[id]['violations'] = sensor_blocks[id].get('violations', 0) + 1

        if sensor_blocks[id]['violations'] >= 3:
            block_minutes = 60  # Block for 1 hour
            sensor_blocks[id]['blocked_until'] = datetime.utcnow() + timedelta(minutes=block_minutes)
            sensor_blocks[id]['block_duration_minutes'] = block_minutes
            sensor_blocks[id]['reason'] = f"Device ID mismatch ({sensor_blocks[id]['violations']} times)"

            return {
                "error": "Device authentication failed",
                "reason": "Device ID mismatch - possible spoofing",
                "blocked_until": sensor_blocks[id]['blocked_until'].isoformat(),
                "violations": sensor_blocks[id]['violations']
            }

    # Validate device key if registered
    if device_id in registered_devices:
        registered = registered_devices[device_id]

        if device_key != registered['device_key']:
            return {
                "error": "Invalid device key",
                "message": "Device authentication failed"
            }

        # Check if device is active
        if not registered.get('is_active', False):
            return {
                "error": "Device deactivated",
                "message": "Contact administrator to reactivate"
            }

        # Update last seen
        registered['last_seen'] = datetime.utcnow().isoformat()
        registered['last_ip'] = client_ip

    # ==================== RATE LIMITING ====================
    rate_key = f"sensor:{id}:{client_ip}"

    # Strict rate limit: 3 requests per minute per sensor+IP
    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=3, window_seconds=60)
    if not allowed:
        # Progressive blocking
        if id not in sensor_blocks:
            sensor_blocks[id] = {'violations': 0}
        
        sensor_blocks[id]['violations'] = sensor_blocks[id].get('violations', 0) + 1
        violations = sensor_blocks[id]['violations']

        # Progressive blocking (faster escalation):
        # 1st: 5min, 2nd: 15min, 3rd: 1h, 4th: 24h, 5th+: permanent
        if violations >= 5:
            block_minutes = 60 * 24  # 24 hours
            sensor_blocks[id]['permanent'] = True
        elif violations >= 4:
            block_minutes = 60 * 24  # 24 hours
        elif violations >= 3:
            block_minutes = 60  # 1 hour
        elif violations >= 2:
            block_minutes = 15  # 15 minutes
        else:
            block_minutes = 5  # 5 minutes (first violation)
        
        sensor_blocks[id]['block_duration_minutes'] = block_minutes
        sensor_blocks[id]['blocked_until'] = datetime.utcnow() + timedelta(minutes=block_minutes)
        sensor_blocks[id]['reason'] = f"Rate limit exceeded ({violations} violations)"

        # Also block the source port
        if client_port := getattr(request.client, 'port', None):
            blocked_ports_dict[client_port] = {
                'reason': f"Sensor flood - {id} ({violations} violations)",
                'blocked_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'expires_at': time.time() + (block_minutes * 60)
            }
        
        return {
            "error": "Rate limit exceeded",
            "blocked_until": sensor_blocks[id]['blocked_until'].isoformat(),
            "block_minutes": block_minutes,
            "violations": violations,
            "retry_after": 60,
            "device_info": device_info
        }

    # ==================== STORE TELEMETRY ====================
    if id not in sensor_data_store:
        sensor_data_store[id] = []

    telemetry = {
        "sensor_id": id,
        "temperature": temp,
        "timestamp": timestamp or int(datetime.utcnow().timestamp()),
        "received_at": datetime.utcnow().isoformat(),
        "ip": client_ip,
        "device_info": device_info
    }

    sensor_data_store[id].append(telemetry)

    # Keep only last 100 readings per sensor
    if len(sensor_data_store[id]) > 100:
        sensor_data_store[id] = sensor_data_store[id][-100:]

    # Track active port (client_port already retrieved above)
    if client_port:
        if client_port not in active_sensor_ports:
            active_sensor_ports[client_port] = {
                'sensor_id': id,
                'ip': client_ip,
                'first_seen': datetime.utcnow().isoformat(),
                'request_count': 0
            }
        active_sensor_ports[client_port]['last_seen'] = datetime.utcnow().isoformat()
        active_sensor_ports[client_port]['request_count'] += 1
        active_sensor_ports[client_port]['sensor_id'] = id

    return {
        "ok": True, 
        "remaining": remaining,
        "device_authenticated": bool(device_id and device_key),
        "device_info": device_info
    }


@app.get("/api/sensor/{sensor_id}/data")
async def get_sensor_data(sensor_id: str, request: Request):
    """Get recent telemetry data for a specific sensor"""
    if sensor_id not in sensor_data_store:
        return {"error": "Sensor not found", "data": []}

    return {
        "sensor_id": sensor_id,
        "readings": sensor_data_store[sensor_id],
        "total": len(sensor_data_store[sensor_id])
    }


@app.get("/api/sensor/list")
async def list_sensors(request: Request):
    """List all registered sensors with latest reading and block status"""
    sensors = []
    for sensor_id, readings in sensor_data_store.items():
        latest = readings[-1] if readings else None
        is_blocked = sensor_id in sensor_blocks and datetime.utcnow() < sensor_blocks[sensor_id].get('blocked_until', datetime.utcnow())
        
        sensors.append({
            "id": sensor_id,
            "last_reading": latest,
            "total_readings": len(readings),
            "is_blocked": is_blocked,
            "violations": sensor_blocks.get(sensor_id, {}).get('violations', 0)
        })
    return {"sensors": sensors}


@app.post("/api/sensor/{sensor_id}/unblock")
async def unblock_sensor(sensor_id: str, request: Request):
    """Unblock a sensor (admin action)"""
    if sensor_id in sensor_blocks:
        del sensor_blocks[sensor_id]
        return {"ok": True, "message": f"Sensor {sensor_id} unblocked"}
    return {"ok": False, "message": "Sensor not blocked"}


@app.delete("/api/sensor/{sensor_id}")
async def delete_sensor_data(sensor_id: str, request: Request):
    """Delete all data for a specific sensor"""
    if sensor_id in sensor_data_store:
        del sensor_data_store[sensor_id]
    if sensor_id in sensor_blocks:
        del sensor_blocks[sensor_id]
    return {"ok": True, "message": f"Sensor {sensor_id} data deleted"}


# ==================== PORT BLOCKING API ====================

@app.post("/api/admin/block-port")
async def block_port_endpoint(
    request: Request,
    port: int = Form(...),
    reason: str = Form("Flood detected"),
    duration_seconds: int = Form(300)
):
    """Block a specific source port for specified duration"""
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}

    expires_at = time.time() + duration_seconds
    blocked_ports_dict[port] = {
        'reason': reason,
        'blocked_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'expires_at': expires_at
    }

    from datetime import datetime
    expires_str = datetime.fromtimestamp(expires_at).strftime('%H:%M:%S')

    await log_security_event(
        event_type="PORT_BLOCKED",
        user_id=user.id,
        username=user_name,
        details=f"Port {port} blocked for {duration_seconds}s. Reason: {reason}",
        severity="warning"
    )

    return {
        "ok": True,
        "message": f"Port {port} blocked until {expires_str}",
        "port": port,
        "duration_seconds": duration_seconds
    }


@app.post("/api/admin/unblock-port")
async def unblock_port_endpoint(
    request: Request,
    port: int = Form(...)
):
    """Unblock a specific source port"""
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}

    if port in blocked_ports_dict:
        del blocked_ports_dict[port]
        return {"ok": True, "message": f"Port {port} unblocked"}

    return {"ok": False, "error": "Port not blocked"}


@app.get("/api/admin/blocked-ports")
async def get_blocked_ports_list(request: Request):
    """Get list of currently blocked ports"""
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}

    from datetime import datetime
    blocked = []
    for port, info in list(blocked_ports_dict.items()):
        expires_at = info.get('expires_at')
        if expires_at and time.time() > expires_at:
            del blocked_ports_dict[port]
            continue
        blocked.append({
            'port': port,
            'reason': info.get('reason', ''),
            'expires_at': datetime.fromtimestamp(expires_at).strftime('%H:%M:%S') if expires_at else 'Permanent'
        })

    return {"ok": True, "blocked_ports": blocked, "total": len(blocked)}


@app.get("/api/admin/active-ports")
async def get_active_ports_list(request: Request):
    """Get list of all active sensor ports"""
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}

    # Clean old entries (older than 5 minutes)
    now = datetime.utcnow()
    active = []
    ports_to_remove = []
    
    for port, info in active_sensor_ports.items():
        last_seen = datetime.fromisoformat(info['last_seen']) if isinstance(info['last_seen'], str) else info['last_seen']
        if (now - last_seen).total_seconds() > 300:
            ports_to_remove.append(port)
        else:
            active.append({
                'port': port,
                'sensor_id': info.get('sensor_id', 'unknown'),
                'ip': info.get('ip', 'unknown'),
                'request_count': info.get('request_count', 0),
                'first_seen': info.get('first_seen', ''),
                'last_seen': info.get('last_seen', ''),
                'last_path': info.get('last_path', ''),
                'is_blocked': port in blocked_ports_dict
            })
    
    for port in ports_to_remove:
        del active_sensor_ports[port]

    # Sort by request count descending
    active.sort(key=lambda x: x['request_count'], reverse=True)

    return {
        "ok": True, 
        "active_ports": active, 
        "total": len(active),
        "blocked_count": len([p for p in active if p['is_blocked']])
    }


# ==================== IP BLOCKING API ====================

@app.post("/api/admin/block-ip")
async def block_ip_address(
    request: Request,
    ip: str = Form(...),
    reason: str = Form("Manual block"),
    duration_seconds: int = Form(300)
):
    """
    Block an IP address for specified duration (default 300 seconds)
    Admin only endpoint
    """
    # Check if user is admin
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}
    
    # Block the IP
    duration_hours = duration_seconds / 3600
    ip_blocker.block_ip(
        ip=ip,
        reason=reason,
        duration_hours=duration_hours,
        permanent=False
    )
    
    # Log the action
    await log_security_event(
        event_type="IP_BLOCKED",
        user_id=user.id,
        username=user_name,
        ip_address=ip,
        details=f"IP blocked by admin: {ip} for {duration_seconds} seconds. Reason: {reason}",
        severity="warning"
    )
    
    return {
        "ok": True,
        "message": f"IP {ip} blocked for {duration_seconds} seconds",
        "ip": ip,
        "duration_seconds": duration_seconds,
        "reason": reason
    }


@app.post("/api/admin/unblock-ip")
async def unblock_ip_address(
    request: Request,
    ip: str = Form(...)
):
    """
    Unblock an IP address
    Admin only endpoint
    """
    # Check if user is admin
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}
    
    # Unblock the IP
    ip_blocker.unblock_ip(ip)
    
    # Log the action
    await log_security_event(
        event_type="IP_UNBLOCKED",
        user_id=user.id,
        username=user_name,
        ip_address=ip,
        details=f"IP unblocked by admin: {ip}",
        severity="info"
    )
    
    return {
        "ok": True,
        "message": f"IP {ip} unblocked successfully",
        "ip": ip
    }


@app.get("/api/admin/blocked-ips")
async def get_blocked_ips_list(request: Request):
    """
    Get list of currently blocked IPs
    Admin only endpoint
    """
    # Check if user is admin
    user_name = request.session.get("user_name")
    if not user_name:
        return {"ok": False, "error": "Not authenticated"}
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not user.is_admin:
            return {"ok": False, "error": "Admin privileges required"}
    
    blocked = ip_blocker.get_blocked_ips()
    
    return {
        "ok": True,
        "blocked_ips": blocked,
        "total": len(blocked)
    }


@app.get("/notifications")
async def get_notifications(request: Request):
    user = request.session.get("user_name")
    if not user:
        return {}

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Message.sender_name, func.count(Message.id))
            .where(
                Message.receiver_name == user,
                Message.is_read == False
            )
            .group_by(Message.sender_name)
        )
        rows = result.all()

    return {sender: count for sender, count in rows}

@app.get("/api/notifications/all")
async def get_all_notifications(request: Request):
    """Get all notifications including messages, mentions, system"""
    user = request.session.get("user_name")
    if not user:
        return {"notifications": [], "total": 0}

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user))
        current_user = result.scalars().first()
        
        notifications = []
        
        # Unread messages
        result = await session.execute(
            select(Message)
            .where(Message.receiver_name == user, Message.is_read == False)
            .order_by(Message.created_at.desc())
            .limit(50)
        )
        messages = result.scalars().all()
        
        for msg in messages:
            notifications.append({
                "id": f"msg_{msg.id}",
                "type": "message",
                "sender": msg.sender_name,
                "text": msg.text[:100] if msg.text else "[file]",
                "time": msg.created_at.isoformat(),
                "read": False,
                "icon": "💬"
            })
        
        # Mentions (search for @username in messages)
        result = await session.execute(
            select(Message)
            .where(
                Message.receiver_name == user,
                Message.text.like(f"%@{user}%")
            )
            .order_by(Message.created_at.desc())
            .limit(20)
        )
        mentions = result.scalars().all()
        
        for msg in mentions:
            if not any(n["id"] == f"msg_{msg.id}" for n in notifications):
                notifications.append({
                    "id": f"mention_{msg.id}",
                    "type": "mention",
                    "sender": msg.sender_name,
                    "text": msg.text[:100],
                    "time": msg.created_at.isoformat(),
                    "read": False,
                    "icon": "🔔"
                })
        
        # System notifications (warnings, bans, etc.)
        result = await session.execute(
            select(UserWarning)
            .where(UserWarning.user_id == current_user.id, UserWarning.is_active == True)
            .order_by(UserWarning.created_at.desc())
        )
        warnings = result.scalars().all()
        
        for warn in warnings:
            notifications.append({
                "id": f"warn_{warn.id}",
                "type": "warning",
                "sender": "Admin",
                "text": f"Ostrzeżenie: {warn.reason}",
                "time": warn.created_at.isoformat(),
                "read": False,
                "icon": "⚠️"
            })
        
        # Sort by time
        notifications.sort(key=lambda x: x["time"], reverse=True)
        
        return {
            "notifications": notifications,
            "total": len([n for n in notifications if not n["read"]]),
            "unread_count": len([n for n in notifications if not n["read"]])
        }

@app.post("/api/notifications/mark-read")
async def mark_notifications_read(request: Request, notification_ids: str = Form(None)):
    """Mark notifications as read"""
    user = request.session.get("user_name")
    if not user:
        return {"ok": False}

    import json
    ids = json.loads(notification_ids) if notification_ids else []
    
    async with AsyncSessionLocal() as session:
        # Mark messages as read
        for nid in ids:
            if nid.startswith("msg_"):
                msg_id = int(nid.replace("msg_", ""))
                result = await session.execute(
                    select(Message).where(Message.id == msg_id, Message.receiver_name == user)
                )
                msg = result.scalars().first()
                if msg:
                    msg.is_read = True
        
        await session.commit()
    
    return {"ok": True}

@app.post("/api/notifications/mark-all-read")
async def mark_all_notifications_read(request: Request):
    """Mark all notifications as read"""
    user = request.session.get("user_name")
    if not user:
        return {"ok": False}

    async with AsyncSessionLocal() as session:
        await session.execute(
            update(Message)
            .where(Message.receiver_name == user, Message.is_read == False)
            .values(is_read=True)
        )
        await session.commit()
    
    return {"ok": True}

@app.post("/read/{sender}")
async def read_messages(sender: str, request: Request):
    user = request.session.get("user_name")
    if not user:
        return {"ok": False}

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Message).where(
                Message.sender_name == sender,
                Message.receiver_name == user,
                Message.is_read == False
            )
        )
        messages = result.scalars().all()

        for msg in messages:
            msg.is_read = True

        await session.commit()

    return {"ok": True}


@app.get('/')
async def landing(request: Request):
    user_name = request.session.get("user_name")
    return templates.TemplateResponse(
        'landing.html',
        {
            'request': request,
            'current_user': user_name
        }
    )

@app.get('/chat')
async def index(request: Request):
    user_name = request.session.get("user_name")

    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        current_user_obj = result.scalars().first()
        
        result = await session.execute(select(User).where(User.user_name != user_name))
        users = result.scalars().all()
        
    users_with_status = []
    for u in users:
        u_dict = {
            "user_name": u.user_name,
            "avatar_url": u.avatar_url,
            "status": "online" if u.user_name in manager.active_connections else "offline"
        }
        users_with_status.append(u_dict)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "session": request.session,
            "users": users_with_status,
            "current_user": user_name,
            "current_user_is_admin": User.is_admin if User else False,  # Teraz 'user' istnieje
        }
    )


@app.get('/messages/{other_user}')
async def get_messages(other_user: str, request: Request):
    current_user = request.session.get("user_name")
    if not current_user:
        return []

    async with AsyncSessionLocal() as session:
        query = select(Message).options(
            selectinload(Message.reply_to)
        ).where(
            or_(
                and_(Message.sender_name == current_user, Message.receiver_name == other_user),
                and_(Message.sender_name == other_user, Message.receiver_name == current_user)
            )
        ).order_by(Message.created_at.asc())

        result = await session.execute(query)
        messages = result.scalars().all()

    return [
        {
            "id": m.id,
            "sender": m.sender_name,
            "text": m.text,
            "file": m.file_name,
            "file_url": m.file_path,
            "reply_to": {"text": m.reply_to.text} if m.reply_to and m.reply_to.text else None
        }
        for m in messages
    ]


@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...), to: str = Form(...)):
    user = request.session.get("user_name")
    file_path = f"uploads/{file.filename}"
    with open(file_path, "wb") as f:
        f.write(await file.read())

    async with AsyncSessionLocal() as session:
        new_msg = Message(sender=user, receiver=to, file_name=file.filename, file_url=f"/{file_path}")
        session.add(new_msg)
        await session.commit()

    payload = {"type": "message", "sender": user, "file": file.filename, "file_url": f"/{file_path}", "to": to}
    await manager.send_personal_message(payload, to)
    await manager.send_personal_message(payload, user)
    return {"status": "ok"}


# Global flood tracking dictionary: username -> {'count': int, 'first_message': float, 'banned_until': float}
flood_tracker: dict = {}

@app.websocket('/ws/{username}')
async def websocket_endpoint(websocket: WebSocket, username: str):
    clean_name = unquote(username)

    # Sanitize username
    if len(clean_name) > 50 or not re.match(r'^[a-zA-Z0-9_]+$', clean_name):
        await websocket.close(code=4001, reason="Invalid username")
        return

    await manager.connect(clean_name, websocket)

    try:
        while True:
            data = await websocket.receive_text()
            msg_data = json.loads(data)

            receiver = msg_data.get('to')
            text = msg_data.get('text')
            reply_to_id = msg_data.get('reply_to_id')

            # Validate message
            if not receiver or not text:
                continue

            # Sanitize text to prevent XSS
            sanitized_text = sanitize_input(text, max_length=5000)

            # Flood detection: Ban for 30 seconds if sending too many messages
            current_time = time.time()
            if clean_name not in flood_tracker:
                flood_tracker[clean_name] = {'count': 0, 'first_message': current_time, 'banned_until': 0}
            
            # Check if user is currently banned for flooding
            if flood_tracker[clean_name]['banned_until'] > current_time:
                remaining = flood_tracker[clean_name]['banned_until'] - current_time
                await websocket.send_json({
                    "error": f"Zbanowany za flood na {int(remaining)} sek. Poczekaj przed wysłaniem kolejnej wiadomości."
                })
                continue
            else:
                # Reset counter if ban expired
                if flood_tracker[clean_name]['banned_until'] > 0 and flood_tracker[clean_name]['banned_until'] <= current_time:
                    flood_tracker[clean_name] = {'count': 0, 'first_message': current_time, 'banned_until': 0}

            # Count messages in 30-second window
            if flood_tracker[clean_name]['count'] == 0:
                flood_tracker[clean_name]['first_message'] = current_time
            
            flood_tracker[clean_name]['count'] += 1

            # Check if user exceeded flood limit (40 messages in 30 seconds)
            time_window = current_time - flood_tracker[clean_name]['first_message']
            if time_window <= 30 and flood_tracker[clean_name]['count'] > 40:
                # Ban user for 30 seconds
                flood_tracker[clean_name]['banned_until'] = current_time + 30
                await websocket.send_json({
                    "error": "Zbanowany za flood na 30 sek. Zbyt wiele wiadomości w krótkim czasie!"
                })
                continue
            elif time_window > 30:
                # Reset counter after 30 seconds window
                flood_tracker[clean_name] = {'count': 1, 'first_message': current_time, 'banned_until': 0}

            # Rate limiting per user (existing)
            ws_rate_key = f"ws:{clean_name}"
            allowed, _ = rate_limiter.is_allowed(ws_rate_key, max_requests=30, window_seconds=60)
            if not allowed:
                await websocket.send_json({"error": "Zbyt wiele wiadomości. Zwolnij!"})
                continue

            if receiver and text:
                async with AsyncSessionLocal() as session:
                    new_msg = Message(
                        sender_name=clean_name,
                        receiver_name=receiver,
                        text=sanitized_text,
                        reply_to_id=reply_to_id if reply_to_id else None
                    )

                    session.add(new_msg)
                    await session.commit()
                    await session.refresh(new_msg)

                    # Get reply_to text if exists
                    reply_to_text = None
                    if reply_to_id:
                        reply_msg = await session.get(Message, reply_to_id)
                        if reply_msg and reply_msg.text:
                            reply_to_text = reply_msg.text

                payload = {
                    "type": "message",
                    "sender": clean_name,
                    "to": receiver,
                    "text": sanitized_text,
                    "id": new_msg.id,
                    "reply_to": {"text": reply_to_text} if reply_to_text else None
                }

                # Dispatch event to bots
                await bot_manager.dispatch_event("message.sent", {
                    "sender": clean_name,
                    "receiver": receiver,
                    "text": sanitized_text,
                    "id": new_msg.id
                })

                await manager.send_personal_message(payload, receiver)
                await manager.send_personal_message(payload, clean_name)

    except WebSocketDisconnect:
        # Clean up flood tracker data on disconnect
        if clean_name in flood_tracker:
            del flood_tracker[clean_name]
        await manager.disconnect(clean_name)


@app.get('/login')
async def login_page(request: Request):
    return templates.TemplateResponse('auth.html', {'request': request, 'title': 'Logowanie'})

@app.post('/login')
async def login_user(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login-legacy:{client_ip}"

    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=5, window_seconds=300)
    if not allowed:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'error': 'Zbyt wiele nieudanych prób. Spróbuj za 5 minut.'
        })

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()

    if user and verify_password(password, user.password):
        request.session["user_name"] = username
        return RedirectResponse(url='/chat', status_code=303)

    return templates.TemplateResponse('auth.html', {
        'request': request,
        'title': 'Logowanie',
        'error': 'Błędne dane logowania'
    })


@app.get('/register')
async def register_page(request: Request):
    return templates.TemplateResponse('auth.html', {'request': request, 'title': 'Rejestracja'})

@app.post('/register')
async def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(None),
    captcha_token: str = Form(None),
    captcha_answer: str = Form(None)
):
    # Username validation
    if not username or len(username.strip()) < 3:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Rejestracja',
            'error': 'Nazwa użytkownika musi mieć co najmniej 3 znaki'
        })

    if len(username) > 50:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Rejestracja',
            'error': 'Nazwa użytkownika nie może mieć więcej niż 50 znaków'
        })

    # Sanitize username - allow only alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Rejestracja',
            'error': 'Nazwa użytkownika może zawierać tylko litery, cyfry i podkreślenia'
        })

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"register:{client_ip}"

    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=3, window_seconds=3600)
    if not allowed:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Rejestracja',
            'error': 'Zbyt wiele prób rejestracji. Spróbuj za godzinę.'
        })

    # Verify captcha
    if captcha_token and captcha_answer:
        if not captcha_manager.verify_captcha(captcha_token, captcha_answer):
            return templates.TemplateResponse('auth.html', {
                'request': request,
                'title': 'Rejestracja',
                'error': 'Nieprawidłowa odpowiedź na captcha'
            })

    # Password strength check
    is_strong, msg = verify_password_strength(password)
    if not is_strong:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Rejestracja',
            'error': msg
        })

    async with AsyncSessionLocal() as session:
        try:
            hashed = hash_password(password)
            user = User(user_name=username.strip(), password=hashed, email=email)
            session.add(user)
            await session.commit()

            # If email provided, send verification
            if email:
                await send_email_verification(request, email, username)

            return RedirectResponse(url='/login', status_code=303)
        except IntegrityError:
            await session.rollback()
            return templates.TemplateResponse('auth.html', {
                'request': request,
                'title': 'Rejestracja',
                'error': 'Użytkownik istnieje'
            })


@app.get('/logout')
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/')


@app.get('/auth/google')
async def google_auth(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'error': 'Google OAuth nie jest skonfigurowany. Dodaj GOOGLE_CLIENT_ID i GOOGLE_CLIENT_SECRET do zmiennych środowiskowych.'
        })
    
    redirect_uri = "http://localhost:8080/auth/google/callback"
    
    google_client = oauth.google
    return await google_client.authorize_redirect(request, redirect_uri)


@app.get('/auth/google/callback', name='google_callback')
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'error': f'Błąd autoryzacji Google: {error.error}'
        })
    
    user_info = token.get('userinfo')
    if not user_info:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'error': 'Nie udało się pobrać danych użytkownika z Google'
        })
    
    email = user_info.get('email')
    google_sub = user_info.get('sub')
    
    if not email:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'error': 'Google nie zwróciło adresu email'
        })
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        
        if not user:
            username = email.split('@')[0]
            base_username = username
            counter = 1
            while True:
                result = await session.execute(select(User).where(User.user_name == username))
                if not result.scalars().first():
                    break
                username = f"{base_username}{counter}"
                counter += 1
            
            hashed = hash_password(google_sub)
            user = User(
                user_name=username,
                password=hashed,
                email=email,
                google_id=google_sub
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
        
        if user.is_banned and user.banned_until and datetime.utcnow() < user.banned_until:
            return templates.TemplateResponse('auth.html', {
                'request': request,
                'title': 'Logowanie',
                'error': f'Konto zablokowane do {user.banned_until}'
            })
        
        client_ip = request.client.host if request.client else "unknown"
        
        attempt = LoginAttempt(username=user.user_name, ip_address=client_ip, success=True)
        session.add(attempt)
        
        login_hist = LoginHistory(
            user_id=user.id,
            ip_address=client_ip,
            device_info=request.headers.get("user-agent", "Unknown")[:255],
            success=True
        )
        session.add(login_hist)
        
        session_token = hash_token(generate_reset_token())
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            device_info=request.headers.get("user-agent", "Unknown")[:255],
            ip_address=client_ip,
            expires_at=expires_at
        )
        session.add(user_session)
        
        user.last_seen = datetime.utcnow()
        await session.commit()
    
    request.session["user_name"] = user.user_name
    return RedirectResponse(url='/chat', status_code=303)


@app.get('/settings')
async def settings_page(request: Request):
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

    return templates.TemplateResponse(
        'settings_enhanced.html',
        {
            'request': request,
            'current_user': user_name,
            'user': user
        }
    )

@app.post('/settings')
async def update_settings(
    request: Request,
    status: str = Form(None),
    new_password: str = Form(None),
    avatar: UploadFile = File(None)
):
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    message = "Ustawienia zaktualizowane"
    success = True

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        if user:
            if status is not None:
                user.status = status

            if new_password and len(new_password.strip()) > 0:
                if len(new_password) < 6:
                    message = "Hasło musi mieć co najmniej 6 znaków"
                    success = False
                else:
                    user.password = hash_password(new_password)

            if success and avatar and avatar.filename:
                file_ext = avatar.filename.split('.')[-1]
                filename = f"{user.id}_{uuid.uuid4()}.{file_ext}"
                file_path = f"{UPLOAD_DIR}/{filename}"
                with open(file_path, "wb") as buffer:
                    buffer.write(await avatar.read())
                user.avatar_url = f"/uploads/{filename}"

            if success:
                await session.commit()
        else:
            message = "Nie znaleziono użytkownika"
            success = False
            
    return templates.TemplateResponse(
        'settings.html',
        {
            'request': request,
            'current_user': user_name,
            'user': user,
            'message': message,
            'success': success
        }
    )


@app.post('/report')
async def create_report(
    request: Request,
    reported_name: str = Form(...),
    comment: str = Form(...)
):
    reporter_name = request.session.get("user_name")
    if not reporter_name:
        raise HTTPException(status_code=401, detail="Not logged in")

    async with AsyncSessionLocal() as session:
        new_report = Report(
            reporter_name=reporter_name,
            reported_name=reported_name,
            comment=comment
        )
        session.add(new_report)
        await session.commit()

    return {"ok": True}

@app.get('/admin')
async def admin_panel(request: Request):
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        if not user or not user.is_admin:
            return "Dostęp zabroniony"

        # Pobierz skargi
        reports_res = await session.execute(select(Report).order_by(Report.created_at.desc()))
        reports = reports_res.scalars().all()

        # Pobierz wszystkich użytkowników
        users_res = await session.execute(select(User))
        all_users = users_res.scalars().all()

    return templates.TemplateResponse(
        'admin.html',
        {
            'request': request,
            'current_user': user_name,
            'reports': reports,
            'users': all_users
        }
    )

@app.get('/bots')
async def bots_page(request: Request):
    """Bot management page"""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        if not user or not user.is_admin:
            return RedirectResponse(url='/admin')

    return templates.TemplateResponse(
        'bots.html',
        {
            'request': request,
            'current_user': user_name
        }
    )


@app.delete("/message/{message_id}")
async def delete_message(message_id: int, request: Request):
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Message).where(Message.id == message_id)
        )
        msg = result.scalars().first()

        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")

        if msg.sender_name != user_name:
            raise HTTPException(status_code=403, detail="Not your message")

        await session.delete(msg)
        await session.commit()

    return {"ok": True}

@app.delete("/report/{report_id}")
async def delete_report(report_id: int, request: Request):
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)

    async with AsyncSessionLocal() as session:
        # Check if user is admin
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        if not user or not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")

        result = await session.execute(
            select(Report).where(Report.id == report_id)
        )
        report = result.scalars().first()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        await session.delete(report)
        await session.commit()

    return {"ok": True}

@app.delete("/admin/user/{user_id}")
async def delete_user(user_id: int, request: Request):
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)

    async with AsyncSessionLocal() as session:
        # Sprawdzenie czy admin
        result = await session.execute(select(User).where(User.user_name == user_name))
        current_admin = result.scalars().first()
        if not current_admin or not current_admin.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")

        # Znajdź użytkownika do usunięcia
        result = await session.execute(select(User).where(User.id == user_id))
        target_user = result.scalars().first()

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if target_user.user_name == user_name:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")

        await session.delete(target_user)
        await session.commit()
    return {"ok": True}


# ==================== NEW FEATURES ====================

# --- Helper Functions ---

async def log_activity(session, user_id: int, action: str, details: str = None, ip_address: str = None):
    """Log user activity"""
    log = ActivityLog(user_id=user_id, action=action, details=details, ip_address=ip_address)
    session.add(log)
    await session.commit()

async def get_profanity_words(session):
    """Get list of active profanity words"""
    result = await session.execute(select(ProfanityFilter).where(ProfanityFilter.is_active == True))
    return [r.word for r in result.scalars().all()]

async def check_user_banned(user: User) -> bool:
    """Check if user is banned"""
    if user.is_banned and user.banned_until:
        if datetime.utcnow() < user.banned_until:
            return True
        else:
            user.is_banned = False
            user.banned_until = None
    return False


# --- Enhanced Login with 2FA and Session Management ---

@app.post('/api/login/check')
async def check_login_status(request: Request, username: str = Form(...)):
    """Check if 2FA is required for user"""
    # Check rate limit
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login_check:{client_ip}"
    
    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=10, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Zbyt wiele prób. Spróbuj ponownie za minutę.")
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()

    if not user:
        return {"requires_2fa": False, "user_exists": False}

    return {"requires_2fa": user.is_2fa_enabled, "user_exists": True}

@app.get('/api/captcha/generate')
async def generate_captcha_endpoint(request: Request):
    """Generate a new captcha challenge"""
    # Check rate limit
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"captcha_gen:{client_ip}"
    
    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=20, window_seconds=300)
    if not allowed:
        raise HTTPException(status_code=429, detail="Zbyt wiele prób.")
    
    captcha_data = captcha_manager.generate_captcha()
    return captcha_data

@app.post('/api/login/verify-2fa')
async def verify_login_2fa(request: Request, username: str = Form(...), totp_code: str = Form(...)):
    """Verify 2FA code during login"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()
        
        if not user or not user.totp_secret:
            raise HTTPException(status_code=400, detail="2FA not configured")
        
        if not verify_totp(user.totp_secret, totp_code):
            raise HTTPException(status_code=400, detail="Invalid 2FA code")
        
        request.session["user_name"] = username
        await log_activity(session, user.id, "LOGIN_2FA", f"User logged in with 2FA", request.client.host if request.client else None)
        
        return {"ok": True, "redirect": "/chat"}

@app.post('/api/login')
async def api_login(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...),
    captcha_token: str = Form(None),
    captcha_answer: str = Form(None)
):
    """API login with session management, rate limiting, captcha and suspicious activity detection"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check rate limit (5 attempts per 5 minutes)
    rate_key = f"login:{client_ip}:{username}"
    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=5, window_seconds=300)
    
    if not allowed:
        # Log suspicious activity
        async with AsyncSessionLocal() as session:
            attempt = LoginAttempt(username=username, ip_address=client_ip, success=False)
            session.add(attempt)
            await session.commit()
        return {"ok": False, "error": "Zbyt wiele nieudanych prób. Spróbuj za 5 minut.", "locked": True}
    
    # Verify captcha if present (required after 2 failed attempts)
    if captcha_token and captcha_answer:
        if not captcha_manager.verify_captcha(captcha_token, captcha_answer):
            return {"ok": False, "error": "Nieprawidłowa odpowiedź na captcha", "remaining": remaining}
    
    async with AsyncSessionLocal() as session:
        # Check for suspicious activity
        suspicious = await SuspiciousActivityDetector.check_login_attempt(session, username, client_ip)
        
        # If critical risk, block immediately
        if suspicious['risk_level'] == 'critical' and suspicious['is_suspicious']:
            await SuspiciousActivityDetector.log_suspicious_activity(
                session, None, username, client_ip, 
                suspicious['reason'], suspicious['risk_level']
            )
            return {"ok": False, "error": "Konto tymczasowo zablokowane z powodu podejrzanej aktywności"}
        
        # Check rate limiting (database-backed)
        recent_attempts = await session.execute(
            select(LoginAttempt).where(
                LoginAttempt.username == username,
                LoginAttempt.created_at > datetime.utcnow() - timedelta(minutes=5)
            )
        )
        failed_attempts = [a for a in recent_attempts.scalars().all() if not a.success]

        # Require captcha after 2 failed attempts
        require_captcha = len(failed_attempts) >= 2
        
        if len(failed_attempts) >= 5:
            return {
                "ok": False, 
                "error": "Zbyt wiele nieudanych prób. Spróbuj za 5 minut.",
                "locked": True,
                "require_captcha_next_time": True
            }

        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()

        if not user:
            attempt = LoginAttempt(username=username, ip_address=client_ip, success=False)
            session.add(attempt)
            await session.commit()
            response = {"ok": False, "error": "Błędne dane logowania", "remaining": max(0, remaining - 1)}
            if require_captcha:
                captcha_data = captcha_manager.generate_captcha()
                response["require_captcha"] = True
                response["captcha"] = captcha_data
            return response

        if not verify_password(password, user.password):
            attempt = LoginAttempt(username=username, ip_address=client_ip, success=False)
            session.add(attempt)
            await session.commit()
            
            response = {"ok": False, "error": "Błędne dane logowania", "remaining": max(0, remaining - 1)}
            
            # If high risk, log suspicious activity
            if suspicious['is_suspicious'] and suspicious['risk_level'] in ['high', 'critical']:
                await SuspiciousActivityDetector.log_suspicious_activity(
                    session, user.id, username, client_ip,
                    suspicious['reason'], suspicious['risk_level']
                )
            
            if require_captcha or len(failed_attempts) + 1 >= 2:
                captcha_data = captcha_manager.generate_captcha()
                response["require_captcha"] = True
                response["captcha"] = captcha_data
            
            return response

        # Check if banned
        if await check_user_banned(user):
            return {"ok": False, "error": f"Konto zablokowane do {user.banned_until}"}

        # Successful login
        attempt = LoginAttempt(username=username, ip_address=client_ip, success=True)
        session.add(attempt)
        
        # Log login history
        login_hist = LoginHistory(
            user_id=user.id,
            ip_address=client_ip,
            device_info=request.headers.get("user-agent", "Unknown")[:255],
            success=True
        )
        session.add(login_hist)

        # Create session
        session_token = hash_token(generate_reset_token())
        expires_at = datetime.utcnow() + timedelta(days=30)

        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            device_info=request.headers.get("user-agent", "Unknown")[:255],
            ip_address=client_ip,
            expires_at=expires_at
        )
        session.add(user_session)

        user.last_seen = datetime.utcnow()
        await session.commit()

        await log_activity(session, user.id, "LOGIN", f"User logged in from {client_ip}", client_ip)

        # Reset rate limit on success
        rate_limiter.reset(rate_key)

        # Check if email is verified (if email is set)
        email_not_verified = False
        if user.email:
            # Check if email is verified
            result = await session.execute(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id,
                    EmailVerificationToken.verified == True
                )
            )
            verified = result.scalars().first()
            if not verified:
                email_not_verified = True

        # Strict mode: block unverified emails (configurable via env)
        strict_email_mode = os.getenv("STRICT_EMAIL_VERIFICATION", "false").lower() == "true"

        if strict_email_mode and email_not_verified:
            # Log suspicious activity
            await log_activity(session, user.id, "LOGIN_BLOCKED_UNVERIFIED_EMAIL",
                             f"User blocked due to unverified email from {client_ip}", client_ip)
            return {
                "ok": False,
                "error": "Email niezweryfikowany. Sprawdź skrzynkę odbiorczą i kliknij link weryfikacyjny.",
                "email_not_verified": True,
                "user_email": user.email
            }

        if user.is_2fa_enabled:
            response = {"ok": True, "requires_2fa": True, "username": username}
            if email_not_verified:
                response["email_not_verified"] = True
                response["warning"] = "Email niezweryfikowany - niektóre funkcje mogą być niedostępne"
            return response

        response = {"ok": True, "redirect": "/chat"}
        if email_not_verified:
            response["email_not_verified"] = True
            response["user_email"] = user.email
            response["warning"] = "Email niezweryfikowany - sprawdź skrzynkę odbiorczą"

        request.session["user_name"] = username
        return response


# --- Password Reset ---

@app.get('/forgot-password')
async def forgot_password_page(request: Request):
    return templates.TemplateResponse('auth.html', {'request': request, 'title': 'Resetowanie hasła'})

@app.post('/api/forgot-password')
async def request_password_reset(request: Request, username: str = Form(...)):
    """Request password reset token with rate limiting"""
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"forgot_pwd:{client_ip}"
    
    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=3, window_seconds=3600)
    if not allowed:
        return {"ok": False, "error": "Zbyt wiele prób. Spróbuj za godzinę."}
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()

        if not user:
            return {"ok": True, "message": "Jeśli użytkownik istnieje, token został wysłany."}

        # Generate token
        token = generate_reset_token()
        hashed_token = hash_token(token)
        expires_at = datetime.utcnow() + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS)

        reset_token = PasswordResetToken(user_id=user.id, token=hashed_token, expires_at=expires_at)
        session.add(reset_token)
        await session.commit()

        # In production, send email here
        # For now, return token for testing
        return {"ok": True, "message": "Token wygenerowany", "debug_token": token}

@app.get('/reset-password')
async def reset_password_page(request: Request, token: str = None):
    if not token:
        return RedirectResponse(url='/forgot-password')
    return templates.TemplateResponse('auth.html', {'request': request, 'title': 'Nowe hasło', 'reset_token': token})

@app.post('/api/reset-password')
async def perform_password_reset(request: Request, token: str = Form(...), new_password: str = Form(...)):
    """Reset password with token"""
    # Check password strength
    is_strong, msg = verify_password_strength(new_password)
    if not is_strong:
        return {"ok": False, "error": msg}
    
    async with AsyncSessionLocal() as session:
        hashed_token = hash_token(token)
        result = await session.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token == hashed_token,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.utcnow()
            )
        )
        reset_token = result.scalars().first()
        
        if not reset_token:
            return {"ok": False, "error": "Nieprawidłowy lub wygasły token"}
        
        result = await session.execute(select(User).where(User.id == reset_token.user_id))
        user = result.scalars().first()
        
        if user:
            user.password = hash_password(new_password)
            reset_token.used = True
            await session.commit()
            await log_activity(session, user.id, "PASSWORD_RESET", "Password was reset")
        
        return {"ok": True, "message": "Hasło zostało zresetowane"}


# --- 2FA Management ---

@app.get('/2fa/setup')
async def setup_2fa_page(request: Request):
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.totp_secret:
            user.totp_secret = generate_totp_secret()
            await session.commit()
        
        totp_uri = get_totp_uri(user_name, user.totp_secret)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code = base64.b64encode(buffered.getvalue()).decode()
        
        return templates.TemplateResponse('2fa_setup.html', {
            'request': request,
            'current_user': user_name,
            'qr_code': qr_code,
            'secret': user.totp_secret
        })

@app.post('/api/2fa/enable')
async def enable_2fa(request: Request, totp_code: str = Form(...)):
    """Enable 2FA after verifying code"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not user.totp_secret:
            raise HTTPException(status_code=400, detail="2FA not initialized")
        
        if not verify_totp(user.totp_secret, totp_code):
            return {"ok": False, "error": "Nieprawidłowy kod"}
        
        user.is_2fa_enabled = True
        await session.commit()
        await log_activity(session, user.id, "2FA_ENABLED", "Two-factor authentication enabled")
        
        return {"ok": True}

@app.post('/api/2fa/disable')
async def disable_2fa(request: Request, password: str = Form(...)):
    """Disable 2FA with password confirmation"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not verify_password(password, user.password):
            return {"ok": False, "error": "Nieprawidłowe hasło"}
        
        user.is_2fa_enabled = False
        user.totp_secret = None
        await session.commit()
        await log_activity(session, user.id, "2FA_DISABLED", "Two-factor authentication disabled")
        
        return {"ok": True}


# --- Session Management ---

@app.get('/sessions')
async def sessions_page(request: Request):
    """View active sessions"""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).order_by(UserSession.last_activity.desc())
        )
        sessions = result.scalars().all()
        
        return templates.TemplateResponse('sessions.html', {
            'request': request,
            'current_user': user_name,
            'sessions': sessions
        })

@app.post('/api/session/revoke/{session_id}')
async def revoke_session(session_id: int, request: Request):
    """Revoke a specific session"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.user_id == user.id
            )
        )
        user_session = result.scalars().first()
        
        if user_session:
            user_session.is_active = False
            await session.commit()
        
        return {"ok": True}

@app.post('/api/sessions/revoke-all')
async def revoke_all_sessions(request: Request):
    """Revoke all sessions except current"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        await session.execute(
            update(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.is_active == True
            )
            .values(is_active=False)
        )
        await session.commit()

        return {"ok": True}


# --- Email Verification ---

@app.get('/api/verify-email')
async def verify_email_endpoint(request: Request, token: str, username: str):
    """Verify email with token"""
    result = await verify_email_token(token, username)
    
    if result['ok']:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'message': result['message']
        })
    else:
        return templates.TemplateResponse('auth.html', {
            'request': request,
            'title': 'Logowanie',
            'error': result['error']
        })

@app.post('/api/email/resend-verification')
async def resend_verification_email(request: Request):
    """Resend email verification"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"email_verify:{client_ip}:{user_name}"
    
    allowed, remaining = rate_limiter.is_allowed(rate_key, max_requests=3, window_seconds=3600)
    if not allowed:
        return {"ok": False, "error": "Zbyt wiele prób. Spróbuj za godzinę."}
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not user.email:
            return {"ok": False, "error": "Email nie jest ustawiony"}
        
        return await send_email_verification(request, user.email, user_name)

@app.post('/api/email/update')
async def update_email(request: Request, email: str = Form(...)):
    """Update user email"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=404)
        
        user.email = email
        await session.commit()
        
        # Send verification
        await send_email_verification(request, email, user_name)
        
        return {"ok": True, "message": "Email zaktualizowany. Sprawdź swoją skrzynkę odbiorczą."}


# --- Security Dashboard ---

@app.get('/security')
async def security_dashboard(request: Request):
    """Security dashboard with login history, suspicious activity, etc."""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        # Get login history
        result = await session.execute(
            select(LoginHistory).where(
                LoginHistory.user_id == user.id
            ).order_by(LoginHistory.created_at.desc()).limit(50)
        )
        login_history = result.scalars().all()
        
        # Get suspicious activity logs
        result = await session.execute(
            select(ActivityLog).where(
                ActivityLog.user_id == user.id,
                ActivityLog.action.like("SUSPICIOUS%")
            ).order_by(ActivityLog.created_at.desc()).limit(20)
        )
        suspicious_logs = result.scalars().all()
        
        # Get active sessions
        result = await session.execute(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).order_by(UserSession.last_activity.desc())
        )
        sessions = result.scalars().all()
        
        return templates.TemplateResponse('security.html', {
            'request': request,
            'current_user': user_name,
            'user': user,
            'login_history': login_history,
            'suspicious_logs': suspicious_logs,
            'sessions': sessions
        })

@app.get('/api/security/login-history')
async def get_login_history(request: Request, limit: int = 50):
    """Get user's login history"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(LoginHistory).where(
                LoginHistory.user_id == user.id
            ).order_by(LoginHistory.created_at.desc()).limit(limit)
        )
        history = result.scalars().all()
        
        return {
            "history": [{
                "id": h.id,
                "ip_address": h.ip_address,
                "device_info": h.device_info,
                "location": h.location,
                "success": h.success,
                "failure_reason": h.failure_reason,
                "created_at": h.created_at.isoformat()
            } for h in history]
        }

@app.get('/api/security/suspicious-activity')
async def get_suspicious_activity(request: Request):
    """Get suspicious activity for current user"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(ActivityLog).where(
                ActivityLog.user_id == user.id,
                ActivityLog.action.like("SUSPICIOUS%")
            ).order_by(ActivityLog.created_at.desc()).limit(50)
        )
        logs = result.scalars().all()
        
        return {
            "logs": [{
                "id": log.id,
                "action": log.action,
                "details": log.details,
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat()
            } for log in logs]
        }

@app.get('/api/security/stats')
async def get_security_stats(request: Request):
    """Get security statistics for user"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        now = datetime.utcnow()
        
        # Failed login attempts last 24h
        result = await session.execute(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.username == user_name,
                LoginAttempt.success == False,
                LoginAttempt.created_at > now - timedelta(hours=24)
            )
        )
        failed_24h = result.scalar() or 0
        
        # Successful logins last 7 days
        result = await session.execute(
            select(func.count(LoginHistory.id)).where(
                LoginHistory.user_id == user.id,
                LoginHistory.success == True,
                LoginHistory.created_at > now - timedelta(days=7)
            )
        )
        success_7d = result.scalar() or 0
        
        # Active sessions
        result = await session.execute(
            select(func.count(UserSession.id)).where(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > now
            )
        )
        active_sessions = result.scalar() or 0
        
        # Suspicious activity count
        result = await session.execute(
            select(func.count(ActivityLog.id)).where(
                ActivityLog.user_id == user.id,
                ActivityLog.action.like("SUSPICIOUS%"),
                ActivityLog.created_at > now - timedelta(days=30)
            )
        )
        suspicious_30d = result.scalar() or 0
        
        return {
            "failed_attempts_24h": failed_24h,
            "successful_logins_7d": success_7d,
            "active_sessions": active_sessions,
            "suspicious_activity_30d": suspicious_30d,
            "security_score": max(0, 100 - (failed_24h * 10) - (suspicious_30d * 20))
        }


# --- Friend System ---

@app.get('/friends')
async def friends_page(request: Request):
    """Friends list page"""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        # Get friends
        result = await session.execute(
            select(Friendship).where(Friendship.user_id == user.id)
        )
        friendships = result.scalars().all()

        friend_ids = [f.friend_id for f in friendships]
        result = await session.execute(select(User).where(User.id.in_(friend_ids)))
        friends = result.scalars().all()

        # Get pending requests
        result = await session.execute(
            select(FriendRequest).where(
                FriendRequest.receiver_id == user.id,
                FriendRequest.status == "pending"
            )
        )
        pending_requests = result.scalars().all()

        return templates.TemplateResponse('friends.html', {
            'request': request,
            'current_user': user_name,
            'friends': friends,
            'pending_requests': pending_requests,
            'active_connections': []  # Will be populated by JS from WebSocket
        })

@app.post('/api/friend/request/{target_username}')
async def send_friend_request(target_username: str, request: Request):
    """Send friend request"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(select(User).where(User.user_name == target_username))
        target = result.scalars().first()
        
        if not target:
            return {"ok": False, "error": "Użytkownik nie istnieje"}
        
        if target.id == user.id:
            return {"ok": False, "error": "Nie możesz dodać samego siebie"}
        
        # Check if already friends
        result = await session.execute(
            select(Friendship).where(
                or_(
                    and_(Friendship.user_id == user.id, Friendship.friend_id == target.id),
                    and_(Friendship.user_id == target.id, Friendship.friend_id == user.id)
                )
            )
        )
        if result.scalars().first():
            return {"ok": False, "error": "Już jesteście znajomymi"}
        
        # Check if request already exists
        result = await session.execute(
            select(FriendRequest).where(
                FriendRequest.sender_id == user.id,
                FriendRequest.receiver_id == target.id,
                FriendRequest.status == "pending"
            )
        )
        if result.scalars().first():
            return {"ok": False, "error": "Zaproszenie już wysłane"}
        
        friend_request = FriendRequest(sender_id=user.id, receiver_id=target.id)
        session.add(friend_request)
        await session.commit()
        
        return {"ok": True}

@app.post('/api/friend/accept/{request_id}')
async def accept_friend_request(request_id: int, request: Request):
    """Accept friend request"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(FriendRequest).where(
                FriendRequest.id == request_id,
                FriendRequest.receiver_id == user.id
            )
        )
        friend_request = result.scalars().first()
        
        if not friend_request:
            return {"ok": False, "error": "Zaproszenie nie istnieje"}
        
        friend_request.status = "accepted"
        
        friendship = Friendship(user_id=friend_request.sender_id, friend_id=user.id)
        session.add(friendship)
        await session.commit()
        
        return {"ok": True}

@app.post('/api/friend/reject/{request_id}')
async def reject_friend_request(request_id: int, request: Request):
    """Reject friend request"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FriendRequest).where(
                FriendRequest.id == request_id
            )
        )
        friend_request = result.scalars().first()
        
        if friend_request:
            friend_request.status = "rejected"
            await session.commit()
        
        return {"ok": True}

@app.delete('/api/friend/{friend_id}')
async def remove_friend(friend_id: int, request: Request):
    """Remove friend"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        await session.execute(
            delete(Friendship).where(
                or_(
                    and_(Friendship.user_id == user.id, Friendship.friend_id == friend_id),
                    and_(Friendship.user_id == friend_id, Friendship.friend_id == user.id)
                )
            )
        )
        await session.commit()
        
        return {"ok": True}


# --- Message Reactions ---

@app.post('/api/message/{message_id}/react')
async def add_reaction(message_id: int, request: Request, emoji: str = Form(...)):
    """Add reaction to message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Message).where(Message.id == message_id))
        message = result.scalars().first()
        
        if not message:
            return {"ok": False, "error": "Wiadomość nie istnieje"}
        
        # Check if reaction already exists
        result = await session.execute(
            select(MessageReaction).where(
                MessageReaction.message_id == message_id,
                MessageReaction.user_name == user_name,
                MessageReaction.emoji == emoji
            )
        )
        existing = result.scalars().first()
        
        if existing:
            await session.delete(existing)
        else:
            reaction = MessageReaction(message_id=message_id, user_name=user_name, emoji=emoji)
            session.add(reaction)
        
        await session.commit()
        
        # Notify via websocket if needed
        return {"ok": True}

@app.get('/api/message/{message_id}/reactions')
async def get_reactions(message_id: int):
    """Get all reactions for a message"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MessageReaction).where(MessageReaction.message_id == message_id)
        )
        reactions = result.scalars().all()
        
        return [{"emoji": r.emoji, "user": r.user_name} for r in reactions]


# --- Message Edit & Reply ---

@app.put('/api/message/{message_id}')
async def edit_message(message_id: int, request: Request, text: str = Form(...)):
    """Edit own message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Message).where(Message.id == message_id))
        message = result.scalars().first()
        
        if not message or message.sender_name != user_name:
            raise HTTPException(status_code=403, detail="Not your message")
        
        # Apply profanity filter
        profanity_words = await get_profanity_words(session)
        message.text = censor_profanity(text, profanity_words)
        message.edited_at = datetime.utcnow()
        
        await session.commit()
        
        return {"ok": True}

@app.post('/api/message/{message_id}/reply')
async def reply_to_message(message_id: int, request: Request, text: str = Form(...), to: str = Form(...)):
    """Reply to a message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Message).where(Message.id == message_id))
        original = result.scalars().first()
        
        if not original:
            return {"ok": False, "error": "Wiadomość nie istnieje"}
        
        # Apply profanity filter
        profanity_words = await get_profanity_words(session)
        filtered_text = censor_profanity(text, profanity_words)
        
        new_msg = Message(
            sender_name=user_name,
            receiver_name=to,
            text=filtered_text,
            reply_to_id=message_id
        )
        session.add(new_msg)
        await session.commit()
        
        # Notify via websocket
        payload = {
            "type": "message",
            "sender": user_name,
            "to": to,
            "text": filtered_text,
            "id": new_msg.id,
            "reply_to_id": message_id
        }
        await manager.send_personal_message(payload, to)
        await manager.send_personal_message(payload, user_name)
        
        return {"ok": True}


# --- Group Chats ---

@app.get('/groups')
async def groups_page(request: Request):
    """Groups list page"""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(GroupMember).where(GroupMember.user_id == user.id, GroupMember.is_banned == False)
        )
        memberships = result.scalars().all()
        
        group_ids = [m.group_id for m in memberships]
        result = await session.execute(select(Group).where(Group.id.in_(group_ids), Group.is_active == True))
        groups = result.scalars().all()
        
        return templates.TemplateResponse('groups.html', {
            'request': request,
            'current_user': user_name,
            'groups': groups
        })

@app.post('/api/groups/create')
async def create_group(request: Request, name: str = Form(...), description: str = Form(None)):
    """Create a new group"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        group = Group(name=name, description=description, owner_id=user.id)
        session.add(group)
        await session.flush()
        
        # Add owner as member
        member = GroupMember(group_id=group.id, user_id=user.id, role="owner")
        session.add(member)
        await session.commit()
        
        return {"ok": True, "group_id": group.id}

@app.get('/api/groups/{group_id}/messages')
async def get_group_messages(group_id: int, request: Request):
    """Get messages from group chat"""
    user_name = request.session.get("user_name")
    if not user_name:
        return []
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GroupMessage).where(
                GroupMessage.group_id == group_id,
                GroupMessage.is_deleted == False
            ).order_by(GroupMessage.created_at.asc())
        )
        messages = result.scalars().all()
        
        return [
            {
                "id": m.id,
                "sender_id": m.sender_id,
                "text": m.text,
                "file": m.file_name,
                "file_url": m.file_path,
                "created_at": m.created_at.isoformat(),
                "reply_to_id": m.reply_to_id
            }
            for m in messages
        ]

@app.post('/api/groups/{group_id}/message')
async def send_group_message(group_id: int, request: Request, text: str = Form(...)):
    """Send message to group chat"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        # Check membership
        result = await session.execute(
            select(GroupMember).where(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user.id,
                GroupMember.is_banned == False
            )
        )
        member = result.scalars().first()
        
        if not member:
            raise HTTPException(status_code=403, detail="Not a group member")
        
        # Apply profanity filter
        profanity_words = await get_profanity_words(session)
        filtered_text = censor_profanity(text, profanity_words)
        
        msg = GroupMessage(group_id=group_id, sender_id=user.id, text=filtered_text)
        session.add(msg)
        await session.commit()
        
        # Notify group members via websocket
        payload = {
            "type": "group_message",
            "group_id": group_id,
            "sender": user_name,
            "text": filtered_text,
            "id": msg.id
        }
        
        for conn_username in manager.active_connections.keys():
            await manager.send_personal_message(payload, conn_username)
        
        return {"ok": True}

@app.post('/api/groups/{group_id}/invite')
async def invite_to_group(group_id: int, request: Request, username: str = Form(...)):
    """Invite user to group"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(select(User).where(User.user_name == username))
        target = result.scalars().first()
        
        if not target:
            return {"ok": False, "error": "Użytkownik nie istnieje"}
        
        # Check if already member
        result = await session.execute(
            select(GroupMember).where(
                GroupMember.group_id == group_id,
                GroupMember.user_id == target.id
            )
        )
        if result.scalars().first():
            return {"ok": False, "error": "Użytkownik już jest w grupie"}
        
        member = GroupMember(group_id=group_id, user_id=target.id, role="member")
        session.add(member)
        await session.commit()
        
        return {"ok": True}


# --- Admin Features ---

@app.get('/admin/activity-logs')
async def activity_logs_page(request: Request, user_id: int = None):
    """View activity logs"""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user or not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        query = select(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(100)
        if user_id:
            query = query.where(ActivityLog.user_id == user_id)
        
        result = await session.execute(query)
        logs = result.scalars().all()
        
        return templates.TemplateResponse('activity_logs.html', {
            'request': request,
            'current_user': user_name,
            'logs': logs
        })

@app.post('/api/admin/warn/{user_id}')
async def warn_user(user_id: int, request: Request, reason: str = Form(...)):
    """Issue warning to user"""
    admin_name = request.session.get("user_name")
    if not admin_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == admin_name))
        admin = result.scalars().first()
        
        if not admin or not admin.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(User).where(User.id == user_id))
        target = result.scalars().first()
        
        if not target:
            return {"ok": False, "error": "Użytkownik nie istnieje"}
        
        warning = UserWarning(user_id=user_id, admin_id=admin.id, reason=reason)
        session.add(warning)
        await session.commit()
        
        await log_activity(session, admin.id, "WARNING_ISSUED", f"Warning issued to {target.user_name}: {reason}")
        
        return {"ok": True}

@app.post('/api/admin/ban/{user_id}')
async def ban_user(user_id: int, request: Request, duration_hours: int = Form(24), reason: str = Form(...)):
    """Temporarily ban user"""
    admin_name = request.session.get("user_name")
    if not admin_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == admin_name))
        admin = result.scalars().first()
        
        if not admin or not admin.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(User).where(User.id == user_id))
        target = result.scalars().first()
        
        if not target:
            return {"ok": False, "error": "Użytkownik nie istnieje"}
        
        if target.is_admin:
            return {"ok": False, "error": "Cannot ban admin"}
        
        target.is_banned = True
        target.banned_until = datetime.utcnow() + timedelta(hours=duration_hours)
        await session.commit()
        
        await log_activity(session, admin.id, "USER_BANNED", f"User {target.user_name} banned for {duration_hours}h: {reason}")
        
        return {"ok": True}

@app.post('/api/admin/unban/{user_id}')
async def unban_user(user_id: int, request: Request):
    """Unban user"""
    admin_name = request.session.get("user_name")
    if not admin_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == admin_name))
        admin = result.scalars().first()
        
        if not admin or not admin.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(User).where(User.id == user_id))
        target = result.scalars().first()
        
        if target:
            target.is_banned = False
            target.banned_until = None
            await session.commit()
        
        return {"ok": True}

@app.post('/api/admin/profanity/add')
async def add_profanity_word(request: Request, word: str = Form(...), replacement: str = Form("****")):
    """Add word to profanity filter"""
    admin_name = request.session.get("user_name")
    if not admin_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == admin_name))
        admin = result.scalars().first()
        
        if not admin or not admin.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        try:
            profanity = ProfanityFilter(word=word, replacement=replacement)
            session.add(profanity)
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return {"ok": False, "error": "Słowo już istnieje"}
        
        return {"ok": True}

@app.delete('/api/admin/profanity/{word_id}')
async def remove_profanity_word(word_id: int, request: Request):
    """Remove word from profanity filter"""
    admin_name = request.session.get("user_name")
    if not admin_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == admin_name))
        admin = result.scalars().first()
        
        if not admin or not admin.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(ProfanityFilter).where(ProfanityFilter.id == word_id))
        profanity = result.scalars().first()
        
        if profanity:
            await session.delete(profanity)
            await session.commit()
        
        return {"ok": True}


# --- User Profile & Settings ---

@app.get('/profile/{username}')
async def profile_page(username: str, request: Request):
    """View user profile"""
    current_user = request.session.get("user_name")
    if not current_user:
        return RedirectResponse(url='/login')
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == username))
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if friends
        is_friend = False
        if current_user:
            result_current = await session.execute(select(User).where(User.user_name == current_user))
            current = result_current.scalars().first()
            result = await session.execute(
                select(Friendship).where(
                    or_(
                        and_(Friendship.user_id == current.id, Friendship.friend_id == user.id),
                        and_(Friendship.user_id == user.id, Friendship.friend_id == current.id)
                    )
                )
            )
            is_friend = result.scalars().first() is not None
        
        return templates.TemplateResponse('profile.html', {
            'request': request,
            'current_user': current_user,
            'profile_user': user,
            'is_friend': is_friend
        })

@app.post('/api/profile/dark-mode')
async def toggle_dark_mode(request: Request, enabled: bool = Form(...)):
    """Toggle dark mode preference"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if user:
            user.dark_mode = enabled
            await session.commit()
        
        return {"ok": True}

@app.post('/api/profile/status')
async def update_status(request: Request, status: str = Form(...)):
    """Update user status"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if user:
            user.status = status
            await session.commit()
        
        await manager.broadcast_status(user_name, status)
        return {"ok": True}


# --- Chat Export ---

@app.get('/api/chat/export/{other_user}')
async def export_chat(other_user: str, request: Request, format: str = "json"):
    """Export chat history"""
    current_user = request.session.get("user_name")
    if not current_user:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        query = select(Message).where(
            or_(
                and_(Message.sender_name == current_user, Message.receiver_name == other_user),
                and_(Message.sender_name == other_user, Message.receiver_name == current_user)
            )
        ).order_by(Message.created_at.asc())
        
        result = await session.execute(query)
        messages = result.scalars().all()
        
        if format == "json":
            data = [
                {
                    "id": m.id,
                    "sender": m.sender_name,
                    "text": m.text,
                    "file": m.file_name,
                    "created_at": m.created_at.isoformat()
                }
                for m in messages
            ]
            return JSONResponse(content=data)
        
        elif format == "txt":
            text = "\n".join([f"[{m.created_at}] {m.sender_name}: {m.text or '[file]'}" for m in messages])
            return StreamingResponse(io.StringIO(text), media_type="text/plain", headers={"Content-Disposition": f"attachment; filename=chat_{other_user}.txt"})
        
        return {"error": "Invalid format"}


# --- Push Notifications ---

@app.post('/api/push/register')
async def register_push_token(request: Request, token: str = Form(...), device_type: str = Form("web")):
    """Register push notification token"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        push_token = PushNotificationToken(user_id=user.id, token=token, device_type=device_type)
        session.add(push_token)
        await session.commit()
        
        return {"ok": True}


# --- Search ---

@app.get('/api/search/users')
async def search_users(q: str, request: Request):
    """Search users"""
    user_name = request.session.get("user_name")
    if not user_name:
        return []
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(
                User.user_name.like(f"%{q}%"),
                User.user_name != user_name
            ).limit(20)
        )
        users = result.scalars().all()
        
        return [{"username": u.user_name, "avatar": u.avatar_url, "status": u.status} for u in users]

@app.get('/api/search/messages')
async def search_messages(q: str, request: Request):
    """Search messages"""
    user_name = request.session.get("user_name")
    if not user_name:
        return []

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Message).where(
                or_(
                    Message.sender_name == user_name,
                    Message.receiver_name == user_name
                ),
                Message.text.like(f"%{q}%"),
                Message.is_deleted == False
            ).order_by(Message.created_at.desc()).limit(50)
        )
        messages = result.scalars().all()

        return [
            {
                "id": m.id,
                "sender": m.sender_name,
                "receiver": m.receiver_name,
                "text": m.text,
                "created_at": m.created_at.isoformat()
            }
            for m in messages
        ]


# ==================== FAZA 1: BEZPIECZEŃSTWO ====================

@app.get('/api/security/2fa/backup-codes')
async def generate_backup_codes(request: Request):
    """Generate 2FA backup codes"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=404)
        
        # Generate 10 backup codes
        import secrets
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        # Store hashed codes
        for code in backup_codes:
            backup_code = TwoFABackupCode(user_id=user.id, code_hash=hash_password(code))
            session.add(backup_code)
        
        await session.commit()
        
        return {"ok": True, "codes": backup_codes}

@app.post('/api/security/2fa/verify-backup')
async def verify_backup_code(request: Request, code: str = Form(...)):
    """Verify 2FA backup code"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(TwoFABackupCode).where(
                TwoFABackupCode.user_id == user.id,
                TwoFABackupCode.used == False
            )
        )
        backup_codes = result.scalars().all()
        
        for bc in backup_codes:
            if verify_password(code, bc.code_hash):
                bc.used = True
                await session.commit()
                return {"ok": True}
        
        return {"ok": False, "error": "Nieprawidłowy kod zapasowy"}

@app.get('/api/security/login-history')
async def get_login_history(request: Request):
    """Get user login history"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(LoginHistory).where(LoginHistory.user_id == user.id)
            .order_by(LoginHistory.created_at.desc()).limit(50)
        )
        history = result.scalars().all()
        
        return [{
            "id": h.id,
            "ip": h.ip_address,
            "device": h.device_info,
            "location": h.location,
            "success": h.success,
            "date": h.created_at.isoformat()
        } for h in history]

@app.post('/api/security/block/{blocked_username}')
async def block_user(blocked_username: str, request: Request):
    """Block a user"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(select(User).where(User.user_name == blocked_username))
        blocked = result.scalars().first()
        
        if not blocked:
            return {"ok": False, "error": "Użytkownik nie istnieje"}
        
        if blocked.id == user.id:
            return {"ok": False, "error": "Nie możesz zablokować samego siebie"}
        
        try:
            block = BlockedUser(user_id=user.id, blocked_user_id=blocked.id)
            session.add(block)
            await session.commit()
            return {"ok": True}
        except IntegrityError:
            await session.rollback()
            return {"ok": False, "error": "Użytkownik już zablokowany"}

@app.delete('/api/security/unblock/{blocked_username}')
async def unblock_user(blocked_username: str, request: Request):
    """Unblock a user"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(select(User).where(User.user_name == blocked_username))
        blocked = result.scalars().first()
        
        if blocked:
            await session.execute(
                delete(BlockedUser).where(
                    BlockedUser.user_id == user.id,
                    BlockedUser.blocked_user_id == blocked.id
                )
            )
            await session.commit()
        
        return {"ok": True}

@app.get('/api/security/blocked-users')
async def get_blocked_users(request: Request):
    """Get list of blocked users"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(BlockedUser).where(BlockedUser.user_id == user.id)
        )
        blocked = result.scalars().all()
        
        blocked_ids = [b.blocked_user_id for b in blocked]
        result = await session.execute(select(User).where(User.id.in_(blocked_ids)))
        users = result.scalars().all()
        
        return [{"id": u.id, "username": u.user_name, "avatar": u.avatar_url} for u in users]


# ==================== FAZA 2: WIADOMOŚCI ====================

@app.post('/api/message/{message_id}/pin')
async def pin_message(message_id: int, request: Request):
    """Pin a message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(select(Message).where(Message.id == message_id))
        message = result.scalars().first()
        
        if not message:
            return {"ok": False, "error": "Wiadomość nie istnieje"}
        
        pin = PinnedMessage(message_id=message_id, user_id=user.id, pinned_by=user_name)
        session.add(pin)
        await session.commit()
        
        return {"ok": True}

@app.delete('/api/message/{message_id}/unpin')
async def unpin_message(message_id: int, request: Request):
    """Unpin a message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        await session.execute(
            delete(PinnedMessage).where(PinnedMessage.message_id == message_id)
        )
        await session.commit()
        
        return {"ok": True}

@app.get('/api/messages/pinned/{chat_user}')
async def get_pinned_messages(chat_user: str, request: Request):
    """Get pinned messages for a chat"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(Message).where(
                or_(
                    and_(Message.sender_name == user_name, Message.receiver_name == chat_user),
                    and_(Message.sender_name == chat_user, Message.receiver_name == user_name)
                )
            )
        )
        chat_messages = result.scalars().all()
        chat_msg_ids = [m.id for m in chat_messages]
        
        result = await session.execute(
            select(PinnedMessage).where(
                PinnedMessage.message_id.in_(chat_msg_ids)
            )
        )
        pinned = result.scalars().all()
        
        pinned_msg_ids = [p.message_id for p in pinned]
        result = await session.execute(
            select(Message).where(Message.id.in_(pinned_msg_ids))
            .options(selectinload(Message.reply_to))
        )
        messages = result.scalars().all()
        
        return [{
            "id": m.id,
            "text": m.text,
            "sender": m.sender_name,
            "date": m.created_at.isoformat()
        } for m in messages]

@app.post('/api/message/{message_id}/star')
async def star_message(message_id: int, request: Request):
    """Star/favorite a message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        try:
            starred = StarredMessage(message_id=message_id, user_id=user.id)
            session.add(starred)
            await session.commit()
            return {"ok": True}
        except IntegrityError:
            await session.rollback()
            return {"ok": False, "error": "Już oznaczone"}

@app.delete('/api/message/{message_id}/unstar')
async def unstar_message(message_id: int, request: Request):
    """Unstar a message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        await session.execute(
            delete(StarredMessage).where(
                StarredMessage.message_id == message_id,
                StarredMessage.user_id == user.id
            )
        )
        await session.commit()
        
        return {"ok": True}

@app.get('/api/messages/starred')
async def get_starred_messages(request: Request):
    """Get all starred messages"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(StarredMessage).where(StarredMessage.user_id == user.id)
            .order_by(StarredMessage.created_at.desc())
        )
        starred = result.scalars().all()
        
        msg_ids = [s.message_id for s in starred]
        result = await session.execute(
            select(Message).where(Message.id.in_(msg_ids))
            .options(selectinload(Message.reply_to))
        )
        messages = result.scalars().all()
        
        return [{
            "id": m.id,
            "text": m.text,
            "sender": m.sender_name,
            "date": m.created_at.isoformat()
        } for m in messages]

@app.post('/api/message/{message_id}/undo')
async def undo_send_message(message_id: int, request: Request):
    """Undo send message (within 5 minutes)"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Message).where(Message.id == message_id))
        message = result.scalars().first()
        
        if not message or message.sender_name != user_name:
            raise HTTPException(status_code=403)
        
        # Check if within 5 minutes
        if datetime.utcnow() - message.created_at > timedelta(minutes=5):
            return {"ok": False, "error": "Zbyt późno na cofnięcie"}
        
        message.is_deleted = True
        message.text = "Wiadomość została cofnięta"
        await session.commit()
        
        return {"ok": True}


# ==================== FAZA 3: GŁOSOWE, WIDEO, ANKIETY ====================

@app.post('/api/message/voice')
async def send_voice_message(
    request: Request,
    to: str = Form(...),
    duration: int = Form(...),
    waveform: str = Form(None)
):
    """Send voice message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        # Create message
        msg = Message(
            sender_name=user_name,
            receiver_name=to,
            text=f"[Wiadomość głosowa {duration}s]",
            file_type="voice"
        )
        session.add(msg)
        await session.flush()
        
        # Create voice metadata
        voice = VoiceMessage(message_id=msg.id, duration=duration, waveform=waveform)
        session.add(voice)
        
        # Update stats
        await update_user_stats(session, user_name, "voice_messages_sent")
        
        await session.commit()
        
        payload = {
            "type": "voice_message",
            "sender": user_name,
            "to": to,
            "duration": duration,
            "id": msg.id
        }
        await manager.send_personal_message(payload, to)
        await manager.send_personal_message(payload, user_name)
        
        return {"ok": True, "id": msg.id}

@app.post('/api/message/video')
async def send_video_message(
    request: Request,
    to: str = Form(...),
    file: UploadFile = File(...),
    duration: int = Form(None),
    width: int = Form(None),
    height: int = Form(None)
):
    """Send video message"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    file_ext = file.filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = f"{UPLOAD_DIR}/{filename}"
    
    with open(file_path, "wb") as f:
        f.write(await file.read())
    
    async with AsyncSessionLocal() as session:
        msg = Message(
            sender_name=user_name,
            receiver_name=to,
            text="[Wiadomość wideo]",
            file_path=f"/uploads/{filename}",
            file_name=filename,
            file_type="video"
        )
        session.add(msg)
        await session.flush()
        
        video = VideoMessage(
            message_id=msg.id,
            duration=duration,
            width=width,
            height=height
        )
        session.add(video)
        
        await session.commit()
        
        payload = {
            "type": "video_message",
            "sender": user_name,
            "to": to,
            "file_url": f"/uploads/{filename}",
            "duration": duration,
            "id": msg.id
        }
        await manager.send_personal_message(payload, to)
        await manager.send_personal_message(payload, user_name)
        
        return {"ok": True, "id": msg.id}

@app.post('/api/poll/create')
async def create_poll(
    request: Request,
    to: str = Form(...),
    question: str = Form(...),
    options: str = Form(...),  # JSON array
    multiple_choice: bool = Form(False)
):
    """Create a poll"""
    import json
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    option_list = json.loads(options)
    
    async with AsyncSessionLocal() as session:
        msg = Message(
            sender_name=user_name,
            receiver_name=to,
            text=f"[Ankieta: {question}]"
        )
        session.add(msg)
        await session.flush()
        
        poll = Poll(
            message_id=msg.id,
            question=question,
            multiple_choice=multiple_choice
        )
        session.add(poll)
        await session.flush()
        
        for opt_text in option_list:
            option = PollOption(poll_id=poll.id, text=opt_text)
            session.add(option)
        
        await update_user_stats(session, user_name, "polls_created")
        await session.commit()
        
        return {"ok": True, "poll_id": poll.id, "message_id": msg.id}

@app.post('/api/poll/{poll_id}/vote')
async def vote_poll(poll_id: int, request: Request, option_id: int = Form(...)):
    """Vote in a poll"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        # Check if already voted
        result = await session.execute(
            select(PollVote).where(
                PollVote.poll_id == poll_id,
                PollVote.voter_name == user_name
            )
        )
        if result.scalars().first():
            return {"ok": False, "error": "Już głosowałeś"}
        
        vote = PollVote(poll_id=poll_id, option_id=option_id, voter_name=user_name)
        session.add(vote)
        
        # Update vote count
        await session.execute(
            update(PollOption).where(PollOption.id == option_id).values(
                vote_count=PollOption.vote_count + 1
            )
        )
        
        await session.commit()
        return {"ok": True}

@app.get('/api/poll/{poll_id}')
async def get_poll(poll_id: int):
    """Get poll details"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Poll).where(Poll.id == poll_id)
            .options(selectinload(Poll.options), selectinload(Poll.votes))
        )
        poll = result.scalars().first()
        
        if not poll:
            raise HTTPException(status_code=404)
        
        return {
            "id": poll.id,
            "question": poll.question,
            "multiple_choice": poll.multiple_choice,
            "options": [{"id": o.id, "text": o.text, "votes": o.vote_count} for o in poll.options],
            "total_votes": sum(o.vote_count for o in poll.options)
        }


# ==================== FAZA 4: KONTAKTY ====================

@app.get('/api/contacts/suggestions')
async def get_contact_suggestions(request: Request):
    """Get suggested friends"""
    user_name = request.session.get("user_name")
    if not user_name:
        return []
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        # Get current friends
        result = await session.execute(
            select(Friendship).where(
                or_(
                    Friendship.user_id == user.id,
                    Friendship.friend_id == user.id
                )
            )
        )
        friendships = result.scalars().all()
        friend_ids = set()
        for f in friendships:
            friend_ids.add(f.user_id if f.friend_id == user.id else f.friend_id)
        friend_ids.add(user.id)
        
        # Get users not in friends, sorted by common friends
        result = await session.execute(
            select(User).where(~User.id.in_(friend_ids)).limit(20)
        )
        suggestions = result.scalars().all()
        
        return [{"id": u.id, "username": u.user_name, "avatar": u.avatar_url} for u in suggestions]

@app.get('/api/contacts/blocked')
async def get_blocked_list(request: Request):
    """Get blocked contacts"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(BlockedUser).where(BlockedUser.user_id == user.id)
        )
        blocked = result.scalars().all()
        
        blocked_ids = [b.blocked_user_id for b in blocked]
        result = await session.execute(select(User).where(User.id.in_(blocked_ids)))
        users = result.scalars().all()
        
        return [{"id": u.id, "username": u.user_name} for u in users]


# ==================== FAZA 5: WYGLĄD ====================

@app.get('/api/themes')
async def get_themes():
    """Get available themes"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ChatTheme))
        themes = result.scalars().all()
        
        return [{
            "id": t.id,
            "name": t.name,
            "primary": t.primary_color,
            "secondary": t.secondary_color,
            "is_dark": t.is_dark,
            "is_premium": t.is_premium
        } for t in themes]

@app.post('/api/theme/select')
async def select_theme(request: Request, theme_id: int = Form(...)):
    """Select user theme"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(select(UserTheme).where(UserTheme.user_id == user.id))
        user_theme = result.scalars().first()
        
        if user_theme:
            user_theme.theme_id = theme_id
        else:
            user_theme = UserTheme(user_id=user.id, theme_id=theme_id)
            session.add(user_theme)
        
        await session.commit()
        return {"ok": True}

@app.post('/api/wallpaper/set')
async def set_wallpaper(
    request: Request,
    wallpaper_url: str = Form(...),
    chat_with: str = Form(None),
    wallpaper_type: str = Form("image")
):
    """Set chat wallpaper"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(ChatWallpaper).where(
                ChatWallpaper.user_id == user.id,
                ChatWallpaper.chat_with == chat_with
            )
        )
        wallpaper = result.scalars().first()
        
        if wallpaper:
            wallpaper.wallpaper_url = wallpaper_url
            wallpaper.wallpaper_type = wallpaper_type
        else:
            wallpaper = ChatWallpaper(
                user_id=user.id,
                chat_with=chat_with,
                wallpaper_url=wallpaper_url,
                wallpaper_type=wallpaper_type
            )
            session.add(wallpaper)
        
        await session.commit()
        return {"ok": True}


# ==================== FAZA 6: POWIADOMIENIA ====================

@app.post('/api/chat/mute')
async def mute_chat(
    request: Request,
    chat_with: str = Form(...),
    duration_hours: int = Form(None)  # NULL = permanent
):
    """Mute a chat"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        muted_until = None
        if duration_hours:
            muted_until = datetime.utcnow() + timedelta(hours=duration_hours)
        
        try:
            mute = MutedChat(user_id=user.id, chat_with=chat_with, muted_until=muted_until)
            session.add(mute)
            await session.commit()
            return {"ok": True}
        except IntegrityError:
            await session.rollback()
            # Update existing
            result = await session.execute(
                select(MutedChat).where(
                    MutedChat.user_id == user.id,
                    MutedChat.chat_with == chat_with
                )
            )
            mute = result.scalars().first()
            if mute:
                mute.muted_until = muted_until
                await session.commit()
            return {"ok": True}

@app.delete('/api/chat/unmute/{chat_with}')
async def unmute_chat(chat_with: str, request: Request):
    """Unmute a chat"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        await session.execute(
            delete(MutedChat).where(
                MutedChat.user_id == user.id,
                MutedChat.chat_with == chat_with
            )
        )
        await session.commit()
        
        return {"ok": True}

@app.get('/api/chat/muted')
async def get_muted_chats(request: Request):
    """Get muted chats"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(MutedChat).where(MutedChat.user_id == user.id)
        )
        muted = result.scalars().all()
        
        return [{
            "chat_with": m.chat_with,
            "muted_until": m.muted_until.isoformat() if m.muted_until else "permanent"
        } for m in muted]


# ==================== FAZA 7: PLIKI ====================

@app.post('/api/files/upload')
async def upload_to_storage(
    request: Request,
    file: UploadFile = File(...)
):
    """Upload file to cloud storage"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    file_ext = file.filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = f"{UPLOAD_DIR}/storage/{filename}"
    
    os.makedirs(f"{UPLOAD_DIR}/storage", exist_ok=True)
    
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        storage = FileStorage(
            user_id=user.id,
            file_path=file_path,
            file_name=file.filename,
            file_size=len(content),
            file_type=file.content_type
        )
        session.add(storage)
        await session.commit()
        
        return {
            "ok": True,
            "file_id": storage.id,
            "url": f"/uploads/storage/{filename}",
            "size": len(content)
        }

@app.get('/api/files/storage')
async def get_storage_files(request: Request):
    """Get user's cloud storage files"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(FileStorage).where(FileStorage.user_id == user.id)
            .order_by(FileStorage.created_at.desc())
        )
        files = result.scalars().all()
        
        total_size = sum(f.file_size for f in files)
        
        return {
            "files": [{
                "id": f.id,
                "name": f.file_name,
                "size": f.file_size,
                "type": f.file_type,
                "url": f"/{f.file_path}",
                "date": f.created_at.isoformat()
            } for f in files],
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }

@app.delete('/api/files/storage/{file_id}')
async def delete_storage_file(file_id: int, request: Request):
    """Delete file from storage"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(FileStorage).where(
                FileStorage.id == file_id,
                FileStorage.user_id == user.id
            )
        )
        storage = result.scalars().first()
        
        if storage:
            if os.path.exists(storage.file_path):
                os.remove(storage.file_path)
            await session.delete(storage)
            await session.commit()
        
        return {"ok": True}

@app.post('/api/qr/generate')
async def generate_qr(request: Request, data: str = Form(...)):
    """Generate QR code"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    filename = f"qr_{uuid.uuid4()}.png"
    file_path = f"{UPLOAD_DIR}/qr/{filename}"
    os.makedirs(f"{UPLOAD_DIR}/qr", exist_ok=True)
    img.save(file_path)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        qr_data = QRCodeData(
            user_id=user.id,
            data=data,
            qr_image_path=file_path
        )
        session.add(qr_data)
        await session.commit()
        
        return {
            "ok": True,
            "qr_url": f"/uploads/qr/{filename}",
            "id": qr_data.id
        }


# ==================== FAZA 8: USTAWIENIA ====================

@app.get('/api/settings/export')
async def export_user_data(request: Request):
    """Export all user data (GDPR)"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        # Get all messages
        result = await session.execute(
            select(Message).where(
                or_(
                    Message.sender_name == user_name,
                    Message.receiver_name == user_name
                )
            )
        )
        messages = result.scalars().all()
        
        # Get friends
        result = await session.execute(
            select(Friendship).where(Friendship.user_id == user.id)
        )
        friendships = result.scalars().all()
        
        data = {
            "user": {
                "username": user.user_name,
                "email": user.email,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "status": user.status
            },
            "messages": [{
                "id": m.id,
                "sender": m.sender_name,
                "receiver": m.receiver_name,
                "text": m.text,
                "date": m.created_at.isoformat()
            } for m in messages],
            "friends_count": len(friendships),
            "export_date": datetime.utcnow().isoformat()
        }
        
        return data

@app.post('/api/settings/auto-delete')
async def set_auto_delete(
    request: Request,
    hours: int = Form(...),
    chat_with: str = Form(None),
    enabled: bool = Form(True)
):
    """Set auto-delete setting"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(AutoDeleteSetting).where(
                AutoDeleteSetting.user_id == user.id,
                AutoDeleteSetting.chat_with == chat_with
            )
        )
        setting = result.scalars().first()
        
        if setting:
            setting.delete_after_hours = hours
            setting.enabled = enabled
        else:
            setting = AutoDeleteSetting(
                user_id=user.id,
                chat_with=chat_with,
                delete_after_hours=hours,
                enabled=enabled
            )
            session.add(setting)
        
        await session.commit()
        return {"ok": True}

@app.post('/api/settings/language')
async def set_language(request: Request, language: str = Form(...)):
    """Set user language"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(UserLanguage).where(UserLanguage.user_id == user.id)
        )
        lang = result.scalars().first()
        
        if lang:
            lang.language = language
        else:
            lang = UserLanguage(user_id=user.id, language=language)
            session.add(lang)
        
        await session.commit()
        return {"ok": True}


# ==================== FAZA 9: INNE ====================

@app.get('/api/stats')
async def get_user_stats(request: Request):
    """Get user statistics"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(UserStatistic).where(UserStatistic.user_id == user.id)
        )
        stats = result.scalars().first()
        
        if not stats:
            # Create default stats
            stats = UserStatistic(user_id=user.id)
            session.add(stats)
            await session.commit()
        
        return {
            "messages_sent": stats.messages_sent,
            "messages_received": stats.messages_received,
            "files_sent": stats.files_sent,
            "voice_messages": stats.voice_messages_sent,
            "stickers_sent": stats.stickers_sent,
            "polls_created": stats.polls_created
        }

@app.post('/api/focus-mode')
async def toggle_focus_mode(
    request: Request,
    enabled: bool = Form(...),
    hide_sidebar: bool = Form(False),
    hide_notifications: bool = Form(False)
):
    """Toggle focus mode"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(FocusMode).where(FocusMode.user_id == user.id)
        )
        focus = result.scalars().first()
        
        if focus:
            focus.enabled = enabled
            focus.hide_sidebar = hide_sidebar
            focus.hide_notifications = hide_notifications
        else:
            focus = FocusMode(
                user_id=user.id,
                enabled=enabled,
                hide_sidebar=hide_sidebar,
                hide_notifications=hide_notifications
            )
            session.add(focus)
        
        await session.commit()
        return {"ok": True}

@app.get('/api/focus-mode')
async def get_focus_mode(request: Request):
    """Get focus mode settings"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(FocusMode).where(FocusMode.user_id == user.id)
        )
        focus = result.scalars().first()
        
        if not focus:
            return {"enabled": False, "hide_sidebar": False, "hide_notifications": False}
        
        return {
            "enabled": focus.enabled,
            "hide_sidebar": focus.hide_sidebar,
            "hide_notifications": focus.hide_notifications,
            "quiet_hours": {"start": focus.quiet_hours_start, "end": focus.quiet_hours_end}
        }

@app.post('/api/shortcuts/set')
async def set_keyboard_shortcut(
    request: Request,
    action: str = Form(...),
    shortcut: str = Form(...)
):
    """Set custom keyboard shortcut"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        try:
            shortcut_obj = KeyboardShortcut(user_id=user.id, action=action, shortcut=shortcut)
            session.add(shortcut_obj)
            await session.commit()
            return {"ok": True}
        except IntegrityError:
            await session.rollback()
            result = await session.execute(
                select(KeyboardShortcut).where(
                    KeyboardShortcut.user_id == user.id,
                    KeyboardShortcut.action == action
                )
            )
            sc = result.scalars().first()
            if sc:
                sc.shortcut = shortcut
                await session.commit()
            return {"ok": True}

@app.get('/api/shortcuts')
async def get_keyboard_shortcuts(request: Request):
    """Get user's keyboard shortcuts"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        result = await session.execute(
            select(KeyboardShortcut).where(KeyboardShortcut.user_id == user.id)
        )
        shortcuts = result.scalars().all()
        
        return [{
            "action": s.action,
            "shortcut": s.shortcut
        } for s in shortcuts]


# ==================== HELPER FUNCTIONS ====================

async def update_user_stats(session, user_name: str, stat_field: str):
    """Update user statistics"""
    result = await session.execute(select(User).where(User.user_name == user_name))
    user = result.scalars().first()
    
    if not user:
        return
    
    result = await session.execute(
        select(UserStatistic).where(UserStatistic.user_id == user.id)
    )
    stats = result.scalars().first()
    
    if not stats:
        stats = UserStatistic(user_id=user.id)
        session.add(stats)
        await session.flush()

    if hasattr(stats, stat_field):
        setattr(stats, stat_field, getattr(stats, stat_field) + 1)

    stats.last_stats_update = datetime.utcnow()
    await session.commit()


# ==================== BOT API ====================

class BotManager:
    """Manager for bot integrations"""
    def __init__(self):
        self.active_bots: dict[str, dict] = {}
        self.bot_commands: dict[str, list] = {}
        self.bot_events: dict[str, list] = {}
    
    async def dispatch_event(self, event_type: str, data: dict):
        """Dispatch event to all subscribed bots"""
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(BotIntegration).where(BotIntegration.enabled == True)
            )
            bots = result.scalars().all()
            
            for bot in bots:
                import json
                config = json.loads(bot.config) if bot.config else {}
                subscribed_events = config.get('events', [])
                
                if event_type in subscribed_events and bot.webhook_url:
                    # Send webhook
                    import aiohttp
                    try:
                        async with aiohttp.ClientSession() as http_session:
                            await http_session.post(
                                bot.webhook_url,
                                json={'event': event_type, 'data': data},
                                headers={'Authorization': f'Bearer {bot.api_key}'}
                            )
                    except Exception as e:
                        print(f"Bot webhook error: {e}")
    
    def register_command(self, bot_name: str, command: str, handler):
        """Register bot command"""
        if bot_name not in self.bot_commands:
            self.bot_commands[bot_name] = []
        self.bot_commands[bot_name].append({'command': command, 'handler': handler})
    
    async def process_command(self, command: str, args: list, user: str, session: AsyncSessionLocal):
        """Process bot command"""
        for bot_name, commands in self.bot_commands.items():
            for cmd in commands:
                if cmd['command'] == command:
                    return await cmd['handler'](args, user, session)
        return None

bot_manager = BotManager()


# ==================== BOT API ENDPOINTS ====================

@app.get('/api/bots')
async def get_bots(request: Request):
    """Get all registered bots"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration))
        bots = result.scalars().all()
        
        return [{
            "id": b.id,
            "name": b.name,
            "enabled": b.enabled,
            "webhook_url": b.webhook_url,
            "created_at": b.created_at.isoformat(),
            "has_config": b.config is not None
        } for b in bots]

@app.post('/api/bots/register')
async def register_bot(
    request: Request,
    name: str = Form(...),
    webhook_url: str = Form(None),
    events: str = Form("[]"),  # JSON array
    config: str = Form("{}")   # JSON config
):
    """Register a new bot"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        import secrets
        api_key = f"bot_{secrets.token_hex(32)}"
        
        bot = BotIntegration(
            name=name,
            api_key=api_key,
            webhook_url=webhook_url,
            events=events,
            config=config
        )
        session.add(bot)
        await session.commit()
        
        bot_manager.active_bots[name] = {
            "id": bot.id,
            "api_key": api_key,
            "webhook_url": webhook_url
        }
        
        return {
            "ok": True,
            "bot_id": bot.id,
            "api_key": api_key,
            "message": "Bot zarejestrowany. Zachowaj API Key!"
        }

@app.post('/api/bots/{bot_id}/toggle')
async def toggle_bot(bot_id: int, request: Request):
    """Enable/disable bot"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration).where(BotIntegration.id == bot_id))
        bot = result.scalars().first()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        
        bot.enabled = not bot.enabled
        await session.commit()
        
        return {"ok": True, "enabled": bot.enabled}

@app.delete('/api/bots/{bot_id}')
async def delete_bot(bot_id: int, request: Request):
    """Delete a bot"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration).where(BotIntegration.id == bot_id))
        bot = result.scalars().first()
        
        if bot:
            await session.delete(bot)
            await session.commit()
        
        return {"ok": True}

@app.post('/api/bots/{bot_id}/webhook')
async def update_bot_webhook(
    bot_id: int,
    request: Request,
    webhook_url: str = Form(...)
):
    """Update bot webhook URL"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration).where(BotIntegration.id == bot_id))
        bot = result.scalars().first()
        
        if bot:
            bot.webhook_url = webhook_url
            await session.commit()
        
        return {"ok": True}

@app.get('/api/bots/{bot_id}/logs')
async def get_bot_logs(bot_id: int, request: Request, limit: int = 50):
    """Get bot activity logs"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ActivityLog).where(
                ActivityLog.action.like("BOT_%")
            ).order_by(ActivityLog.created_at.desc()).limit(limit)
        )
        logs = result.scalars().all()
        
        return [{
            "id": l.id,
            "action": l.action,
            "details": l.details,
            "date": l.created_at.isoformat()
        } for l in logs]


# ==================== BOT COMMANDS SYSTEM ====================

@app.post('/api/bots/command')
async def execute_bot_command(
    request: Request,
    command: str = Form(...),
    args: str = Form("[]"),  # JSON array
    chat_with: str = Form(None)
):
    """Execute bot command from chat"""
    import json
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        command_parts = args if args else []
        if isinstance(command_parts, str):
            try:
                command_parts = json.loads(command_parts)
            except:
                command_parts = []
        
        # Process command
        response = await bot_manager.process_command(
            command, command_parts, user_name, session
        )
        
        if response:
            # Send bot response to chat
            if chat_with:
                msg = Message(
                    sender_name="Bot",
                    receiver_name=user_name,
                    text=response.get('text', '')
                )
                session.add(msg)
                await session.commit()
                
                payload = {
                    "type": "message",
                    "sender": "Bot",
                    "text": response.get('text', ''),
                    "id": msg.id
                }
                await manager.send_personal_message(payload, user_name)
            
            return {"ok": True, "response": response}
        
        return {"ok": False, "error": "Komenda nieznaleziona"}


# ==================== BUILT-IN BOT COMMANDS ====================

async def cmd_help(args, user, session):
    return {"text": "Dostępne komendy: /help, /stats, /weather, /quote, /ping, /admin"}

async def cmd_stats(args, user, session):
    result = await session.execute(select(UserStatistic).where(UserStatistic.user_id == user))
    stats = result.scalars().first()
    if stats:
        return {"text": f"📊 Twoje statystyki:\n📝 Wiadomości: {stats.messages_sent}\n📁 Pliki: {stats.files_sent}\n🎤 Głosowe: {stats.voice_messages_sent}\n📊 Ankiety: {stats.polls_created}"}
    return {"text": "Brak statystyk"}

async def cmd_ping(args, user, session):
    import time
    start = time.time()
    await session.execute(select(1))
    latency = int((time.time() - start) * 1000)
    return {"text": f"🏓 Pong! Latencja: {latency}ms"}

async def cmd_quote(args, user, session):
    import random
    quotes = [
        "💬 \"Jedyny sposób na wykonanie wielkiej pracy to kochać to, co się robi.\" - Steve Jobs",
        "💬 \"Przyszłość należy do tych, którzy wierzą w piękno swoich marzeń.\" - Eleanor Roosevelt",
        "💬 \"Nie czekaj. Czas nigdy nie będzie idealny.\" - Napoleon Hill",
        "💬 \"Sukces to nie klucz do szczęścia. Szczęście to klucz do sukcesu.\""
    ]
    return {"text": random.choice(quotes)}

async def cmd_admin(args, user, session):
    result = await session.execute(select(User).where(User.id == user))
    u = result.scalars().first()
    if u and u.is_admin:
        return {"text": "✅ Masz uprawnienia administratora"}
    return {"text": "❌ Nie masz uprawnień administratora"}

async def cmd_weather(args, user, session):
    if len(args) < 1:
        return {"text": "🌡️ Użycie: /weather <miasto>"}
    city = args[0]
    # Mock weather data (in production, call real API)
    import random
    temp = random.randint(-10, 35)
    conditions = ["☀️ Słonecznie", "⛅ Pochmurno", "🌧️ Deszczowo", "❄️ Śnieg", "⛈️ Burza"]
    return {"text": f"🌡️ Pogoda: {city}\n🌡️ Temperatura: {temp}°C\n{random.choice(conditions)}"}

async def cmd_roll(args, user, session):
    import random
    max_val = int(args[0]) if args and args[0].isdigit() else 6
    return {"text": f"🎲 Rzucasz kostką k{max_val}: {random.randint(1, max_val)}"}

async def cmd_coin(args, user, session):
    import random
    result = "Orzeł" if random.random() < 0.5 else "Reszka"
    return {"text": f"🪵 Rzucasz monetą: {result}"}

# Register built-in commands
bot_manager.register_command("system", "help", cmd_help)
bot_manager.register_command("system", "stats", cmd_stats)
bot_manager.register_command("system", "ping", cmd_ping)
bot_manager.register_command("system", "quote", cmd_quote)
bot_manager.register_command("system", "admin", cmd_admin)
bot_manager.register_command("system", "weather", cmd_weather)
bot_manager.register_command("system", "roll", cmd_roll)
bot_manager.register_command("system", "coin", cmd_coin)


# ==================== BOT WEBHOOK RECEIVER ====================

@app.post('/api/bots/webhook/{bot_name}')
async def bot_webhook_receiver(
    bot_name: str,
    request: Request,
    authorization: str = None
):
    """Receive webhook from external bot service"""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(BotIntegration).where(
                BotIntegration.name == bot_name,
                BotIntegration.enabled == True
            )
        )
        bot = result.scalars().first()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found or disabled")
        
        if authorization != f'Bearer {bot.api_key}':
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        body = await request.json()
        
        # Log bot activity
        log = ActivityLog(
            user_id=None,
            action=f"BOT_{bot_name.upper()}",
            details=str(body),
            ip_address=request.client.host if request.client else None
        )
        session.add(log)
        await session.commit()
        
        # Process bot response
        if 'response' in body:
            return {"ok": True, "processed": True}
        
        return {"ok": True}


# ==================== BOT EVENTS ====================

@app.post('/api/bots/events/subscribe')
async def subscribe_bot_event(
    request: Request,
    bot_id: int = Form(...),
    event: str = Form(...)
):
    """Subscribe bot to an event"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration).where(BotIntegration.id == bot_id))
        bot = result.scalars().first()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        
        import json
        config = json.loads(bot.config) if bot.config else {}
        events = config.get('events', [])
        
        if event not in events:
            events.append(event)
        
        config['events'] = events
        bot.config = json.dumps(config)
        await session.commit()
        
        return {"ok": True, "events": events}

@app.post('/api/bots/events/unsubscribe')
async def unsubscribe_bot_event(
    request: Request,
    bot_id: int = Form(...),
    event: str = Form(...)
):
    """Unsubscribe bot from an event"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration).where(BotIntegration.id == bot_id))
        bot = result.scalars().first()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        
        import json
        config = json.loads(bot.config) if bot.config else {}
        events = config.get('events', [])
        
        if event in events:
            events.remove(event)
        
        config['events'] = events
        bot.config = json.dumps(config)
        await session.commit()
        
        return {"ok": True, "events": events}

@app.get('/api/bots/events')
async def get_bot_events():
    """Get available bot events"""
    return {
        "events": [
            {"name": "message.sent", "description": "Wiadomość wysłana"},
            {"name": "message.received", "description": "Wiadomość otrzymana"},
            {"name": "user.login", "description": "Użytkownik zalogowany"},
            {"name": "user.logout", "description": "Użytkownik wylogowany"},
            {"name": "user.register", "description": "Nowy użytkownik"},
            {"name": "file.upload", "description": "Plik przesłany"},
            {"name": "command.executed", "description": "Komenda wykonana"}
        ]
    }


# ==================== BOT CHAT INTEGRATION ====================

@app.websocket('/ws/bot/{bot_name}')
async def bot_websocket_endpoint(websocket: WebSocket, bot_name: str):
    """WebSocket connection for bots"""
    await websocket.accept()
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(BotIntegration).where(
                BotIntegration.name == bot_name,
                BotIntegration.enabled == True
            )
        )
        bot = result.scalars().first()
        
        if not bot:
            await websocket.close(code=4001, reason="Bot not found or disabled")
            return
        
        # Verify API key
        data = await websocket.receive_json()
        if data.get('api_key') != bot.api_key:
            await websocket.close(code=4002, reason="Invalid API key")
            return
        
        bot_manager.active_bots[bot_name]['websocket'] = websocket
        
        try:
            while True:
                data = await websocket.receive_json()
                
                # Process bot message/action
                action = data.get('action')
                
                if action == 'send_message':
                    to = data.get('to')
                    text = data.get('text')
                    
                    if to and text:
                        msg = Message(
                            sender_name=bot_name,
                            receiver_name=to,
                            text=text
                        )
                        session.add(msg)
                        await session.commit()
                        
                        payload = {
                            "type": "message",
                            "sender": bot_name,
                            "text": text,
                            "id": msg.id
                        }
                        await manager.send_personal_message(payload, to)
                        
                        await websocket.send_json({"ok": True, "message_id": msg.id})
                
                elif action == 'get_user':
                    username = data.get('username')
                    result = await session.execute(
                        select(User).where(User.user_name == username)
                    )
                    u = result.scalars().first()
                    
                    if u:
                        await websocket.send_json({
                            "ok": True,
                            "user": {
                                "id": u.id,
                                "username": u.user_name,
                                "status": u.status
                            }
                        })
                    else:
                        await websocket.send_json({"ok": False, "error": "User not found"})
                
                elif action == 'broadcast':
                    text = data.get('text')
                    # Send to all connected users
                    for username in manager.active_connections.keys():
                        msg = Message(
                            sender_name=bot_name,
                            receiver_name=username,
                            text=text
                        )
                        session.add(msg)
                        payload = {
                            "type": "message",
                            "sender": bot_name,
                            "text": text,
                            "id": msg.id
                        }
                        await manager.send_personal_message(payload, username)
                    await session.commit()
                    await websocket.send_json({"ok": True})
                
        except WebSocketDisconnect:
            if bot_name in bot_manager.active_bots:
                del bot_manager.active_bots[bot_name]['websocket']


# ==================== BOT ANALYTICS ====================

@app.get('/api/bots/{bot_id}/analytics')
async def get_bot_analytics(bot_id: int, request: Request, days: int = 7):
    """Get bot analytics"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        result = await session.execute(select(BotIntegration).where(BotIntegration.id == bot_id))
        bot = result.scalars().first()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Get activity count
        result = await session.execute(
            select(func.count(ActivityLog.id)).where(
                ActivityLog.action.like(f"BOT_{bot.name.upper()}%"),
                ActivityLog.created_at > cutoff
            )
        )
        activity_count = result.scalar()
        
        # Get commands count
        result = await session.execute(
            select(func.count(Message.id)).where(
                Message.sender_name == bot.name,
                Message.created_at > cutoff
            )
        )
        messages_count = result.scalar()
        
        return {
            "bot_name": bot.name,
            "period_days": days,
            "activity_count": activity_count,
            "messages_sent": messages_count,
            "avg_per_day": round(activity_count / days, 2) if days > 0 else 0
        }


# ==================== BOT TEMPLATES ====================

@app.get('/api/bots/templates')
async def get_bot_templates():
    """Get bot templates for quick setup"""
    return {
        "templates": [
            {
                "name": "Welcome Bot",
                "description": "Automatycznie wita nowych użytkowników",
                "events": ["user.register", "user.login"],
                "config": {
                    "welcome_message": "Witaj w naszym czacie! 🎉",
                    "send_rules": True
                }
            },
            {
                "name": "Moderation Bot",
                "description": "Automatyczna moderacja treści",
                "events": ["message.sent"],
                "config": {
                    "auto_delete_profanity": True,
                    "warn_on_violation": True,
                    "max_warnings": 3
                }
            },
            {
                "name": "Notification Bot",
                "description": "Wysyła powiadomienia systemowe",
                "events": [],
                "config": {
                    "broadcast_enabled": True,
                    "scheduled_messages": []
                }
            },
            {
                "name": "Integration Bot",
                "description": "Integracja z zewnętrznymi API",
                "events": ["command.executed"],
                "config": {
                    "external_api_url": "",
                    "api_key": "",
                    "timeout": 30
                }
            }
        ]
    }

@app.post('/api/bots/create-from-template')
async def create_bot_from_template(
    request: Request,
    template_name: str = Form(...),
    bot_name: str = Form(...),
    config: str = Form("{}")
):
    """Create bot from template"""
    import json
    import secrets
    
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401)
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()
        
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        
        templates = {
            "Welcome Bot": {"events": ["user.register", "user.login"]},
            "Moderation Bot": {"events": ["message.sent"]},
            "Notification Bot": {"events": []},
            "Integration Bot": {"events": ["command.executed"]}
        }
        
        if template_name not in templates:
            return {"ok": False, "error": "Template not found"}
        
        api_key = f"bot_{secrets.token_hex(32)}"
        template_config = templates[template_name]
        template_config['events'] = template_config.get('events', [])
        
        bot = BotIntegration(
            name=bot_name,
            api_key=api_key,
            webhook_url=None,
            config=json.dumps(template_config),
            enabled=True
        )
        session.add(bot)
        await session.commit()

        return {
            "ok": True,
            "bot_id": bot.id,
            "api_key": api_key
        }



# ==================== ADVANCED SECURITY ENDPOINTS ====================

@app.get('/security-dashboard')
async def advanced_security_dashboard(request: Request):
    """Advanced security dashboard with all security features"""
    user_name = request.session.get("user_name")
    if not user_name:
        return RedirectResponse(url='/login')

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        # Calculate security score
        security_score = 100
        
        # Check 2FA
        if not user.is_2fa_enabled:
            security_score -= 20
        
        # Check email verification
        email_verified = user.email is not None  # Simplified - would need email_verified field
        if not email_verified:
            security_score -= 15
        
        # Get failed login attempts in last 24h
        from datetime import timedelta
        now = datetime.utcnow()
        result = await session.execute(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.username == user_name,
                LoginAttempt.success == False,
                LoginAttempt.created_at > now - timedelta(hours=24)
            )
        )
        failed_attempts_24h = result.scalar() or 0
        security_score -= min(failed_attempts_24h * 5, 30)  # Max 30 points deduction
        
        # Get successful logins in last 7 days
        result = await session.execute(
            select(func.count(LoginHistory.id)).where(
                LoginHistory.user_id == user.id,
                LoginHistory.success == True,
                LoginHistory.created_at > now - timedelta(days=7)
            )
        )
        successful_logins_7d = result.scalar() or 0
        
        # Get active sessions
        sessions = await SessionTimeoutManager.get_user_sessions(user.id)
        active_sessions = len(sessions)
        
        # Get API keys
        api_keys = await APIKeyManager.list_user_api_keys(user.id)
        api_keys_count = len(api_keys)
        
        # Get security events
        result = await session.execute(
            select(ActivityLog)
            .where(ActivityLog.user_id == user.id)
            .order_by(ActivityLog.created_at.desc())
            .limit(50)
        )
        security_events_list = result.scalars().all()
        
        # Format sessions for display
        session_list = []
        current_session_token = request.session.get('session_token')
        
        for sess in sessions:
            idle_minutes = (datetime.utcnow() - sess.last_activity).total_seconds() / 60
            session_list.append({
                'id': sess.id,
                'device_info': sess.device_info or 'Nieznane urządzenie',
                'ip_address': sess.ip_address or 'Brak danych',
                'created_at': sess.created_at,
                'last_activity': sess.last_activity,
                'expires_at': sess.expires_at,
                'idle_minutes': round(idle_minutes, 1),
                'is_current': sess.session_token == current_session_token
            })
        
        return templates.TemplateResponse('security_dashboard.html', {
            'request': request,
            'current_user': user_name,
            'security_score': max(0, security_score),
            'failed_attempts_24h': failed_attempts_24h,
            'successful_logins_7d': successful_logins_7d,
            'active_sessions': active_sessions,
            'api_keys_count': api_keys_count,
            'two_factor_enabled': user.is_2fa_enabled,
            'email_verified': email_verified,
            'sessions': session_list,
            'security_events': security_events_list,
            'api_keys': api_keys,
            'message': None,
            'success': True
        })


@app.post('/api/security/session/revoke/{session_id}')
async def revoke_session(session_id: int, request: Request):
    """Revoke a specific user session"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        success = await SessionTimeoutManager.revoke_session(
            session_token=str(session_id),
            user_id=user.id
        )

        if success:
            await SessionTimeoutManager.update_session_activity(str(session_id))
            await audit_logger.log_event(
                session=session,
                event_type="SESSION_REVOKED",
                user_id=user.id,
                username=user_name,
                ip_address=request.client.host if request.client else None,
                details=f"Session {session_id} revoked",
                severity="info"
            )
            return {"ok": True}
        else:
            raise HTTPException(status_code=404, detail="Session not found")


@app.post('/api/security/sessions/revoke-all')
async def revoke_all_sessions(request: Request):
    """Revoke all user sessions except current"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        current_session_token = request.session.get('session_token')
        revoked_count = await SessionTimeoutManager.revoke_all_sessions(
            user_id=user.id,
            except_token=current_session_token
        )

        await audit_logger.log_event(
            session=session,
            event_type="SESSION_REVOKED",
            user_id=user.id,
            username=user_name,
            ip_address=request.client.host if request.client else None,
            details=f"Revoked {revoked_count} sessions",
            severity="info"
        )

        return {"ok": True, "revoked_count": revoked_count}


@app.post('/api/security/api-keys/create')
async def create_api_key_endpoint(
    request: Request,
    name: str = Form(...),
    permissions: str = Form('["read"]'),
    expires_in_days: int = Form(None)
):
    """Create new API key for user"""
    import json
    
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        try:
            perms = json.loads(permissions)
        except:
            perms = ["read"]

        raw_key, key_id = await APIKeyManager.create_api_key(
            user_id=user.id,
            username=user_name,
            name=name,
            permissions=perms,
            expires_in_days=expires_in_days
        )

        await audit_logger.log_event(
            session=session,
            event_type="API_KEY_CREATED",
            user_id=user.id,
            username=user_name,
            ip_address=request.client.host if request.client else None,
            details=f"API key created: {name}",
            severity="info"
        )

        return {
            "ok": True,
            "api_key": raw_key,
            "key_id": key_id,
            "warning": "Save this key now - it cannot be retrieved later!"
        }


@app.post('/api/security/api-keys/revoke/{key_id}')
async def revoke_api_key_endpoint(key_id: int, request: Request):
    """Revoke an API key"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        success = await APIKeyManager.revoke_api_key(user.id, key_id)

        if success:
            await audit_logger.log_event(
                session=session,
                event_type="API_KEY_REVOKED",
                user_id=user.id,
                username=user_name,
                ip_address=request.client.host if request.client else None,
                details=f"API key {key_id} revoked",
                severity="info"
            )
            return {"ok": True}
        else:
            raise HTTPException(status_code=404, detail="API key not found")


@app.get('/api/security/events')
async def get_security_events_api(
    request: Request,
    limit: int = 100,
    event_type: str = None,
    severity: str = None
):
    """Get security events for current user"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        events = await audit_logger.get_user_security_log(
            session=session,
            user_id=user.id,
            limit=limit
        )

        return {
            "events": [
                {
                    "id": e.id,
                    "action": e.action,
                    "details": e.details,
                    "ip_address": e.ip_address,
                    "created_at": e.created_at.isoformat()
                }
                for e in events
            ]
        }


@app.get('/api/security/device-fingerprint')
async def get_device_fingerprint(request: Request):
    """Get current device fingerprint"""
    fingerprint = DeviceFingerprintGenerator.generate_fingerprint(request)
    return {
        "fingerprint": fingerprint,
        "user_agent": request.headers.get('user-agent', ''),
        "platform": request.headers.get('sec-ch-ua-platform', ''),
        "ip": request.client.host if request.client else None
    }


@app.post('/api/security/ip/block')
async def block_ip_endpoint(
    request: Request,
    ip_address: str = Form(...),
    reason: str = Form(""),
    duration_hours: int = Form(24),
    permanent: bool = Form(False)
):
    """Block an IP address (admin only)"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")

        ip_blocker.block_ip(
            ip=ip_address,
            reason=reason,
            duration_hours=duration_hours,
            permanent=permanent
        )

        await audit_logger.log_event(
            session=session,
            event_type="IP_BLOCKED",
            user_id=user.id,
            username=user_name,
            ip_address=ip_address,
            details=f"IP blocked: {reason}",
            severity="warning"
        )

        return {"ok": True, "message": f"IP {ip_address} blocked"}


@app.post('/api/security/ip/unblock/{ip_address}')
async def unblock_ip_endpoint(ip_address: str, request: Request):
    """Unblock an IP address (admin only)"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")

        ip_blocker.unblock_ip(ip_address)

        await audit_logger.log_event(
            session=session,
            event_type="IP_UNBLOCKED",
            user_id=user.id,
            username=user_name,
            ip_address=ip_address,
            details="IP unblocked",
            severity="info"
        )

        return {"ok": True, "message": f"IP {ip_address} unblocked"}


@app.get('/api/security/blocked-ips')
async def get_blocked_ips_api(request: Request):
    """Get list of blocked IPs (admin only)"""
    user_name = request.session.get("user_name")
    if not user_name:
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.user_name == user_name))
        user = result.scalars().first()

        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")

        blocked = ip_blocker.get_blocked_ips()
        return {"blocked_ips": blocked}


# ==================== IMPORT WSZYSTKICH FUNKCJI ====================
from features_all import router as features_router
app.include_router(features_router)


if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=8080, reload=True)

