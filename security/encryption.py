"""
Encryption utilities for end-to-end encryption and data protection:
- Message encryption/decryption
- File encryption
- Key management
- Data anonymization
"""
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional, Tuple


# ==================== ENCRYPTION KEY MANAGEMENT ====================

class EncryptionKeyManager:
    """Manage encryption keys securely"""

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet encryption key"""
        return Fernet.generate_key()

    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive encryption key from password using PBKDF2
        Returns: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def store_key_secure(key: bytes, key_file: str = "encryption.key"):
        """Store encryption key securely in file"""
        # In production, use a secure key management service (AWS KMS, Azure Key Vault, etc.)
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # Set restrictive file permissions (Unix-only)
        try:
            os.chmod(key_file, 0o600)  # Read/write only by owner
        except (OSError, NotImplementedError):
            pass  # Windows doesn't support Unix permissions

    @staticmethod
    def load_key(key_file: str = "encryption.key") -> Optional[bytes]:
        """Load encryption key from file"""
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        return None


# ==================== MESSAGE ENCRYPTION ====================

class MessageEncryptor:
    """Encrypt and decrypt messages"""

    def __init__(self, key: Optional[bytes] = None):
        """Initialize with encryption key"""
        if key is None:
            # Try to load from file
            key = EncryptionKeyManager.load_key()
            if key is None:
                # Generate new key
                key = EncryptionKeyManager.generate_key()
                EncryptionKeyManager.store_key_secure(key)
        
        self.fernet = Fernet(key)

    def encrypt_message(self, message: str) -> str:
        """Encrypt a message string"""
        encrypted = self.fernet.encrypt(message.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt an encrypted message"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            # Log error but don't expose details
            print(f"Decryption error: {e}")
            return "[Error: Unable to decrypt message]"

    def encrypt_dict(self, data: dict) -> str:
        """Encrypt a dictionary (useful for complex message data)"""
        import json
        json_str = json.dumps(data, ensure_ascii=False)
        return self.encrypt_message(json_str)

    def decrypt_to_dict(self, encrypted_data: str) -> dict:
        """Decrypt to dictionary"""
        import json
        json_str = self.decrypt_message(encrypted_data)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return {"error": "Invalid encrypted data"}


# ==================== FILE ENCRYPTION ====================

class FileEncryptor:
    """Encrypt and decrypt files"""

    def __init__(self, key: Optional[bytes] = None):
        """Initialize with encryption key"""
        if key is None:
            key = EncryptionKeyManager.load_key()
            if key is None:
                key = EncryptionKeyManager.generate_key()
                EncryptionKeyManager.store_key_secure(key)
        
        self.fernet = Fernet(key)

    def encrypt_file(self, input_path: str, output_path: Optional[str] = None) -> str:
        """
        Encrypt a file
        Returns: path to encrypted file
        """
        if output_path is None:
            output_path = input_path + ".enc"

        with open(input_path, 'rb') as f:
            file_data = f.read()

        encrypted_data = self.fernet.encrypt(file_data)

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return output_path

    def decrypt_file(self, input_path: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file
        Returns: path to decrypted file
        """
        if output_path is None:
            output_path = input_path.replace('.enc', '')
            if output_path == input_path:
                output_path = input_path + ".decrypted"

        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self.fernet.decrypt(encrypted_data)

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return output_path

    def encrypt_file_in_place(self, file_path: str):
        """Encrypt a file and replace original"""
        encrypted_path = self.encrypt_file(file_path)
        os.replace(encrypted_path, file_path)

    def decrypt_file_in_place(self, file_path: str):
        """Decrypt a file and replace original"""
        decrypted_path = self.decrypt_file(file_path)
        os.replace(decrypted_path, file_path)


# ==================== DATA ANONYMIZATION ====================

class DataAnonymizer:
    """Anonymize sensitive data for logging and analytics"""

    @staticmethod
    def anonymize_email(email: str) -> str:
        """Anonymize email address"""
        if not email or '@' not in email:
            return "***@***.***"
        
        parts = email.split('@')
        username = parts[0]
        domain = parts[1]
        
        # Show first and last character of username
        if len(username) > 2:
            anon_username = username[0] + '*' * (len(username) - 2) + username[-1]
        else:
            anon_username = '*' * len(username)
        
        # Show domain with partial masking
        if '.' in domain:
            domain_parts = domain.split('.')
            anon_domain = domain_parts[0][:2] + '**'
            if len(domain_parts) > 1:
                anon_domain += '.' + domain_parts[-1]
        else:
            anon_domain = '***'
        
        return f"{anon_username}@{anon_domain}"

    @staticmethod
    def anonymize_ip(ip: str) -> str:
        """Anonymize IP address (keep first 2 octets)"""
        if not ip:
            return "***.***.***.***"
        
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.**"
        return "***.***.***.***"

    @staticmethod
    def anonymize_phone(phone: str) -> str:
        """Anonymize phone number"""
        if not phone:
            return "***-***-***"
        
        # Keep last 4 digits
        digits = ''.join(c for c in phone if c.isdigit())
        if len(digits) >= 4:
            return '*' * (len(digits) - 4) + digits[-4:]
        return '*' * len(digits)

    @staticmethod
    def anonymize_name(name: str) -> str:
        """Anonymize full name"""
        if not name:
            return "***"
        
        parts = name.strip().split()
        if len(parts) >= 2:
            # First name initial + last name
            return f"{parts[0][0]}. {parts[-1]}"
        elif len(parts) == 1 and len(parts[0]) > 2:
            return parts[0][0] + '*' * (len(parts[0]) - 2) + parts[0][-1]
        return "***"

    @staticmethod
    def mask_string(s: str, show_first: int = 2, show_last: int = 2) -> str:
        """Generic string masking"""
        if not s:
            return "***"
        
        if len(s) <= show_first + show_last:
            return '*' * len(s)
        
        return s[:show_first] + '*' * (len(s) - show_first - show_last) + s[-show_last:]

    @staticmethod
    def hash_data(data: str, salt: str = "") -> str:
        """Create one-way hash of data"""
        salted_data = salt + data + salt
        return hashlib.sha256(salted_data.encode()).hexdigest()


# ==================== INITIALIZATION ====================

def initialize_encryption():
    """Initialize encryption system and ensure key exists"""
    key = EncryptionKeyManager.load_key()
    if key is None:
        key = EncryptionKeyManager.generate_key()
        EncryptionKeyManager.store_key_secure(key)
        print("[Security] New encryption key generated")
    return key


# Global encryptor instances
_message_encryptor = None
_file_encryptor = None

def get_message_encryptor() -> MessageEncryptor:
    """Get or create message encryptor"""
    global _message_encryptor
    if _message_encryptor is None:
        initialize_encryption()
        _message_encryptor = MessageEncryptor()
    return _message_encryptor

def get_file_encryptor() -> FileEncryptor:
    """Get or create file encryptor"""
    global _file_encryptor
    if _file_encryptor is None:
        initialize_encryption()
        _file_encryptor = FileEncryptor()
    return _file_encryptor
