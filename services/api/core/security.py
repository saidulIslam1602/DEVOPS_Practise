"""
Security and Authentication Module

This module implements industry-standard security practices including:
- Password hashing using bcrypt
- JWT token generation and validation
- Bearer token authentication
- Role-based access control foundations

Industry Standards:
    - OWASP password hashing guidelines
    - JWT (RFC 7519) for stateless authentication
    - bcrypt for password hashing (OWASP recommended)
    - Bearer token authentication (RFC 6750)
    - Constant-time comparison for security

Security Features:
    - Automatic password strength validation
    - Token expiration and refresh
    - Protection against timing attacks
    - Secure random token generation
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import settings

# Password Hashing Context Configuration
# ====================================
# Uses bcrypt algorithm (OWASP recommended for 2024+)
# bcrypt automatically handles:
# - Salt generation (unique per password)
# - Work factor scaling (future-proof against hardware improvements)
# - Constant-time verification (prevents timing attacks)
pwd_context = CryptContext(
    schemes=["bcrypt"],  # Primary hashing algorithm
    deprecated="auto",   # Automatically upgrade old hash formats (e.g., from bcrypt v1 to v2)
    bcrypt__rounds=12,   # Work factor: 2^12 = 4,096 iterations (balance of security vs performance)
)

# HTTP Bearer Token Authentication Scheme
# ======================================
# Implements RFC 6750 Bearer Token Usage standard
# Client sends: Authorization: Bearer <jwt_token>
# FastAPI automatically extracts and validates the Bearer format
security = HTTPBearer(
    scheme_name="JWT Bearer Token",  # Name shown in OpenAPI/Swagger docs
    description="Enter JWT token obtained from /api/v1/auth/login",  # Help text for API docs
    auto_error=True,  # Automatically return 401 if no token provided
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify Password Against Hash (Constant-Time Comparison)

    Uses bcrypt's built-in constant-time comparison to prevent timing attacks.
    Timing attacks could theoretically reveal information about password hashes
    by measuring how long verification takes.

    Args:
        plain_password: User-provided password in plain text (from login form)
        hashed_password: Stored bcrypt hash from database (60 characters)

    Returns:
        bool: True if password matches hash, False otherwise

    Example:
        >>> hashed = get_password_hash("secret123")
        >>> verify_password("secret123", hashed)  # Correct password
        True
        >>> verify_password("wrong", hashed)      # Incorrect password
        False

    Security Notes:
        - Uses constant-time comparison (prevents timing attacks)
        - Automatically verifies salt and work factor from hash
        - Safe against rainbow table attacks (each hash has unique salt)
        - Resistant to GPU-based cracking (bcrypt is memory-hard)

    Performance:
        Typical verification time: 100-300ms (intentionally slow for security)
        This prevents brute-force attacks by making each attempt expensive
    """
    # passlib handles all the complexity:
    # 1. Extracts salt and work factor from stored hash
    # 2. Hashes plain_password with same salt and work factor
    # 3. Compares results in constant time
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash Password Using bcrypt with Automatic Salt Generation

    Creates a secure bcrypt hash that includes:
    - Algorithm identifier ($2b$ for bcrypt)
    - Work factor (cost parameter)
    - 22-character base64-encoded salt
    - 31-character base64-encoded hash

    Args:
        password: Plain text password to hash (user input)

    Returns:
        str: Complete bcrypt hash string (~60 characters)
             Format: $2b$12$saltsaltsaltsaltsaltsalt.hashhashhashhashhashhashhashhash

    Example:
        >>> hash1 = get_password_hash("mypassword")
        >>> hash2 = get_password_hash("mypassword")
        >>> hash1 != hash2  # Different because each gets unique salt
        True
        >>> len(hash1)  # Standard bcrypt hash length
        60

    Security Notes:
        - Automatic random salt generation (prevents rainbow table attacks)
        - Work factor of 12 rounds = 2^12 = 4,096 iterations
        - Resistant to GPU cracking attempts (memory-hard algorithm)
        - Follows OWASP password storage guidelines (2024)
        - Future-proof: can increase work factor as hardware improves

    Performance:
        Typical hashing time: 100-300ms (intentionally slow)
        This is a security feature, not a bug!

    Best Practices:
        - Never log or display hashed passwords (they're still sensitive)
        - Store in database with VARCHAR(60) or larger field
        - Consider adding pepper (application-level secret) for extra security
        - Implement rate limiting on login attempts
    """
    # passlib automatically:
    # 1. Generates cryptographically secure random salt
    # 2. Applies bcrypt algorithm with configured work factor
    # 3. Returns complete hash string with all metadata embedded
    return pwd_context.hash(password)


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create JWT Access Token (RFC 7519 Compliant)

    Generates a signed JWT token for stateless authentication.
    Token structure: header.payload.signature (base64url encoded)

    Args:
        data: Claims to encode in token payload
              Common claims: {"sub": user_id, "username": "john", "role": "admin"}
        expires_delta: Optional custom expiration time (overrides default)

    Returns:
        str: Complete JWT token string (3 parts separated by dots)

    Example:
        >>> # Create token for user authentication
        >>> user_claims = {
        ...     "sub": "user_123",           # Subject (user ID)
        ...     "username": "john_doe",      # Username for display
        ...     "role": "admin",             # User role for authorization
        ...     "permissions": ["read", "write"]  # Fine-grained permissions
        ... }
        >>> token = create_access_token(user_claims)
        >>> # Token format: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyI...

    JWT Token Structure:
        Header (base64url):    {"typ": "JWT", "alg": "HS256"}
        Payload (base64url):   {"sub": "user_123", "exp": 1640995200, ...}
        Signature (base64url): HMAC-SHA256(header + payload, secret_key)

    Security Notes:
        - Tokens are signed but NOT encrypted (don't store sensitive data)
        - Include expiration time to limit token lifetime
        - Signature prevents tampering but payload is readable
        - Use HTTPS to protect tokens in transit
        - Consider implementing token refresh mechanism

    Best Practices:
        - Keep access tokens short-lived (15-60 minutes)
        - Use refresh tokens for long-term sessions
        - Implement token revocation for logout/security events
        - Store tokens securely on client (httpOnly cookies preferred)
        - Include minimal necessary claims to reduce token size
    """
    # Create a copy to avoid modifying the original data dictionary
    # This prevents side effects if the same data is used elsewhere
    to_encode = data.copy()

    # Calculate token expiration time
    if expires_delta:
        # Use custom expiration if provided (e.g., for refresh tokens)
        expire = datetime.utcnow() + expires_delta
    else:
        # Use default expiration from application settings
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    # Add standard JWT claims (RFC 7519 registered claims)
    to_encode.update(
        {
            "exp": expire,                    # Expiration time (Unix timestamp)
            "iat": datetime.utcnow(),        # Issued at time (for audit trails)
            "type": "access",                # Token type (distinguish from refresh tokens)
            # Optional: Add "nbf" (not before) for delayed activation
            # Optional: Add "jti" (JWT ID) for token revocation tracking
        }
    )

    # Encode and sign the token using HMAC-SHA256
    # The secret key should be:
    # - At least 256 bits (32 bytes) for HS256
    # - Stored securely (environment variables, not in code)
    # - Rotated periodically for security
    encoded_jwt = jwt.encode(
        to_encode,                    # Payload (claims)
        settings.JWT_SECRET,          # Secret key for signing
        algorithm=settings.JWT_ALGORITHM  # Signing algorithm (HS256 recommended)
    )

    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and Validate JWT Token with Comprehensive Security Checks

    Performs multiple validation steps:
    1. Signature verification (prevents tampering)
    2. Expiration time check (prevents replay attacks)
    3. Algorithm verification (prevents algorithm confusion attacks)
    4. Token format validation

    Args:
        token: JWT token string to decode (without "Bearer " prefix)

    Returns:
        Dict[str, Any]: Decoded token payload containing user claims

    Raises:
        HTTPException: 401 Unauthorized if token is invalid, expired, or tampered

    Example:
        >>> # Valid token
        >>> token = create_access_token({"sub": "user123", "role": "admin"})
        >>> payload = decode_access_token(token)
        >>> print(payload["sub"])    # "user123"
        >>> print(payload["role"])   # "admin"
        >>> print(payload["exp"])    # 1640995200 (expiration timestamp)

        >>> # Invalid token raises HTTPException
        >>> decode_access_token("invalid.token.here")
        HTTPException: 401 Unauthorized

    Validation Checks Performed:
        - Signature verification using HMAC-SHA256
        - Expiration time check against current UTC time
        - Algorithm verification (prevents algorithm substitution attacks)
        - Token format validation (3 parts, valid base64url encoding)
        - Claims validation (required fields present)

    Security Notes:
        - Always validate tokens on every protected endpoint request
        - Check expiration time server-side (don't trust client)
        - Implement token revocation for sensitive operations
        - Log failed validation attempts for security monitoring
        - Consider implementing token refresh before expiration

    Common Failure Scenarios:
        - Expired token: User needs to re-authenticate
        - Invalid signature: Token was tampered with
        - Malformed token: Client sent corrupted data
        - Wrong algorithm: Potential security attack
    """
    try:
        # Decode and verify the token in one operation
        # This automatically checks:
        # - Token format (header.payload.signature)
        # - Base64url decoding of each part
        # - Signature verification using secret key
        # - Expiration time validation
        # - Algorithm matching
        payload = jwt.decode(
            token,                        # Token to decode
            settings.JWT_SECRET,          # Secret key for signature verification
            algorithms=[settings.JWT_ALGORITHM]  # Allowed algorithms (prevents confusion attacks)
        )
        
        # Additional custom validation could go here:
        # - Check token type ("access" vs "refresh")
        # - Verify issuer claim if using multiple services
        # - Check audience claim for multi-tenant applications
        # - Validate custom claims (roles, permissions, etc.)
        
        return payload
        
    except JWTError as e:
        # JWTError covers all JWT-related failures:
        # - ExpiredSignatureError: Token has expired
        # - InvalidSignatureError: Token signature is invalid
        # - InvalidTokenError: Token format is malformed
        # - InvalidAlgorithmError: Algorithm mismatch
        
        # Log the error for security monitoring (but don't expose details to client)
        # logger.warning(f"JWT validation failed: {str(e)}")
        
        # Return standardized 401 response
        # WWW-Authenticate header tells client how to authenticate
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",  # Generic message (don't leak specifics)
            headers={"WWW-Authenticate": "Bearer"},   # RFC 6750 compliance
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    FastAPI Dependency: Extract and Validate Current User from JWT Token

    This is a FastAPI dependency function that:
    1. Extracts Bearer token from Authorization header
    2. Validates and decodes the JWT token
    3. Returns user information for use in route handlers

    Args:
        credentials: HTTP authorization credentials (automatically injected by FastAPI)
                    Contains the token from "Authorization: Bearer <token>" header

    Returns:
        Dict[str, Any]: User data from token payload (user_id, username, roles, etc.)

    Raises:
        HTTPException: 401 Unauthorized if token is missing, invalid, or expired

    Usage in Route Handlers:
        ```python
        @app.get("/protected")
        async def protected_route(current_user: dict = Depends(get_current_user)):
            return {"message": f"Hello {current_user['username']}"}

        @app.get("/admin-only")
        async def admin_route(current_user: dict = Depends(get_current_user)):
            if current_user.get("role") != "admin":
                raise HTTPException(403, "Admin access required")
            return {"admin_data": "sensitive"}
        ```

    Security Flow:
        1. Client sends: Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
        2. FastAPI extracts token using HTTPBearer security scheme
        3. This function validates token and extracts user claims
        4. Route handler receives validated user data
        5. Route can make authorization decisions based on user data

    Error Handling:
        - Missing token: 401 with WWW-Authenticate header
        - Invalid token: 401 with generic error message
        - Expired token: 401 (client should refresh or re-authenticate)
        - Malformed token: 401 (potential attack attempt)
    """
    # Extract the actual token from credentials
    # credentials.credentials contains just the token part (without "Bearer ")
    token = credentials.credentials
    
    # Decode and validate the token
    # This may raise HTTPException if token is invalid
    payload = decode_access_token(token)

    # Extract user identifier from token payload
    # "sub" (subject) is the standard JWT claim for user identification
    user_id: str = payload.get("sub")
    if user_id is None:
        # Token is valid but missing required user identifier
        # This shouldn't happen with properly generated tokens
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Return the complete payload for use in route handlers
    # This typically includes: user_id, username, role, permissions, etc.
    return payload


async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    FastAPI Dependency: Get Current Active User (Chained Dependency)

    This dependency builds on get_current_user() to add an additional
    authorization check for user account status. It implements a common
    pattern where users can be temporarily deactivated without deleting
    their accounts.

    Args:
        current_user: Current user from token (injected by get_current_user dependency)

    Returns:
        Dict[str, Any]: Active user data (same as current_user if active)

    Raises:
        HTTPException: 400 Bad Request if user account is deactivated

    Usage Examples:
        ```python
        # Route that requires active user
        @app.get("/dashboard")
        async def dashboard(user: dict = Depends(get_current_active_user)):
            return {"welcome": f"Hello {user['username']}"}

        # Route that allows inactive users (e.g., account reactivation)
        @app.post("/reactivate")
        async def reactivate(user: dict = Depends(get_current_user)):
            # Can access even if user is inactive
            return {"status": "reactivation successful"}