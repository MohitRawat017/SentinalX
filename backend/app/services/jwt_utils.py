"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX JWT Token Utilities                             ║
║                     JSON Web Token Creation and Verification                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Handle JWT token creation, verification, and payload extraction      ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ JWT (JSON Web Token) OVERVIEW:                                                ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ A JWT is a compact, URL-safe token format with three parts:                  ║
║                                                                               ║
║   HEADER.PAYLOAD.SIGNATURE                                                    ║
║                                                                               ║
║ 1. HEADER: Algorithm and token type                                          ║
║    {"alg": "HS256", "typ": "JWT"}                                            ║
║                                                                               ║
║ 2. PAYLOAD: Claims (user data)                                               ║
║    {"sub": "0x123...", "exp": 1234567890, "iat": 1234560000}                ║
║                                                                               ║
║ 3. SIGNATURE: Cryptographic signature                                        ║
║    HMACSHA256(base64(header) + "." + base64(payload), secret)                ║
║                                                                               ║
║ WHY JWT?                                                                      ║
║ - Stateless: Server doesn't need to store sessions                          ║
║ - Self-contained: Token contains all needed info                            ║
║ - Portable: Works across microservices                                       ║
║ - Standard: Widely supported across platforms                                ║
║                                                                               ║
║ SECURITY CONSIDERATIONS:                                                      ║
║ - Tokens are ENCODED, not ENCRYPTED                                          ║
║ - Anyone with the token can read the payload                                 ║
║ - But only server with SECRET_KEY can CREATE valid tokens                   ║
║ - Never put sensitive data (passwords) in the payload!                       ║
║                                                                               ║
║ INTERVIEW QUESTION: What's the difference between JWT and session cookies?  ║
║ ANSWER:                                                                      ║
║ JWT:                                                                        ║
║ - Stateless (server doesn't store session)                                  ║
║ - Can be validated without database lookup                                  ║
║ - Good for microservices                                                    ║
║ - Harder to revoke before expiration                                        ║
║ Session Cookies:                                                             ║
║ - Stateful (server stores session in DB/memory)                             ║
║ - Easy to revoke (delete from server)                                       ║
║ - Requires session lookup on every request                                  ║
║ - Better for single-server apps                                             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt

from app.config import settings


# ───────────────────────────────────────────────────────────────────────────────
# TOKEN CREATION
# ───────────────────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ CREATE A JWT ACCESS TOKEN                                                 ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ @param data: Dict containing claims to encode (typically {"sub": wallet}) ║
    ║ @param expires_delta: Optional custom expiration time                     ║
    ║ @returns: Encoded JWT string                                              ║
    ║                                                                           ║
    ║ STANDARD CLAIMS (registered):                                              ║
    ║ - sub: Subject (user identifier - wallet address)                        ║
    ║ - exp: Expiration time (when token becomes invalid)                      ║
    ║ - iat: Issued at time (when token was created)                           ║
    ║ - nbf: Not valid before (optional)                                        ║
    ║ - iss: Issuer (optional - identifies the server)                         ║
    ║ - aud: Audience (optional - who the token is for)                        ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why include iat (issued at)?                          ║
    ║ ANSWER: iat allows:                                                       ║
    ║ - Determining token age                                                   ║
    ║ - Implementing "max session age" policies                                 ║
    ║ - Detecting reused/stale tokens                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # Copy the data to avoid modifying the original dict
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # Use default expiration from settings (60 minutes)
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add standard claims
    to_encode.update({
        "exp": expire,  # Expiration time
        "iat": datetime.utcnow(),  # Issued at
    })
    
    # Encode the token using HS256 algorithm
    # The secret key is used to sign the token
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


# ───────────────────────────────────────────────────────────────────────────────
# TOKEN VERIFICATION
# ───────────────────────────────────────────────────────────────────────────────

def verify_token(token: str) -> Optional[dict]:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ VERIFY AND DECODE A JWT TOKEN                                             ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ @param token: JWT string to verify                                        ║
    ║ @returns: Decoded payload dict if valid, None if invalid                  ║
    ║                                                                           ║
    ║ VERIFICATION STEPS:                                                        ║
    ║ 1. Decode the token (extract header, payload, signature)                  ║
    ║ 2. Verify signature using SECRET_KEY                                      ║
    ║ 3. Check expiration (exp claim)                                           ║
    ║ 4. Return payload if all checks pass                                      ║
    ║                                                                           ║
    ║ WHAT CAN FAIL:                                                              ║
    ║ - ExpiredSignatureError: Token has expired                               ║
    ║ - JWTError: Invalid signature, malformed token, etc.                     ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: What happens if SECRET_KEY is leaked?                 ║
    ║ ANSWER: Attacker can:                                                     ║
    ║ - Forge tokens for any user                                              ║
    ║ - Bypass all authentication                                               ║
    ║ - Access any account                                                      ║
    ║ Solution: Rotate keys immediately, invalidate all existing tokens         ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    try:
        # Decode and verify the token
        # This checks:
        # 1. Signature validity (using SECRET_KEY)
        # 2. Token hasn't expired (exp claim)
        # 3. Token is well-formed
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError:
        # Token is invalid (bad signature, expired, malformed, etc.)
        return None


# ───────────────────────────────────────────────────────────────────────────────
# WALLET EXTRACTION
# ───────────────────────────────────────────────────────────────────────────────

def get_wallet_from_token(token: str) -> Optional[str]:
    """
    Extract the wallet address from a JWT token.
    
    The wallet address is stored in the "sub" (subject) claim.
    This is a convenience function for the common case of extracting
    the authenticated user's wallet address.
    
    @param token: JWT string
    @returns: Wallet address if valid, None if invalid
    """
    payload = verify_token(token)
    if payload:
        return payload.get("sub")  # "sub" = subject = wallet address
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR jwt_utils.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why use HS256 instead of RS256?
A1: HS256 (HMAC):
    - Simpler: One secret key
    - Faster: Less computational overhead
    - Good for monolithic apps where one service creates and verifies tokens
    
    RS256 (RSA):
    - Uses public/private key pair
    - Allows public key distribution for verification
    - Private key stays secure on auth server
    - Better for microservices where multiple services verify tokens

Q2: How do you handle token revocation?
A2: JWT tokens are hard to revoke because they're stateless. Options:
    1. Short expiration times (e.g., 15 minutes)
    2. Refresh tokens with revocation list
    3. Token versioning (increment version in DB, check on each request)
    4. Redis blacklist of revoked tokens
    
    For this project, we use short expiration + re-authentication for sensitive actions.

Q3: Where should you store JWT tokens on the frontend?
A3: Options with trade-offs:
    
    localStorage:
    - Pros: Easy to access, persists across page reloads
    - Cons: Vulnerable to XSS attacks (any JS can read it)
    
    httpOnly cookies:
    - Pros: Not accessible to JavaScript (XSS safe)
    - Cons: Vulnerable to CSRF attacks
    - Best practice: Use with SameSite attribute
    
    Memory (React state):
    - Pros: Not persisted, most secure
    - Cons: Lost on page refresh, need to re-authenticate

Q4: What happens if a user's token is stolen?
A4: Attacker can impersonate the user until:
    - Token expires
    - User changes password (if versioning implemented)
    - Token is blacklisted (if implemented)
    
    Mitigation:
    - Short token lifetimes
    - Secure storage (httpOnly cookies)
    - HTTPS only
    - Token rotation on sensitive actions

Q5: Why use "sub" for the wallet address?
A5: "sub" (subject) is a registered JWT claim defined in RFC 7519.
    It's the standard field for user identifier.
    Using standard claims:
    - Makes tokens interoperable
    - Follows best practices
    - JWT libraries can validate automatically
"""