from passlib.context import CryptContext
from datetime import timedelta, datetime
from src.config import Config
from uuid import uuid4
import logging
import jwt
from itsdangerous import URLSafeTimedSerializer
from fastapi import HTTPException, status
from jwt import ExpiredSignatureError, InvalidTokenError

password_context = CryptContext(schemes=['bcrypt'])
ACCESS_TOKEN_EXPIRY = timedelta(minutes=10)  # safer than seconds


def generate_password_hash(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hash: str) -> bool:
    return password_context.verify(password, hash)


def create_access_tokens(user_data: dict, expiry: timedelta = None, refresh: bool = False):
    if expiry is None:
        expiry = ACCESS_TOKEN_EXPIRY

    payload = {
        "user": user_data,
        "exp": int((datetime.utcnow() + expiry).timestamp()),
        "jti": str(uuid4()),
        "refresh": refresh
    }

    token = jwt.encode(
        payload=payload,
        key=Config.JWT_SECRET,
        algorithm=Config.JWT_ALGORITHM
    )
    return token


#def decode_token(token: str) -> dict:
    try:
        token_data = jwt.decode(
            jwt=token,
            key=Config.JWT_SECRET,
            algorithms=[Config.JWT_ALGORITHM]
        )
        return token_data
    except ExpiredSignatureError:
        logging.exception("JWT signature has expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please login again."
        )
    except InvalidTokenError:
        logging.exception("JWT is invalid.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token."
        )

def decode_token(token: str, ignore_exp: bool = False) -> dict:
    try:
        options = {"verify_exp": not ignore_exp}
        token_data = jwt.decode(
            jwt=token,
            key=Config.JWT_SECRET,
            algorithms=[Config.JWT_ALGORITHM],
            options=options
        )
        return token_data
    except ExpiredSignatureError:
        logging.exception("JWT signature has expired.")
        if ignore_exp:
            return jwt.decode(
                jwt=token,
                key=Config.JWT_SECRET,
                algorithms=[Config.JWT_ALGORITHM],
                options={"verify_exp": False}
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please login again."
        )
    except InvalidTokenError:
        logging.exception("JWT is invalid.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token."
        )
    
    
serializer = URLSafeTimedSerializer(
        secret_key = Config.JWT_SECRET,
        salt='email-configuration'
    )
    
def create_url_safe_token(data: dict):
    token = serializer.dumps(data)
    return token


def decode_url_safe_token(token: str):
    try:
        token_data = serializer.loads(token)

        return token_data
    
    except Exception as e:
        logging.error(str(e))
