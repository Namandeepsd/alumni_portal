from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta

from src.auth.schemas import (
    UserCreateModel,
    UserLoginModel,
    PasswordResetRequestModel,
    PasswordResetConfirmModel
)
from src.auth.service import UserService
from src.db.main import get_session
from .utils import (
    verify_password,
    create_access_tokens,
    create_url_safe_token,
    decode_url_safe_token,
    generate_password_hash
)
from .dependencies import RefreshTokenBearer, AccessTokenBearer
from src.db.redis import add_jti_to_blocklist
from src.config import Config
from src.mail import mail, create_message

auth_router = APIRouter()
user_service = UserService()

REFRESH_TOKEN_EXPIRY_DAYS = 5


@auth_router.get('/signup')
async def signup_ready():
    return {"message": "Signup endpoint ready."}


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreateModel,
    session: AsyncSession = Depends(get_session)
):
    new_user = await user_service.create_user(user_data, session)
    if not new_user:
        raise HTTPException(status_code=500, detail="Could not create user.")

    token = create_url_safe_token({"email": user_data.email})
    link = f"http://{Config.DOMAIN}/alumniDB/v1/user/auth/verify/{token}"
    html_message = f"""
    <h1>Verify Your Email</h1>
    <p>Please click this <a href="{link}">link</a> to verify your email.</p>
    """

    await mail.send_message(create_message(
        recipients=[user_data.email],
        subject="Verify your email",
        body=html_message
    ))

    return {
        "message": "Account created! Check your email to verify your account.",
        "user": {
            "email": new_user.email,
            "uid": str(new_user.uid)
        }
    }


@auth_router.get('/verify/{token}')
async def verify_user_account(
    token: str,
    session: AsyncSession = Depends(get_session)
):
    try:
        token_data = decode_url_safe_token(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    user_email = token_data.get('email')
    if not user_email:
        raise HTTPException(status_code=400, detail="Token missing email data.")

    user = await user_service.get_user_by_email(user_email, session)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    await user_service.update_user(user, {'is_verified': True}, session)
    return {"message": "Account verified successfully."}


@auth_router.post('/login')
async def login_user(
    login_data: UserLoginModel,
    session: AsyncSession = Depends(get_session)
):
    user = await user_service.get_user_by_email(login_data.email, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with this email does not exist."
        )

    if not verify_password(login_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password."
        )

    access_token = create_access_tokens(
        user_data={"email": user.email, "uid": str(user.uid)}
    )
    refresh_token = create_access_tokens(
        user_data={"email": user.email, "uid": str(user.uid)},
        refresh=True,
        expiry=timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
    )

    return {
        "message": "Login successful.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"email": user.email, "uid": str(user.uid)}
    }


@auth_router.get('/refresh_token')
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    new_access_token = create_access_tokens(user_data=token_details['user'])
    return {"access_token": new_access_token}


@auth_router.get('/logout')
async def logout_user(token_details: dict = Depends(AccessTokenBearer())):
    await add_jti_to_blocklist(token_details['jti'])
    return {"message": "Logged out successfully."}


@auth_router.get('/protected')
async def protected_route(token_details: dict = Depends(AccessTokenBearer())):
    return {
        "message": "This is a protected route.",
        "user": token_details["user"]
    }


@auth_router.post('/password-reset-request')
async def request_password_reset(email_data: PasswordResetRequestModel):
    token = create_url_safe_token({"email": email_data.email})
    link = f"http://{Config.DOMAIN}/alumniDB/v1/user/auth/password-reset-verify/{token}"

    html_message = f"""
    <h1>Reset Your Password</h1>
    <p>Please click this <a href="{link}">link</a> to reset your password.</p>
    """

    await mail.send_message(create_message(
        recipients=[email_data.email],
        subject="Reset your password",
        body=html_message
    ))

    return {"message": "Please check your email for instructions to reset your password."}


@auth_router.get('/password-reset-verify/{token}')
async def verify_password_reset_token(token: str):
    try:
        token_data = decode_url_safe_token(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    user_email = token_data.get('email')
    if not user_email:
        raise HTTPException(status_code=400, detail="Invalid token data.")

    return {
        "message": "Token is valid. Now POST to reset your password.",
        "reset_url": f"/alumniDB/v1/user/auth/password-reset-confirm/{token}"
    }


@auth_router.post('/password-reset-confirm/{token}')
async def reset_password(
    token: str,
    passwords: PasswordResetConfirmModel,
    session: AsyncSession = Depends(get_session)
):
    if passwords.new_password != passwords.confirm_new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match."
        )

    try:
        token_data = decode_url_safe_token(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    user_email = token_data.get('email')
    if not user_email:
        raise HTTPException(status_code=400, detail="Invalid token data.")

    user = await user_service.get_user_by_email(user_email, session)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    passwd_hash = generate_password_hash(passwords.new_password)
    await user_service.update_user(user, {'password': passwd_hash}, session)

    return {"message": "Password reset successfully."}
