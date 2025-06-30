from fastapi import APIRouter, Depends, status
from src.auth.schemas import UserCreateModel, UserModel, UserLoginModel
from src.auth.service import UserService
from src.db.main import get_session
from sqlalchemy.ext.asyncio import AsyncSession
from .utils import verify_password, create_access_tokens
from fastapi.responses import JSONResponse
from .dependencies import RefreshTokenBearer
from datetime import timedelta, datetime
from src.auth.dependencies import AccessTokenBearer
from src.db.redis import add_jti_to_blocklist



auth_router = APIRouter()

@auth_router.get('/signup')
async def signup():
    return 'signUp'


user_service = UserService()


REFRESH_TOKEN_EXPIRY=5

@auth_router.post("/register", response_model=UserModel, status_code=status.HTTP_201_CREATED)
async def signup(user_data: UserCreateModel, session: AsyncSession = Depends(get_session)):
    user = await user_service.create_user(user_data, session)
    return user


@auth_router.post('/login')
async def login_users(login_data: UserLoginModel, session: AsyncSession=Depends(get_session)):
    email = login_data.email    
    password = login_data.password

    user = await user_service.get_user_by_email(email, session)

    if user is not None:
        password_valid = verify_password(password, user.password)

        if password_valid:
            access_token = create_access_tokens(
                user_data={
                    'email': user.email,
                    'uid':str(user.uid)
                }
            )

            refresh_token = create_access_tokens(
                user_data={
                    'email': user.email,
                    'uid':str(user.uid)
                },
                refresh=True,
                expiry= timedelta(days=REFRESH_TOKEN_EXPIRY)
            )
            return JSONResponse(
                content={
                    "message":"Login Successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user":{
                        "email":user.email,
                        "uid": str(user.uid)
                    }
                }
            )
        

@auth_router.get('/refresh_token')
async def get_new_access_token(token_details: dict=Depends(RefreshTokenBearer())):
    expiry_timestamp = token_details['exp']

    if datetime.fromtimestamp(expiry_timestamp)>datetime.now():
        new_access_token = create_access_tokens(
            user_data=token_details['user']
        )
        return JSONResponse(content={
            "access_token":new_access_token
        })


@auth_router.get('/logout')
async def revoke_token(token_details: dict=Depends(AccessTokenBearer())):

    jti=token_details['jti']
    await add_jti_to_blocklist(jti)
    return JSONResponse(
        content={
            "message":"Logged Out Successfully"
        },
        status_code=status.HTTP_200_OK
    )

@auth_router.get("/protected")
async def protected_route(token_details: dict = Depends(AccessTokenBearer())):
    return {
        "message": "This is a protected route",
        "user": token_details["user"]
    }
