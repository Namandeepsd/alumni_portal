from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from src.auth.models import User
from src.auth.schemas import UserCreateModel
from .utils import generate_password_hash


class UserService:
    async def create_user(self, user_data: UserCreateModel, session: AsyncSession) -> User:
        """
        Creates a new user in the database after hashing the password.
        Raises HTTPException if user already exists.
        """
        if await self.user_exists(user_data.email, session):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this email already exists."
            )

        user = User(
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            email=user_data.email,
            password=generate_password_hash(user_data.password)
        )

        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    async def get_user_by_email(self, email: str, session: AsyncSession) -> User | None:
        """
        Fetches a user by email. Returns None if not found.
        """
        statement = select(User).where(User.email == email)
        result = await session.execute(statement)
        return result.scalars().first()

    async def user_exists(self, email: str, session: AsyncSession) -> bool:
        """
        Returns True if a user with given email exists, else False.
        """
        return await self.get_user_by_email(email, session) is not None

    async def update_user(self, user:User, user_data: dict, session: AsyncSession):
        for k,v  in user_data.items():
            setattr(user,k,v)
        await session.commit()
        return user