from sqlalchemy.ext.asyncio import AsyncSession
from src.auth.models import User
from src.auth.schemas import UserCreateModel
from sqlalchemy import select
from .utils import generate_password_hash

class UserService:
    async def create_user(self, user_data: UserCreateModel, session: AsyncSession):
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
    
    async def get_user_by_email(self, email:str,session:AsyncSession):
        statement = select(User).where(User.email == email)
        result = await session.execute(statement)
        user = result.scalars().first()
        return user
    
    async def user_exists(self,email,session:AsyncSession)-> bool:
        user = await self.get_user_by_email(email,session)
        return True if user is not None else False
