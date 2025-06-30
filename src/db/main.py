from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine,AsyncSession
from sqlalchemy.orm import sessionmaker
from src.auth.models import Base 
from src.config import Config


#create engine

engine: AsyncEngine = create_async_engine(
    url=Config.DATABASE_URL,
    echo=True
)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_session()-> AsyncSession:
    async_session = sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    async with async_session() as session:
        yield session 