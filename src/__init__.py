from fastapi import FastAPI
from src.auth.routes import auth_router
from contextlib import asynccontextmanager
from src.db.main import init_db

@asynccontextmanager
async def life_span(app: FastAPI):
    print('Server is starting')
    await init_db
    yield
    print('Server is stopped')


version='v1'
app = FastAPI()
app.include_router(auth_router, prefix=f'/alumniDB/{version}/user/auth', tags=['auth'])