from pydantic import BaseModel, Field

class UserCreateModel(BaseModel):
    first_name: str = Field(max_length=100)
    last_name: str = Field(max_length=100)
    email: str
    password: str

class UserModel(BaseModel):
    uid: str
    first_name: str
    last_name: str
    email: str
    is_verified: bool


class UserLoginModel(BaseModel):
    email: str = Field(max_length=40)
    password: str=Field(min_length=6)
