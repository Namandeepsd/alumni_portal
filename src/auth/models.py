import uuid
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Boolean

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    uid = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    is_verified = Column(Boolean, default=False)
    must_change_password = Column(Boolean, default=False)
