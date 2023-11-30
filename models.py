from sqlalchemy import create_engine, Integer, Column, String
from sqlalchemy.orm import declarative_base

engine = create_engine("sqlite:///database.db", echo=False, future=True)
Base = declarative_base()


class CredentialModel(Base):
    __tablename__ = "credentials"
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(30))
    username = Column(String(40))
    password = Column(String(20))


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    master_password = Column(String(30))
