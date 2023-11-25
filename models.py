from sqlalchemy import create_engine, Integer, Column, String, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, backref

engine = create_engine("sqlite:///database.db", echo=False, future=True)
Base = declarative_base()


class SiteModel(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    name = Column(String(30))


class CredentialModel(Base):
    __tablename__ = "credentials"
    login = Column(String(30), primary_key=True)
    password = Column(String(30))
    site_id = Column(Integer, ForeignKey("sites.id"))
    site = relationship("SiteModel", backref=backref("credentials", uselist=False))
