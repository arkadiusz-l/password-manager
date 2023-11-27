from sqlalchemy import MetaData, Table, Column, Integer, String
from sqlalchemy.orm import Session
from models import UserModel


def create_database(engine):
    meta = MetaData()

    credentials = Table(
        "credentials", meta,
        Column("id", Integer, primary_key=True),
        Column("title", String),
        Column("login", String),
        Column("password", String),
    )

    users = Table(
        "users", meta,
        Column("id", Integer, primary_key=True),
        Column("main_password", String),
    )

    meta.create_all(engine)

    return engine


def create_main_password(engine):
    main_password = input("Enter main password:\n")
    print("Database with tables has been created successfully.")
    with Session(engine) as s:
        user = UserModel(id=1, main_password=main_password)
        s.add(user)
        s.commit()
    print("Main password saved successfully.")
