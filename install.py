from sqlalchemy import MetaData, Table, Column, Integer, String


def create_database(engine):
    meta = MetaData()

    credentials = Table(
        "credentials", meta,
        Column("id", Integer, primary_key=True),
        Column("title", String),
        Column("username", String),
        Column("password", String),
    )

    users = Table(
        "users", meta,
        Column("id", Integer, primary_key=True),
        Column("master_password", String),
    )

    meta.create_all(engine)
    print("Database with tables has been created successfully.")

    return engine
