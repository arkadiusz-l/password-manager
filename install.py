from sqlalchemy import MetaData, Table, Column, Integer, String


def install(engine):
    meta = MetaData()

    sites = Table(
        "sites", meta,
        Column("id", Integer, primary_key=True),
        Column("name", String),
    )

    credentials = Table(
        "credentials", meta,
        Column("id", Integer, primary_key=True),
        Column("site_id", Integer),
        Column("login", String),
        Column("password", String),
    )

    meta.create_all(engine)
