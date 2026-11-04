from alembic import context
from sqlalchemy import create_engine
from veyrix_api.config import settings
from veyrix_api.models import Base


def run_migrations() -> None:
    engine = create_engine(settings.database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations()
