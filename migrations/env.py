import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from src.auth.models import Base  # IMPORTANT: import your Base
from src.config import Config

# Alembic Config object
config = context.config

# Set DB URL dynamically from your app config
database_url = Config.DATABASE_URL
config.set_main_option('sqlalchemy.url', database_url)

# Logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set your metadata for Alembic to generate migrations
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()

def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()

async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()

def run_migrations_online() -> None:
    """Entry point to run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())

# Entry point
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
