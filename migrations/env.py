"""Alembic environment for qjsync.

The DB URL comes from ``QJSYNC_DATABASE_URL`` (the same env var the app uses),
not from ``alembic.ini``, so secrets stay out of version control. ``target_metadata``
points at the ORM ``Base`` so ``--autogenerate`` works, but the initial migration
is hand-written to keep enum/JSON types explicit and reviewable.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from qjsync.state.models import Base

# Alembic Config object, providing access to values in alembic.ini.
config = context.config

# Resolve the runtime URL from the environment, falling back to the ini value.
_db_url = os.environ.get("QJSYNC_DATABASE_URL")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DBAPI connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (against a live connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
