"""Database engine, session management, and connection lifecycle."""

import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.core.config import settings

logger = logging.getLogger("sentinel.db")


def create_db_engine(db_url: str):
    """Create a configured SQLAlchemy engine with dialect-specific options."""
    if db_url.startswith("sqlite"):
        # SQLite configuration for development and in-memory testing
        if ":memory:" in db_url:
            return create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=settings.db_echo,
            )
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=settings.db_echo,
        )
    else:
        # PostgreSQL / TimescaleDB configuration with pooling
        return create_engine(
            db_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=settings.db_pool_recycle,
            pool_pre_ping=True,
            echo=settings.db_echo,
        )


engine = create_db_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database sessions with transaction management."""
    db: Session = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error(f"Database transaction rollback due to error: {exc}")
        raise
    finally:
        db.close()


def check_db_health(target_engine=None) -> bool:
    """Verify active database connectivity."""
    active_engine = target_engine or engine
    try:
        with active_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(f"Database health check failed: {exc}")
        return False
