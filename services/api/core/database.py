"""
Database Connection and Session Management Module

This module provides database connectivity using SQLAlchemy ORM with
connection pooling, session management, and dependency injection patterns.

Industry Standards:
    - Connection pooling for performance
    - Context manager pattern for session lifecycle
    - Dependency injection for FastAPI
    - Declarative base for ORM models
    - Pool pre-ping for connection health checks

Architecture:
    - Engine: Database connection pool manager
    - SessionLocal: Session factory for creating DB sessions
    - Base: Declarative base class for all ORM models
    - get_db: Dependency injection function for FastAPI routes
"""

# Import Generator type hint for functions that yield values (like get_db)
from typing import Generator

# Import create_engine: Core SQLAlchemy function for database connection management
from sqlalchemy import create_engine
# Import declarative_base: Factory function for creating ORM model base classes
from sqlalchemy.ext.declarative import declarative_base
# Import Session: Database session class for executing queries and transactions
# Import sessionmaker: Factory function for creating session classes
from sqlalchemy.orm import Session, sessionmaker

# Import application settings containing database configuration
from .config import settings

# Database Engine Configuration
# ==============================
# SQLAlchemy engine manages connection pool and database communication
# This is the core component that handles all database connectivity
engine = create_engine(
    # Database connection string from configuration (PostgreSQL URL)
    settings.DATABASE_URL,
    
    # Number of persistent connections to keep open in the pool
    # These connections are reused across requests for better performance
    pool_size=settings.DATABASE_POOL_SIZE,
    
    # Additional connections beyond pool_size when demand is high
    # Total max connections = pool_size + max_overflow
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    
    # Verify connection health before using (prevents stale connections)
    # Sends a simple query (SELECT 1) to test if connection is alive
    pool_pre_ping=True,
    
    # Log all SQL statements when DEBUG=True (useful for development)
    # Shows actual SQL queries being executed
    echo=settings.DEBUG,
    
    # Recycle connections after 1 hour to prevent timeout issues
    # Closes and recreates connections that have been idle too long
    pool_recycle=3600,
    
    # Additional connection arguments passed to the database driver
    # Sets timezone to UTC for consistency across different environments
    connect_args={"options": "-c timezone=utc"},
)

# Session Factory
# ===============
# Creates new database sessions with proper configuration
# Sessions represent a "workspace" for database operations
SessionLocal = sessionmaker(
    # autocommit=False: Explicit transaction control (recommended)
    # Transactions must be manually committed, preventing accidental data changes
    autocommit=False,
    
    # autoflush=False: Manual flush control for better performance
    # Changes aren't automatically sent to DB until explicitly flushed
    autoflush=False,
    
    # bind=engine: Associate this session factory with our database engine
    # All sessions created will use this engine for database communication
    bind=engine,
    
    # expire_on_commit=False: Prevent expired object errors after commit
    # Allows accessing object attributes after transaction is committed
    expire_on_commit=False,
)

# Declarative Base
# ================
# Base class for all ORM models
# All database models should inherit from this class
# Provides common functionality like table creation and metadata management
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Database Session Dependency (Dependency Injection Pattern)

    Provides a database session for FastAPI route handlers.
    Automatically handles session lifecycle: creation, usage, and cleanup.

    Yields:
        Session: SQLAlchemy database session

    Example:
        ```python
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
        ```

    Note:
        - Session is automatically closed after request completion
        - Exceptions trigger automatic rollback
        - Use with FastAPI's Depends() for dependency injection

    Best Practices:
        - Always use this dependency instead of creating sessions manually
        - Never store sessions in global variables
        - Let FastAPI handle session lifecycle
    """
    # Create a new database session using our configured session factory
    # Each request gets its own isolated session
    db = SessionLocal()
    
    try:
        # Yield the session to the calling function (FastAPI route handler)
        # This is where the actual database operations happen
        yield db
        
    except Exception:
        # Rollback on any exception to maintain database consistency
        # Undoes any uncommitted changes to prevent partial/corrupted data
        db.rollback()
        # Re-raise the exception so FastAPI can handle it properly
        raise
        
    finally:
        # Always close session to return connection to pool
        # This happens regardless of success or failure
        # Ensures connections are properly cleaned up and returned to the pool
        db.close()


def init_db() -> None:
    """
    Initialize Database Schema

    Creates all tables defined in SQLAlchemy models.
    Should be called on application startup.

    Note:
        - Only creates tables that don't exist
        - Does not handle migrations (use Alembic for that)
        - Safe to call multiple times (idempotent)

    Example:
        ```python
        @app.on_event("startup")
        async def startup():
            init_db()
        ```

    Warning:
        In production, use Alembic migrations instead of this function.
        This is primarily for development and testing.
    """
    # Create all tables defined in models that inherit from Base
    # Uses the metadata collected from all model classes
    # bind=engine: Use our configured database engine for table creation
    # This is idempotent - won't recreate existing tables
    Base.metadata.create_all(bind=engine)