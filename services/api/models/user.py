"""User database model"""

import uuid

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from ..core.database import Base


class User(Base):
    """
    User model for authentication and user management.
    
    This model represents users in the aquaculture system, storing
    essential user information including authentication credentials,
    profile data, and system permissions.
    """

    __tablename__ = "users"

    # Primary key - UUID for better security and distributed systems
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Authentication fields
    email = Column(String(255), unique=True, nullable=False, index=True)  # User's email address (login)
    username = Column(String(100), unique=True, nullable=False, index=True)  # Unique username (alternative login)
    hashed_password = Column(String(255), nullable=False)  # Bcrypt/Argon2 hashed password
    
    # Profile information
    full_name = Column(String(255))  # User's display name (optional)
    
    # System permissions and status
    is_active = Column(Boolean, default=True)  # Account active status (for soft deletion)
    is_superuser = Column(Boolean, default=False)  # Admin privileges flag
    
    # Audit timestamps - automatically managed by database
    created_at = Column(DateTime(timezone=True), server_default=func.now())  # Account creation timestamp
    updated_at = Column(
        DateTime(timezone=True), 
        server_default=func.now(), 
        onupdate=func.now()  # Automatically updates on any record modification
    )

    def __repr__(self):
        """String representation for debugging and logging"""
        return f"<User(username='{self.username}', email='{self.email}')>"