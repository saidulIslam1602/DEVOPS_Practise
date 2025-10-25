"""
Configuration Management Module

This module handles all application configuration using Pydantic Settings.
Settings are loaded from environment variables and .env file with validation.

Industry Standards:
    - Type hints for all configuration values
    - Pydantic validation for type safety
    - Environment variable override support
    - Singleton pattern with LRU cache
    - Separation of concerns by configuration domain
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application Settings

    Centralized configuration management using Pydantic BaseSettings.
    All settings can be overridden via environment variables.

    Attributes:
        API_V1_PREFIX: API version prefix for all endpoints
        PROJECT_NAME: Human-readable project name
        VERSION: Semantic version following semver.org
        DESCRIPTION: Project description for OpenAPI docs

    Example:
        >>> settings = get_settings()
        >>> print(settings.PROJECT_NAME)
        'Aquaculture ML Platform'

    Note:
        Settings are cached using lru_cache for performance.
        Changes to .env require application restart.
    """

    # API Configuration
    # RESTful API settings following OpenAPI 3.0 specification
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Aquaculture ML Platform"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "Production-grade ML platform for fish classification"

    # Server Configuration
    # Network binding settings for uvicorn ASGI server
    API_HOST: str = "0.0.0.0"  # Bind to all interfaces
    API_PORT: int = 8000

    # Database Configuration
    # PostgreSQL connection settings with connection pooling
    DATABASE_URL: str = (
        "postgresql://aquaculture:aquaculture123@postgres:5432/aquaculture_db"
    )
    DATABASE_POOL_SIZE: int = 20  # Max connections in pool
    DATABASE_MAX_OVERFLOW: int = 10  # Additional connections when pool is full

    # Redis Configuration
    # In-memory cache and session store settings
    REDIS_URL: str = "redis://redis:6379/0"
    REDIS_MAX_CONNECTIONS: int = 50  # Connection pool size

    # Kafka Configuration
    # Message broker settings for event streaming
    KAFKA_BOOTSTRAP_SERVERS: str = "kafka:9092"
    KAFKA_TOPIC_PREDICTIONS: str = "fish-predictions"

    # Security Configuration
    # Authentication and authorization settings
    # WARNING: Change these secrets in production!
    SECRET_KEY: str = "change-this-to-a-secure-random-string-in-production"
    JWT_SECRET: str = "change-this-to-another-secure-random-string"
    JWT_ALGORITHM: str = "HS256"  # HMAC using SHA-256
    JWT_EXPIRATION_HOURS: int = 24
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours in minutes

    # CORS Configuration
    # Cross-Origin Resource Sharing settings for web clients
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]  # Allow all HTTP methods
    CORS_ALLOW_HEADERS: List[str] = ["*"]  # Allow all headers

    # Rate Limiting Configuration
    # API rate limiting to prevent abuse
    RATE_LIMIT_PER_MINUTE: int = 100  # Requests per minute per user
    RATE_LIMIT_BURST: int = 20  # Burst capacity for traffic spikes

    # Monitoring Configuration
    # Observability and metrics collection settings
    PROMETHEUS_ENABLED: bool = True
    LOG_LEVEL: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

    # ML Configuration
    # Machine Learning model and inference settings
    MODEL_PATH: str = "/app/models/fish_classifier_v1.pth"
    BATCH_SIZE: int = 32  # Images processed simultaneously
    CONFIDENCE_THRESHOLD: float = 0.5  # Minimum confidence for valid predictions
    INFERENCE_DEVICE: str = "cpu"  # Device for ML inference (cpu/cuda)
    
    # File Upload Configuration
    # Image upload settings for fish classification
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB maximum file size
    UPLOAD_DIR: str = "/app/uploads"  # Directory for uploaded files
    ALLOWED_EXTENSIONS: List[str] = ["jpg", "jpeg", "png", "webp"]  # Allowed image formats

    # Environment Configuration
    # Deployment environment settings
    ENVIRONMENT: str = "development"  # development, staging, production
    DEBUG: bool = True  # Enable debug mode (disable in production!)

    class Config:
        """Pydantic configuration"""

        env_file = ".env"  # Load from .env file
        case_sensitive = True  # Environment variables are case-sensitive


@lru_cache()
def get_settings() -> Settings:
    """
    Get Application Settings (Singleton Pattern)

    Returns cached Settings instance for performance.
    Settings are loaded once and reused across the application.

    Returns:
        Settings: Validated application configuration

    Example:
        >>> from services.api.core.config import get_settings
        >>> settings = get_settings()
        >>> print(settings.DATABASE_URL)

    Note:
        Uses functools.lru_cache to ensure single instance.
        Thread-safe and efficient for concurrent access.
    """
    return Settings()


# Global settings instance
# Import this in other modules: from services.api.core.config import settings
settings = get_settings()
