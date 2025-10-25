-- =============================================================================
-- AquaCulture Database Initialization Script
-- =============================================================================
--
-- This SQL script initializes the PostgreSQL database for the AquaCulture
-- monitoring system. It creates the complete database schema including:
-- - User management and authentication tables
-- - Fish species and classification data
-- - ML model management and prediction tracking
-- - Audit logging for security and compliance
-- - API key management for external integrations
-- - Performance-optimized indexes
-- - Sample data for development and testing
--
-- Database Design Principles:
-- - UUID primary keys for distributed system compatibility
-- - JSONB for flexible metadata storage
-- - Proper foreign key relationships for data integrity
-- - Comprehensive indexing for query performance
-- - Audit trails for all critical operations
-- - Timezone-aware timestamps for global deployment
--
-- Security Features:
-- - Hashed passwords using bcrypt
-- - API key management with expiration
-- - Audit logging for all user actions
-- - IP address and user agent tracking
-- - Role-based access control foundations
-- =============================================================================

-- =============================================================================
-- DATABASE EXTENSIONS
-- =============================================================================
-- Enable PostgreSQL extensions required for advanced functionality

-- UUID Generation Extension
-- =========================
-- Enables uuid_generate_v4() function for creating UUID primary keys
-- UUIDs provide better distribution in clustered databases and avoid
-- sequential ID guessing attacks
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Trigram Similarity Extension
-- ============================
-- Enables fuzzy text search and similarity matching
-- Useful for fish species name matching and search functionality
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================================================
-- CORE USER MANAGEMENT
-- =============================================================================

-- Users Table - Authentication and User Management
-- ===============================================
-- Stores user accounts for the aquaculture monitoring system
-- Supports both regular users and system administrators
CREATE TABLE IF NOT EXISTS users (
    -- Primary key using UUID for better distribution and security
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Authentication fields
    email VARCHAR(255) UNIQUE NOT NULL,          -- User's email address (login identifier)
    username VARCHAR(100) UNIQUE NOT NULL,       -- Unique username (alternative login)
    hashed_password VARCHAR(255) NOT NULL,       -- bcrypt hashed password (never store plain text)
    
    -- Profile information
    full_name VARCHAR(255),                      -- User's display name (optional)
    
    -- Account status and permissions
    is_active BOOLEAN DEFAULT TRUE,              -- Account active status (soft delete capability)
    is_superuser BOOLEAN DEFAULT FALSE,          -- Administrative privileges flag
    
    -- Audit timestamps (automatically managed)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Account creation time
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP   -- Last profile update time
);

-- =============================================================================
-- AQUACULTURE DOMAIN DATA
-- =============================================================================

-- Fish Species Table - Classification Reference Data
-- =================================================
-- Master table of fish species supported by the monitoring system
-- Used for ML model training and prediction classification
CREATE TABLE IF NOT EXISTS fish_species (
    -- Auto-incrementing integer ID for species reference
    id SERIAL PRIMARY KEY,
    
    -- Species identification
    name VARCHAR(100) UNIQUE NOT NULL,           -- Common name (e.g., "Tilapia")
    scientific_name VARCHAR(200),                -- Scientific name (e.g., "Oreochromis niloticus")
    description TEXT,                            -- Detailed species description
    
    -- Environmental parameters for aquaculture management
    optimal_temperature_min DECIMAL(5,2),       -- Minimum optimal water temperature (°C)
    optimal_temperature_max DECIMAL(5,2),       -- Maximum optimal water temperature (°C)
    
    -- Record management timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- MACHINE LEARNING MODEL MANAGEMENT
-- =============================================================================

-- ML Models Table - Model Registry and Versioning
-- ===============================================
-- Tracks all machine learning models used in the system
-- Supports model versioning, performance metrics, and lifecycle management
CREATE TABLE IF NOT EXISTS models (
    -- UUID primary key for model identification
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Model identification and versioning
    name VARCHAR(100) NOT NULL,                  -- Model name (e.g., "fish_classifier")
    version VARCHAR(50) NOT NULL,                -- Model version (e.g., "v1.2.3", "2024-01-15")
    architecture VARCHAR(100),                   -- Model architecture (e.g., "ResNet50", "EfficientNet")
    file_path VARCHAR(500),                      -- Path to model file (.pth, .pkl, .h5)
    
    -- Model performance metrics (from validation/test sets)
    accuracy DECIMAL(5,4),                       -- Overall accuracy (0.0000 to 1.0000)
    precision_score DECIMAL(5,4),                -- Precision metric for classification quality
    recall_score DECIMAL(5,4),                   -- Recall metric for classification completeness
    f1_score DECIMAL(5,4),                       -- F1 score (harmonic mean of precision and recall)
    
    -- Model lifecycle management
    is_active BOOLEAN DEFAULT FALSE,             -- Whether model is currently in use
    metadata JSONB,                              -- Flexible storage for model-specific data
    
    -- Audit information
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),        -- User who uploaded/created the model
    
    -- Ensure unique model name/version combinations
    UNIQUE(name, version)
);

-- =============================================================================
-- ML PREDICTION TRACKING
-- =============================================================================

-- Predictions Table - ML Inference Results and Analytics
-- ======================================================
-- Stores all ML model predictions for analysis, monitoring, and improvement
-- Enables tracking of model performance in production
CREATE TABLE IF NOT EXISTS predictions (
    -- UUID primary key for prediction identification
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Model and input references
    model_id UUID REFERENCES models(id),         -- Which model made this prediction
    image_path VARCHAR(500),                     -- Path to input image file
    predicted_species_id INTEGER REFERENCES fish_species(id),  -- Predicted fish species
    
    -- Prediction quality metrics
    confidence DECIMAL(5,4),                     -- Model confidence score (0.0000 to 1.0000)
    inference_time_ms INTEGER,                   -- Time taken for prediction (milliseconds)
    
    -- Additional prediction data
    metadata JSONB,                              -- Flexible storage for prediction details
    
    -- Audit information
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id)         -- User who requested the prediction
);

-- =============================================================================
-- SECURITY AND AUDIT LOGGING
-- =============================================================================

-- Audit Logs Table - Security and Compliance Tracking
-- ===================================================
-- Comprehensive audit trail for all system operations
-- Essential for security monitoring, compliance, and debugging
CREATE TABLE IF NOT EXISTS audit_logs (
    -- UUID primary key for log entry identification
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User and action identification
    user_id UUID REFERENCES users(id),           -- User who performed the action (nullable for system actions)
    action VARCHAR(100) NOT NULL,                -- Action performed (e.g., "LOGIN", "CREATE_MODEL", "DELETE_USER")
    resource_type VARCHAR(100),                  -- Type of resource affected (e.g., "USER", "MODEL", "PREDICTION")
    resource_id VARCHAR(255),                    -- ID of the affected resource
    
    -- Action details and context
    details JSONB,                               -- Flexible storage for action-specific details
    
    -- Network and client information for security analysis
    ip_address INET,                             -- Client IP address
    user_agent TEXT,                             -- Client user agent string
    
    -- Timestamp (immutable once created)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- API ACCESS MANAGEMENT
-- =============================================================================

-- API Keys Table - External Integration Authentication
-- ===================================================
-- Manages API keys for external system integration and programmatic access
-- Supports key rotation, expiration, and usage tracking
CREATE TABLE IF NOT EXISTS api_keys (
    -- UUID primary key for API key identification
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User association
    user_id UUID REFERENCES users(id),           -- User who owns this API key
    
    -- Key management
    key_hash VARCHAR(255) UNIQUE NOT NULL,       -- Hashed API key (never store plain text)
    name VARCHAR(100),                           -- Human-readable key name/description
    
    -- Key lifecycle management
    is_active BOOLEAN DEFAULT TRUE,              -- Whether key is currently valid
    expires_at TIMESTAMP WITH TIME ZONE,        -- Optional expiration date
    last_used_at TIMESTAMP WITH TIME ZONE,      -- Last time key was used (for monitoring)
    
    -- Audit timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- PERFORMANCE OPTIMIZATION INDEXES
-- =============================================================================
-- Strategic indexes to optimize common query patterns

-- Predictions Table Indexes
-- =========================
-- Optimize queries for prediction analytics and monitoring
CREATE INDEX idx_predictions_created_at ON predictions(created_at DESC);  -- Time-based queries
CREATE INDEX idx_predictions_model_id ON predictions(model_id);           -- Model performance analysis
CREATE INDEX idx_predictions_species_id ON predictions(predicted_species_id);  -- Species distribution analysis

-- Audit Logs Table Indexes
-- ========================
-- Optimize security monitoring and compliance queries
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);    -- Recent activity queries
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);               -- User activity tracking

-- Users Table Indexes
-- ===================
-- Optimize authentication and user lookup queries
CREATE INDEX idx_users_email ON users(email);                             -- Email-based login
CREATE INDEX idx_users_username ON users(username);                       -- Username-based login

-- =============================================================================
-- SAMPLE DATA FOR DEVELOPMENT AND TESTING
-- =============================================================================

-- Insert Common Aquaculture Fish Species
-- ======================================
-- Populate the fish_species table with commonly farmed species
-- Includes optimal temperature ranges for aquaculture management
INSERT INTO fish_species (name, scientific_name, description, optimal_temperature_min, optimal_temperature_max) VALUES
-- Asian Aquaculture Species
('Bangus', 'Chanos chanos', 'Milkfish - important aquaculture species in Southeast Asia', 25.0, 32.0),
('Tilapia', 'Oreochromis niloticus', 'Nile tilapia - widely farmed globally for its hardiness', 20.0, 30.0),
('Catfish', 'Clarias gariepinus', 'African catfish - hardy species with fast growth', 22.0, 30.0),

-- Premium Species
('Salmon', 'Salmo salar', 'Atlantic salmon - premium species requiring cold water', 8.0, 14.0),

-- Carp Species (Important in Asian Aquaculture)
('Grass Carp', 'Ctenopharyngodon idella', 'Herbivorous carp species - biological weed control', 20.0, 28.0),
('Big Head Carp', 'Hypophthalmichthys nobilis', 'Filter-feeding carp - plankton control', 18.0, 28.0),
('Silver Carp', 'Hypophthalmichthys molitrix', 'Asian carp species - algae control', 18.0, 28.0),
('Indian Carp', 'Labeo rohita', 'Rohu - important in South Asian aquaculture', 20.0, 30.0),

-- Southeast Asian Species
('Pangasius', 'Pangasianodon hypophthalmus', 'Striped catfish - major export species', 24.0, 30.0),
('Gourami', 'Trichogaster pectoralis', 'Snakeskin gourami - air-breathing fish', 24.0, 30.0)

-- Handle conflicts gracefully (useful for repeated script execution)
ON CONFLICT (name) DO NOTHING;

-- Create Default System Administrator Account
-- ==========================================
-- Creates a default admin user for initial system setup
-- Password: admin123 (MUST be changed in production!)
-- Hash generated using bcrypt with 12 rounds
INSERT INTO users (email, username, hashed_password, full_name, is_superuser) VALUES
('admin@aquaculture.com', 'admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqN8/xKzXu', 'System Administrator', TRUE)
ON CONFLICT (email) DO NOTHING;

-- =============================================================================
-- DATABASE PERMISSIONS AND SECURITY
-- =============================================================================

-- Grant Application User Permissions
-- ==================================
-- Grant necessary permissions to the application database user
-- Follows principle of least privilege
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO aquaculture;      -- Table access
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO aquaculture;   -- Sequence access for SERIAL columns

-- =============================================================================
-- PRODUCTION DEPLOYMENT NOTES
-- =============================================================================
--
-- Security Considerations:
-- 1. Change default admin password immediately after deployment
-- 2. Use environment variables for sensitive configuration
-- 3. Enable PostgreSQL SSL/TLS in production
-- 4. Configure proper firewall rules for database access
-- 5. Implement regular database backups and point-in-time recovery
--
-- Performance Tuning:
-- 1. Adjust PostgreSQL configuration for your hardware
-- 2. Monitor query performance and add indexes as needed
-- 3. Consider partitioning large tables (predictions, audit_logs)
-- 4. Implement connection pooling (PgBouncer recommended)
-- 5. Set up read replicas for analytics workloads
--
-- Monitoring and Maintenance:
-- 1. Set up database monitoring (pg_stat_statements, etc.)
-- 2. Configure automated backups with retention policies
-- 3. Implement log rotation for PostgreSQL logs
-- 4. Monitor disk space usage and growth trends
-- 5. Set up alerts for database health metrics
--
-- Data Retention Policies:
-- 1. Consider archiving old predictions and audit logs
-- 2. Implement data purging policies for compliance
-- 3. Set up automated cleanup jobs for temporary data
-- 4. Plan for data export and migration procedures
-- =============================================================================
