# src/database/connection.py
"""
Unified Database Connection Manager
Architecture: Single PostgreSQL database with multiple schemas (raw, cleansed, curated)
"""
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import logging

load_dotenv()
logger = logging.getLogger(__name__)

# --- Configuration centralisée ---
DB_CONFIG = {
    "user": os.getenv("PG_USER", "postgres"),
    "password": os.getenv("PG_PASSWORD", "tip_pwd"),
    "host": os.getenv("PG_HOST", "localhost"),
    "port": os.getenv("PG_PORT", "5432"),
    "database": os.getenv("PG_DB", "tip"),  # Une seule base de données
}

# Mapping des layers vers les schémas PostgreSQL
LAYER_SCHEMA_MAP = {
    "bronze": "raw",
    "silver": "cleansed",
    "gold": "curated"
}


def get_engine():
    """
    Retourne un moteur SQLAlchemy pour la base de données unique
    """
    try:
        conn_str = (
            f"postgresql+psycopg2://{DB_CONFIG['user']}:{DB_CONFIG['password']}@"
            f"{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
        engine = create_engine(conn_str, pool_pre_ping=True)
        
        # Test de connexion
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        logger.info(f"✅ Connected to PostgreSQL at {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
        return engine
    
    except SQLAlchemyError as e:
        logger.error(f"❌ Failed to connect to database: {e}")
        raise


def get_schema_name(layer: str) -> str:
    """
    Retourne le nom du schéma pour un layer donné
    
    Args:
        layer: 'bronze', 'silver', ou 'gold'
    
    Returns:
        str: Nom du schéma PostgreSQL
    """
    schema = LAYER_SCHEMA_MAP.get(layer.lower())
    if not schema:
        raise ValueError(f"❌ Layer '{layer}' invalide. Choisis parmi: {list(LAYER_SCHEMA_MAP.keys())}")
    return schema


def verify_schemas(engine=None):
    """
    Vérifie que tous les schémas nécessaires existent
    """
    if engine is None:
        engine = get_engine()
    
    with engine.connect() as conn:
        for layer, schema in LAYER_SCHEMA_MAP.items():
            result = conn.execute(text(
                "SELECT schema_name FROM information_schema.schemata WHERE schema_name = :schema"
            ), {"schema": schema})
            
            if result.fetchone():
                logger.info(f"✅ Schema '{schema}' ({layer} layer) exists")
            else:
                logger.warning(f"⚠️ Schema '{schema}' ({layer} layer) NOT FOUND!")


# Fonction de compatibilité (backward compatibility)
def create_db_engine():
    """Alias pour get_engine() - compatibilité avec l'ancien code"""
    return get_engine()


if __name__ == "__main__":
    # Test de connexion
    logging.basicConfig(level=logging.INFO)
    engine = get_engine()
    verify_schemas(engine)
    print("\n✅ Database connection test successful!")