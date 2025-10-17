# src/database/connection.py
"""
Unified Database Connection Manager
Architecture: Single PostgreSQL database with multiple schemas (raw, silver, gold)
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
# CORRECTION: Alignement avec l'architecture Bronze → Silver → Gold
LAYER_SCHEMA_MAP = {
    "bronze": "raw",        # Bronze = raw (données brutes)
    "silver": "silver",     # Silver = silver (données nettoyées) ⚠️ FIXED
    "gold": "gold"          # Gold = gold (modèle en étoile) ⚠️ FIXED
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
        engine = create_engine(
            conn_str, 
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_recycle=3600
        )
        
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
    
    Examples:
        >>> get_schema_name('bronze')
        'raw'
        >>> get_schema_name('silver')
        'silver'
        >>> get_schema_name('gold')
        'gold'
    """
    schema = LAYER_SCHEMA_MAP.get(layer.lower())
    if not schema:
        raise ValueError(
            f"❌ Layer '{layer}' invalide. "
            f"Choisis parmi: {list(LAYER_SCHEMA_MAP.keys())}"
        )
    return schema


def verify_schemas(engine=None):
    """
    Vérifie que tous les schémas nécessaires existent dans la base de données
    """
    if engine is None:
        engine = get_engine()
    
    logger.info("🔍 Verifying database schemas...")
    
    with engine.connect() as conn:
        for layer, schema in LAYER_SCHEMA_MAP.items():
            result = conn.execute(
                text("""
                    SELECT schema_name 
                    FROM information_schema.schemata 
                    WHERE schema_name = :schema
                """),
                {"schema": schema}
            )
            
            if result.fetchone():
                logger.info(f"✅ Schema '{schema}' ({layer} layer) exists")
            else:
                logger.warning(
                    f"⚠️  Schema '{schema}' ({layer} layer) NOT FOUND! "
                    f"Run the corresponding SQL file to create it."
                )


def create_schemas_if_not_exist(engine=None):
    """
    Crée les schémas s'ils n'existent pas déjà
    ATTENTION: Cette fonction crée uniquement les schémas vides.
    Utilisez les fichiers SQL pour créer les tables complètes.
    """
    if engine is None:
        engine = get_engine()
    
    logger.info("🏗️  Creating schemas if they don't exist...")
    
    with engine.begin() as conn:
        for layer, schema in LAYER_SCHEMA_MAP.items():
            conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema};"))
            logger.info(f"✅ Schema '{schema}' ({layer} layer) ready")


def get_table_info(schema: str, engine=None) -> list:
    """
    Retourne la liste des tables dans un schéma donné
    
    Args:
        schema: Nom du schéma (ex: 'raw', 'silver', 'gold')
        engine: Engine SQLAlchemy (optionnel)
    
    Returns:
        list: Liste des noms de tables
    """
    if engine is None:
        engine = get_engine()
    
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = :schema 
                AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """),
            {"schema": schema}
        )
        tables = [row[0] for row in result]
    
    return tables


def get_row_count(schema: str, table: str, engine=None) -> int:
    """
    Retourne le nombre de lignes dans une table
    
    Args:
        schema: Nom du schéma
        table: Nom de la table
        engine: Engine SQLAlchemy (optionnel)
    
    Returns:
        int: Nombre de lignes
    """
    if engine is None:
        engine = get_engine()
    
    with engine.connect() as conn:
        result = conn.execute(
            text(f"SELECT COUNT(*) FROM {schema}.{table}")
        )
        count = result.scalar()
    
    return count


def get_database_stats(engine=None) -> dict:
    """
    Retourne des statistiques sur toutes les couches de données
    
    Returns:
        dict: Statistiques par layer/schema
    """
    if engine is None:
        engine = get_engine()
    
    stats = {}
    
    for layer, schema in LAYER_SCHEMA_MAP.items():
        tables = get_table_info(schema, engine)
        
        table_stats = {}
        for table in tables:
            try:
                count = get_row_count(schema, table, engine)
                table_stats[table] = count
            except Exception as e:
                table_stats[table] = f"Error: {e}"
        
        stats[layer] = {
            "schema": schema,
            "tables": table_stats,
            "total_tables": len(tables)
        }
    
    return stats


# Fonction de compatibilité (backward compatibility)
def create_db_engine():
    """Alias pour get_engine() - compatibilité avec l'ancien code"""
    return get_engine()


if __name__ == "__main__":
    # Test de connexion et affichage des statistiques
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    
    print("=" * 72)
    print("🔌 DATABASE CONNECTION TEST")
    print("=" * 72)
    
    # Test de connexion
    engine = get_engine()
    
    # Vérifier les schémas
    verify_schemas(engine)
    
    # Afficher les statistiques
    print("\n" + "=" * 72)
    print("📊 DATABASE STATISTICS")
    print("=" * 72)
    
    stats = get_database_stats(engine)
    
    for layer, info in stats.items():
        print(f"\n🔹 {layer.upper()} LAYER (schema: {info['schema']})")
        print(f"   Tables: {info['total_tables']}")
        
        if info['tables']:
            for table, count in info['tables'].items():
                if isinstance(count, int):
                    print(f"   - {table}: {count:,} rows")
                else:
                    print(f"   - {table}: {count}")
        else:
            print("   No tables found")
    
    print("\n" + "=" * 72)
    print("✅ Database connection test successful!")
    print("=" * 72)