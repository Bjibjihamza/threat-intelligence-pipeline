"""
=============================================================================
Threat Intelligence Pipeline - Airflow DAG
=============================================================================
DAG pour orchestrer le pipeline complet:
1. Scrape CVE (Bronze Layer)
2. Transform Bronze -> Silver
3. Transform Silver -> Gold
=============================================================================
"""

from datetime import datetime, timedelta
from pathlib import Path
import sys

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator

# Configuration du path pour importer les modules du projet
PROJECT_ROOT = Path("/opt/airflow")  # Chemin dans le container Docker
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.append(str(SRC_ROOT))

# =============================================================================
# CONFIGURATION DU DAG
# =============================================================================

default_args = {
    'owner': 'threat-intel-team',
    'depends_on_past': False,
    'email': ['hamza@example.com'],
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 2,
    'retry_delay': timedelta(minutes=5),
    'execution_timeout': timedelta(hours=2),
}

dag = DAG(
    'tip_pipeline_dag',
    default_args=default_args,
    description='Threat Intelligence Pipeline: CVE Scraping -> Bronze -> Silver -> Gold',
    schedule='0 */6 * * *',  # Updated: use 'schedule' instead of 'schedule_interval'
    start_date=datetime(2025, 10, 17),
    catchup=False,
    tags=['threat-intelligence', 'cve', 'security'],
    max_active_runs=1,
)

# =============================================================================
# TASK FUNCTIONS
# =============================================================================

def scrape_live_cves(**context):
    """Task 1: Scrape CVE et charger dans Bronze Layer"""
    import logging
    from batch.extract.stream.scrape_live_cvefeed_bronze import CompleteCVEScraper
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("🚀 TASK 1: SCRAPING CVE FEED (BRONZE LAYER)")
    logger.info("=" * 80)
    
    # Date d'aujourd'hui pour la recherche
    today = datetime.now().strftime("%Y-%m-%d")
    
    # URL de recherche: CVEs publiées aujourd'hui avec CVSS >= 3.0
    search_url = (
        f"https://cvefeed.io/search?"
        f"keyword=&"
        f"published_after={today}%2000:00:00&"
        f"published_before={today}%2023:59:59&"
        f"cvss_min=3.00&cvss_max=10.00&"
        f"order_by=-published"
    )
    
    scraper = CompleteCVEScraper()
    stats = scraper.scrape_and_load(
        search_url=search_url,
        batch_size=50,
        delay=2,
        save_csv=True,
        output_csv=f"/opt/airflow/Data/cve_backup_{today}.csv"
    )
    
    # Pousser les stats dans XCom pour les tâches suivantes
    context['task_instance'].xcom_push(key='bronze_stats', value=stats)
    
    logger.info(f"✅ Bronze Layer: {stats.get('inserted', 0)} CVEs insérés")
    return stats


def transform_bronze_to_silver(**context):
    """Task 2: Transformer Bronze -> Silver Layer"""
    import logging
    from batch.transform.EDA_bronze_to_silver import main as bronze_to_silver_main
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("🔄 TASK 2: TRANSFORMATION BRONZE -> SILVER")
    logger.info("=" * 80)
    
    # Récupérer les stats de la tâche précédente
    bronze_stats = context['task_instance'].xcom_pull(
        task_ids='scrape_live_cvefeed_bronze',
        key='bronze_stats'
    )
    
    logger.info(f"📊 Bronze stats: {bronze_stats}")
    
    # Exécuter la transformation
    silver_stats = bronze_to_silver_main()
    
    # Pousser les stats dans XCom
    context['task_instance'].xcom_push(key='silver_stats', value=silver_stats)
    
    logger.info(f"✅ Silver Layer: Transformation terminée")
    return silver_stats


def load_silver_layer(**context):
    """Task 3: Charger les données dans Silver Layer"""
    import logging
    from batch.load.load_silver_layer import main as load_silver_main
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("💾 TASK 3: CHARGEMENT SILVER LAYER")
    logger.info("=" * 80)
    
    # Charger les données transformées
    load_stats = load_silver_main()
    
    context['task_instance'].xcom_push(key='silver_load_stats', value=load_stats)
    
    logger.info(f"✅ Silver Layer chargé avec succès")
    return load_stats


def transform_silver_to_gold(**context):
    """Task 4: Transformer Silver -> Gold Layer"""
    import logging
    from batch.transform.transformation_to_gold import main as silver_to_gold_main
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("🔄 TASK 4: TRANSFORMATION SILVER -> GOLD")
    logger.info("=" * 80)
    
    # Récupérer les stats des tâches précédentes
    silver_stats = context['task_instance'].xcom_pull(
        task_ids='load_silver_layer',
        key='silver_load_stats'
    )
    
    logger.info(f"📊 Silver stats: {silver_stats}")
    
    # Exécuter la transformation
    gold_stats = silver_to_gold_main()
    
    context['task_instance'].xcom_push(key='gold_stats', value=gold_stats)
    
    logger.info(f"✅ Gold Layer: Transformation terminée")
    return gold_stats


def load_gold_layer(**context):
    """Task 5: Charger les données dans Gold Layer"""
    import logging
    from batch.load.load_gold_layer import main as load_gold_main
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("💾 TASK 5: CHARGEMENT GOLD LAYER")
    logger.info("=" * 80)
    
    # Charger les données transformées
    load_stats = load_gold_main()
    
    context['task_instance'].xcom_push(key='gold_load_stats', value=load_stats)
    
    logger.info(f"✅ Gold Layer chargé avec succès")
    return load_stats


def send_pipeline_summary(**context):
    """Task 6: Envoyer un résumé du pipeline"""
    import logging
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("📊 PIPELINE SUMMARY")
    logger.info("=" * 80)
    
    # Récupérer toutes les stats
    bronze_stats = context['task_instance'].xcom_pull(
        task_ids='scrape_live_cvefeed_bronze', key='bronze_stats'
    )
    silver_stats = context['task_instance'].xcom_pull(
        task_ids='load_silver_layer', key='silver_load_stats'
    )
    gold_stats = context['task_instance'].xcom_pull(
        task_ids='load_gold_layer', key='gold_load_stats'
    )
    
    summary = f"""
    🎉 PIPELINE COMPLETÉ AVEC SUCCÈS 🎉
    
    Bronze Layer:
    - CVEs scrapés: {bronze_stats.get('scraped', 0) if bronze_stats else 0}
    - CVEs insérés: {bronze_stats.get('inserted', 0) if bronze_stats else 0}
    - CVEs ignorés: {bronze_stats.get('skipped', 0) if bronze_stats else 0}
    
    Silver Layer:
    - Status: {silver_stats if silver_stats else 'N/A'}
    
    Gold Layer:
    - Status: {gold_stats if gold_stats else 'N/A'}
    
    Exécution: {context['execution_date']}
    """
    
    logger.info(summary)
    return summary


# =============================================================================
# DÉFINITION DES TASKS
# =============================================================================

# Task 1: Scraper CVE Feed (Bronze)
scrape_task = PythonOperator(
    task_id='scrape_live_cvefeed_bronze',
    python_callable=scrape_live_cves,
    dag=dag,
)

# Task 2: Transformer Bronze -> Silver
transform_bronze_task = PythonOperator(
    task_id='transform_bronze_to_silver',
    python_callable=transform_bronze_to_silver,
    dag=dag,
)

# Task 3: Charger Silver Layer
load_silver_task = PythonOperator(
    task_id='load_silver_layer',
    python_callable=load_silver_layer,
    dag=dag,
)

# Task 4: Transformer Silver -> Gold
transform_gold_task = PythonOperator(
    task_id='transform_silver_to_gold',
    python_callable=transform_silver_to_gold,
    dag=dag,
)

# Task 5: Charger Gold Layer
load_gold_task = PythonOperator(
    task_id='load_gold_layer',
    python_callable=load_gold_layer,
    dag=dag,
)

# Task 6: Résumé du pipeline
summary_task = PythonOperator(
    task_id='send_pipeline_summary',
    python_callable=send_pipeline_summary,
    trigger_rule='all_done',  # S'exécute même si certaines tâches échouent
    dag=dag,
)

# =============================================================================
# DÉFINITION DU WORKFLOW
# =============================================================================

scrape_task >> transform_bronze_task >> load_silver_task >> transform_gold_task >> load_gold_task >> summary_task