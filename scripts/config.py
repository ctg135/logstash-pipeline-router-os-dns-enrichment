'''
Скрипт для загрузки переменных окружения
'''

import os
from dotenv import load_dotenv


load_dotenv()

# Реквизиты Opensearch
OPENSEARCH_HOST     = os.getenv("OPENSEARCH_HOST", "")
OPENSEARCH_PORT     = os.getenv("OPENSEARCH_PORT", "")
OPENSEARCH_LOGIN    = os.getenv("OPENSEARCH_LOGIN", "")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "")
OPENSEARCH_AUTH     = (OPENSEARCH_LOGIN, OPENSEARCH_PASSWORD)
OPENSEARCH_INDEX    = os.getenv("OPENSEARCH_INDEX", "")

# Реквизиты Threat Inteligence Portal
TIP_URL         = os.getenv("TIP_URL", "")
TIP_WAIT_TIME   = 0.5
TIP_AUTH_TOKEN  = os.getenv("TIP_AUTH_TOKEN", "")

# Реквизиты Neo4j
NEO4J_URI       = os.getenv("NEO4J_URI", "")
NEO4J_LOGIN     = os.getenv("NEO4J_LOGIN", "")
NEO4J_PASSWORD  = os.getenv("NEO4J_PASSWORD", "")
NEO4J_AUTH      = (NEO4J_LOGIN, NEO4J_PASSWORD)
NEO4J_DB        = os.getenv("NEO4J_DB", "")

# Параметры логгирования
import logging

LOGGING_LEVEL = logging.INFO
LOGGING_FORMAT = '%(asctime)s [%(levelname)s] %(name)s %(funcName)s: %(message)s'

# Дополнительные переменные
PLACEHOLDER_NO_DNS = "NO_DNS"

