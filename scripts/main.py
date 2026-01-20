'''
Входная точка скрипта
'''

import logging, coloredlogs

from config import *
from traffic_data import Traffic_data
from tip import TIP
from graph_db import GraphDB

coloredlogs.install(LOGGING_LEVEL,
                    fmt=LOGGING_FORMAT)
logger = logging.getLogger()

logger.info('Initialization of network services')

td = Traffic_data(OPENSEARCH_HOST,
                  OPENSEARCH_PORT,
                  OPENSEARCH_AUTH)
if not td.check_availability():
    exit(1)

tip = TIP(TIP_URL, 
          TIP_AUTH_TOKEN, 
          TIP_WAIT_TIME)
if not tip.check_availability():
    exit(1)

db = GraphDB(NEO4J_URI, 
             NEO4J_AUTH, 
             NEO4J_DB)
if not db.check_availability():
    exit(1)


logger.info('Getting aggregated traffic data')
traffic_data = td.get_last_data(OPENSEARCH_INDEX, PLACEHOLDER_NO_DNS)

logger.info('Enrichment traffic with IoCs')
iocs = tip.enrich_traffic_data(traffic_data, PLACEHOLDER_NO_DNS)

logger.info('Loading to graph DB obtained data')
db.load_to_graph(traffic_data, iocs, PLACEHOLDER_NO_DNS)
