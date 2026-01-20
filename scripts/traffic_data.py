# Для получения данных из Opensearch

from opensearchpy import OpenSearch
import logging

class Traffic_data:
    
    def __init__(self, host: str, port: int, auth: tuple, logger = logging.getLogger("traffic_data")):
        self._host = host
        self._port = port
        self._auth = auth
        self._logger = logger
        
    def _get_opensearch(self) -> OpenSearch:
        return OpenSearch(
            hosts=[{'host': self._host, 'port': self._port}],
            http_auth=self._auth,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        
    def check_availability(self) -> bool:
        """Функция проверки доступности кластера Opensearch

        Returns:
            _type_: _description_
        """
        client = self._get_opensearch()
        try:
            info = client.info()
            if info.get('cluster_name'):
                self._logger.info(f"OpenSearch is available: {info['cluster_name']} (version: {info['version']['number']})")
                return True
            
        except Exception as e:
            self._logger.critical(f'Opensearch unavailable {e}')
            return False

    def get_last_data(self, index: str, no_dns_str: str, gte='now-30m') -> list:
        """
        Получение данных по трафику хостов за последние полчаса
        
        :param self: Экземпляр класса
        :param index: Индекс для получения данных
        :type index: str
        :param no_dns_str: Текст для отметки об отсутствии DNS записи
        :type no_dns_str: str
        :param gte: Временная отметка для получения данных
        :return: Список словарей с ключами: `source`, `destinaion`, `protocol`, `dns`
        :rtype: list
        """

        # Получение данных из OpenSearch
        client = self._get_opensearch()
        
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": "now"
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "connections": {
                    "multi_terms": {
                        "terms": [
                            {"field": "source.ip.keyword"},
                            {"field": "destination.ip.keyword"},
                            {"field": "destination.dns.keyword", "missing": no_dns_str},
                            {"field": "event.type.keyword"}
                        ],
                        "size": 1000
                    },
                    "aggs": {
                        "first_seen": {
                            "min": {
                                "field": "@timestamp"
                            }
                        },
                        "last_seen": {
                            "max": {
                                "field": "@timestamp"
                            }
                        },
                        "connection_count": {
                            "value_count": {
                                "field": "source.ip.keyword"
                            }
                        }
                    }
                }
            }
        }
                
        response = client.search(index=index, body=query)

        if 'aggregations' not in response:
            self._logger.error('No aggregations in result')
            self._logger.debug('Total values: 0')
            return []

        buckets = response['aggregations']['connections']['buckets']
        data = []

        for connection in buckets:
            k = connection['key']
            data.append({
                'source':      k[0],
                'destination': k[1],
                'dns':         k[2],
                'protocol':    k[3]
            })
            
        self._logger.debug(f'Total values: {len(data)}')
        
        return data
