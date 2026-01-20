import neo4j, logging

class GraphDB:
    def __init__(self, uri: str, auth: tuple, db: str, logger=logging.getLogger("GraphDB")):
        self._uri    = uri
        self._auth   = auth
        self._db     = db
        self._logger = logger
        
    def _get_driver(self) -> neo4j.Driver:
        return neo4j.GraphDatabase.driver(self._uri,
                                    auth=self._auth)
        
    def check_availability(self) -> bool:
        """Функция проверки доступности БД

        Returns:
            bool: `True` - в случае успеха
        """
        self._logger.debug('Checking availability')
        
        try:
            driver = self._get_driver()
            driver.verify_connectivity()
            if driver.verify_authentication():
                self._logger.info('neo4j is available')
                return True
            else:
                self._logger.critical('neo4j is unavailable')
                return False
        except Exception as e:
            self._logger.critical(f'Error while check neo4j: {e}')
            return False
    
    def _clean_graph(self) -> None:
        """Функция очистки графа
        """
        self._logger.info('Cleaning graph')
        self._get_driver().execute_query(
            'MATCH (n) DETACH DELETE n;',
            database_=self._db
        )
    
    def _load_nodes(self, nodes: dict) -> None:
        """Функция загрузки нод в граф

        Args:
            nodes (dict): словарь нод
        """
        self._logger.info('Loading nodes')
        driver = self._get_driver()
        
        for node_type in nodes.keys():
            for node in nodes[node_type]:
                node_props = nodes[node_type][node]
                q = f'''
                MERGE (n:{node_type.capitalize()} {"{name: $name}"})
                ON CREATE SET n += $props
                '''
                driver.execute_query(q,
                                    name=node,
                                    props=node_props,
                                    database_=self._db)
        self._logger.info('Done')
        
        
    def _load_relations(self, relations) -> None:
        """Функция загрузки отношений в БД

        Args:
            relations (_type_): Список отношений нод
        """
        self._logger.info('Loading relations')
        driver = self._get_driver()
        for relation in relations:
            q = f'''
                MATCH (a:{relation['source_type'].capitalize()} {"{name: $nameA}"})
                MATCH (b:{relation['target_type'].capitalize()} {"{name: $nameB}"})
                MERGE (a)-[l:{relation['name'].upper()}]->(b)
                ON CREATE SET l += $props
            '''
            driver.execute_query(q,
                                nameA=relation['source'],
                                nameB=relation['target'],
                                props=relation['properties'],
                                database_=self._db)
        self._logger.info('Done')
    
    def _update_malware_analysis_types(self, nodes: dict) -> None:
        """Конкретизация типов нод malware-analysis

        Args:
            nodes (_type_): Словарь нод
        """
        self._logger.info('Updating malware_analysis types')
        driver = self._get_driver()
        for node_key, node_value in nodes['malware_analysis'].items():
            if 'description' not in node_value.keys(): continue
            if 'score' in node_value['description']: continue
            
            old_mark = 'Malware_analysis'
            new_mark = f'Malware_analysis_{node_value["description"].lower().replace(' ', '_').replace('&', 'a')}'
            q = f'''
                MATCH (n:{old_mark} {"{name: $name}"})
                REMOVE n:{old_mark}
                SET n:{new_mark};
            '''
            driver.execute_query(q,
                                name=node_key,
                                database_=self._db)
        self._logger.info('Done')
        
            
    def _parse_traffic_data(self, td: list, nodes: dict, relations: list, str_no_dns: str):
        """Парсинг трафика для поиска связей и первых нод

        Args:
            td (list): Агрегация сетевого трафика
            nodes (dict): Ноды
            relations (list): Отношения нод
            str_no_dns (str): Строка для проверки пустого значения DNS
        """
        self._logger.info('Parsing traffic data to graph')
        for con in td:
            # Обновление списка сущностей
            if con['source'] not in nodes['source'].keys(): 
                nodes['source'][con['source']] = {}
            if con['destination'] not in nodes['ip'].keys(): 
                nodes['ip'][con['destination']] = {}
            if con['dns'] not in nodes['dns'].keys() and con['dns'] != str_no_dns:
                nodes['dns'][con['dns']] = {}
            
            # Добавление связи между узлами
                
            if con['dns'] != str_no_dns:
                # Если у узла есть доменное имя
                # То добавляем связь по протоколу между доменом и IP
                # И связь, что домен разрешается в IP
                
                relations.append({
                    'source': con['source'],
                    'source_type': 'source',
                    'target': con['dns'],
                    'target_type': 'dns',
                    'name': 'ACCESSES_TO',
                    'properties': {
                        'protocol': con['protocol']
                    }
                })
                
                relations.append({
                    'source': con['dns'],
                    'source_type': 'dns',
                    'target': con['destination'],
                    'target_type': 'ip',
                    'name': 'RESOLVES',
                    'properties': {}
                })
                
            else:
                # Если связь напрямую по IP
                # То добавляется связь напрямую между хостом и IP
                relations.append({
                    'source': con['source'],
                    'source_type': 'source',
                    'target': con['destination'],
                    'target_type': 'ip',
                    'name': 'ACCESSES_TO',
                    'properties': {
                        'protocol': con['protocol']
                    }
                })
        
        self._logger.info(f'parsed: ip({len(nodes['ip'].keys())}), dns({len(nodes['dns'].keys())}), sources({len(nodes['source'].keys())})')
        self._logger.info(f'parsed relations: {len(relations)}')
        return nodes, relations
                
    def _parse_iocs(self, iocs: dict, nodes: dict, relations: list) -> tuple[dict, list]:
        """Функция для добавления в граф информации об IoC

        Args:
            iocs (dict): Список IoC
            nodes (dict): Список нод
            relations (list): Отношения нод
        """
        self._logger.info('Parsing IoC list')
        for object_name, ioc in iocs.items():
            
            # Добавление дополнительной информации в зависимости от типа
            type_object = ioc['ioc']['ioc_type'] 
            details     = ioc['details']['basic']
            history     = ioc['details']['history']
            graph_ids   = {}
            
            # Основной тип объекта
            if type_object == 'ip':
                nodes['ip'][object_name]['as_owner']          = details['as_owner']
                nodes['ip'][object_name]['asn']               = details['asn']
                nodes['ip'][object_name]['network']           = details['network']
                nodes['ip'][object_name]['last_update']       = history['last_update']
                nodes['ip'][object_name]['uploaded']          = history['uploaded']
                nodes['ip'][object_name]['valid_from']        = history['valid_from']
                nodes['ip'][object_name]['valid_until']       = history['valid_until']
            elif type_object == 'domain':
                nodes['dns'][object_name]['top_level_domain'] = details['top_level_domain']    
                nodes['dns'][object_name]['last_update']      = history['last_update']
                nodes['dns'][object_name]['uploaded']         = history['uploaded']
                nodes['dns'][object_name]['valid_from']       = history['valid_from']
                nodes['dns'][object_name]['valid_until']      = history['valid_until']
            
            
            for graph_item in ioc['graph']['objects']:
                item_type = graph_item['type']
                if 'name' in graph_item.keys(): item_name = graph_item['name']
                item_id   = graph_item['id']
                
                # Пропускаем на данном этапе связи
                if item_type == 'relationship':
                    continue
                # Если IP - проверить наличие по name
                elif item_type == 'ipv4-addr':
                    graph_ids[item_id] = item_name
                    if item_name not in nodes['ip'].keys():
                        nodes['ip'][item_name] = {}
                # Если DNS - проверить наличие по name
                elif item_type == 'domain-name':
                    graph_ids[item_id] = item_name  
                    if item_name not in nodes['dns'].keys():
                        nodes['dns'][item_name] = {}
                # Если DNS - проверить наличие по name
                elif item_type == 'file':
                    graph_ids[item_id] = item_name
                    if item_name not in nodes['file'].keys():
                        nodes['file'][item_name] = {}
                # Если URL - проверить наличие по name
                elif item_type == 'url':
                    graph_ids[item_id] = item_name
                    if item_name not in nodes['url'].keys():
                        nodes['url'][item_name] = {}
                # Если indicator - добавить по id
                elif item_type == 'indicator':
                    pattern_type = graph_item['pattern_type']
                    if pattern_type == 'stix' and item_id not in nodes['indicator'].keys():
                        nodes['indicator'][item_id] = {
                            'pattern_type': pattern_type,
                            'description':  item_name,
                            'pattern':      graph_item['pattern']
                        }
                    else:
                        self._logger.error(f'Unknown pattern - {pattern_type}')
                # Если malware - добавить по id
                elif item_type == 'malware':
                    if item_id not in nodes['malware'].keys():
                        nodes['malware'][item_id] = {
                            'description': item_name
                        }
                # Если malware-analysis - добавить по id анализ ресурса
                elif item_type == 'malware-analysis':
                    # Если это итоговое значение угрозы
                    if 'score' in item_name:
                        if item_id not in nodes['malware_analysis'].keys():
                            nodes['malware_analysis'][item_id] = {
                                'description': item_name,
                                'score': graph_item['result']['score'],
                                'type': 'score'
                            }
                            # Добавление дополнительных полей
                            if 'result' in graph_item.keys():
                                res = graph_item['result']
                                res_fields = ['algorithm', 'ioc', 'ioc_type', 'positives', 'total']
                                for f in res_fields:
                                    if f in res.keys():
                                        nodes['malware_analysis'][item_id][f] = res[f]
                    elif item_name == 'Blacklists':
                        if item_id not in nodes['malware_analysis'].keys():
                            nodes['malware_analysis'][item_id] = {
                                'description': 'Blacklists',
                                'result': graph_item['result']
                            }
                    elif item_name == 'MITRE ATT&CK':
                        if item_id not in nodes['malware_analysis'].keys():
                            ta_list = []
                            for ta in graph_item['result']:
                                ta_list.append(f'{ta['id']}: {ta['tactic']['name']}')
                            nodes['malware_analysis'][item_id] = {
                                'description': item_name,
                                'result': ta_list
                            }
                    elif item_name == 'Tor exit node':
                        if item_id not in nodes['malware_analysis'].keys():
                            nodes['malware_analysis'][item_id] = {
                                'description': item_name,
                                'result': graph_item['result'],
                                'created': graph_item['created']
                            }
                    elif item_name == 'Categories':
                        if item_id not in nodes['malware_analysis'].keys():
                            cat_list = [cat['name'] for cat in graph_item['result']]
                            nodes['malware_analysis'][item_id] = {
                                'description': item_name,
                                'result': cat_list
                            }
                    elif item_name in ['Whois lookup','Whois Lookup']:
                        if item_id not in nodes['malware_analysis'].keys():
                            nodes['malware_analysis'][item_id] = {
                                'description': item_name,
                                'result': graph_item['result']
                            }
                    elif item_name in ['Hostname lookup','Hostname Lookup']:
                        if item_id not in nodes['malware_analysis'].keys():
                            nodes['malware_analysis'][item_id] = {
                                'description': item_name,
                            }
                    elif item_name in ['Subdomains',
                                    'DNS records',
                                    'Malware analysis',
                                    'Markers']:
                        continue
                    elif 'name' not in graph_item.keys():
                        continue
                    else:
                        self._logger.error(f'Unknown malware-analyis: {item_name} of {object_name}')
                elif item_type == 'analysis-tool':
                    continue
                else:
                    self._logger.error(f'Unknown graph item type: {item_type} in IoC data of {object_name}')
                    
            # Составление связей из локального графа
            for graph_item in ioc['graph']['objects']:
                item_type = graph_item['type']
                
                # Если это IP или DNS, то используется глобальный элемент графа  
                if item_type == 'relationship':
                    s = graph_item['source_ref']
                    t = graph_item['target_ref']
                    n = graph_item['relationship_type']
                    
                    s_type = s.split('--')[0]
                    if s_type == 'ipv4-addr':
                        s_type = 'ip'
                    elif s_type == 'domain-name':
                        s_type = 'dns'
                    elif s_type == 'malware-analysis':
                        s_type = 'malware_analysis'
                        
                    t_type = t.split('--')[0]
                    if t_type == 'ipv4-addr':
                        t_type = 'ip'
                    elif t_type == 'domain-name':
                        t_type = 'dns'
                    elif t_type == 'malware-analysis':
                        t_type = 'malware_analysis'
                    
                    if s_type == 'analysis-tool' or t_type == 'analysis-tool': continue
                    
                    s = s if s not in graph_ids.keys() else graph_ids[s]
                    t = t if t not in graph_ids.keys() else graph_ids[t]
                    
                    relations.append({
                        'source': s,
                        'source_type': s_type,
                        'target': t,
                        'target_type': t_type,
                        'name': n,
                        'properties': {}
                    })
                    
                if item_type == 'malware-analysis':
                    if 'name' in graph_item.keys():
                        if 'AV score' in graph_item['name']:
                            if 'sample_ref' in graph_item.keys():

                                s = graph_item['id']
                                s_type = 'malware_analysis'
                                t = graph_item['sample_ref']
                                n = 'SAMPLE'
                                    
                                t_type = t.split('--')[0]
                                if t_type == 'ipv4-addr':
                                    t_type = 'ip'
                                elif t_type == 'domain-name':
                                    t_type = 'dns'
                                elif t_type == 'malware-analysis':
                                    t_type = 'malware_analysis'
                                            
                                t = t if t not in graph_ids.keys() else graph_ids[t]
                                
                                relations.append({
                                    'source': s,
                                    'source_type': s_type,
                                    'target': t,
                                    'target_type': t_type,
                                    'name': n,
                                    'properties': {}
                                })
                                
        nodes_stats = [f'{x}({len(nodes[x].keys())})' for x in nodes.keys()]
        self._logger.info(f'Parsed: {len(relations)} relations and nodes: {nodes_stats}')
        return nodes, relations
        
    def load_to_graph(self, traffic_data: list, iocs: dict, str_no_dns: str, clean=True) -> None: 
        """Функция парсинга и загрузки данных в графовую БД

        Args:
            traffic_data (list): Агрегации по трафику
            iocs (dict): Словарь IoC по источникам
            clean (bool, optional): Флаг чистой загрузки
        """
        
        # Основные сущности графа
        nodes = {
            'source':           {},
            'ip':               {},
            'dns':              {},
            'indicator':        {},
            'file':             {},
            'url':              {},
            'malware':          {},
            'malware_analysis': {},
            'analysis_tool':    {}
        }
        
        # Список отношений нод
        relations = []
        
        nodes, relations = self._parse_traffic_data(traffic_data, nodes, relations, str_no_dns)
        nodes, relations = self._parse_iocs(iocs, nodes, relations)
        
        # Загрузка в neo4j
        if clean: self._clean_graph()
        self._load_nodes(nodes)
        self._load_relations(relations)
        self._update_malware_analysis_types(nodes)
    
    