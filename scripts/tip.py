import requests, time, logging

class TIP:
    def __init__(self, url, token, wait_time=0.5, logger=logging.getLogger("TIP")):
        self._url = url
        self._token = token
        self._wait = wait_time
        self._logger = logger
        
        self._headers = {
            "Authorization": f"Token {token}"
        }
        self._url_feeds = f'{self._url}/feeds/'
    
    def check_availability(self) -> bool:
        """Функция проверки доступности портала TIP

        Returns:
            bool: `True` - в случае успеха
        """
        try:
            self._logger.debug(f'Checking {self._url}...')
            check = requests.get(url=self._url)
            if check.status_code != 405:
                raise Exception(f"Unknown status code {check.status_code}")
            
            self._logger.info('TIP is available')
            return True
        
        except Exception as e:
            self._logger.critical(f'TIP is unavailable: {e}')
            return False
        
    def search_ioc(self, data: str) -> dict:
        """Функция для поиска данных об IoC

        Args:
            data (str): Значение для поиска на портале

        Raises:
            Exception: При ошибке выполнения запросов

        Returns:
            dict: Данные об IoC
        """
        self._logger.info(f'Search IoC for: {data}')
        
        request = {
            'ioc': data
        }
        
        task = requests.post(
            url=self._url_feeds,
            headers=self._headers,
            data=request
        )
        
        if task.status_code != 200:
            self._logger.critical(f'Bad status code: {task.status_code} for "{data}"')
            self._logger.debug(task.json())
            raise Exception('Bad status code error')
        
        task_id = task.json()['task_id']
        self._logger.debug(f'Task id: {task_id}')

        tip_task_url = f'{self._url}/{task_id}/'
        
        # Счетчик при долгом ожидании
        safe_counter = 10
        while True:
            if safe_counter == 0:
                self._logger.error('Long await, getting next IoC')
                return None
            
            safe_counter -= 1
            # Ожидание выполнения поиска
            time.sleep(self._wait)
            self._logger.debug('Trying get task result')
            ioc = requests.get(
                url=tip_task_url,
                headers=self._headers
            )
            
            # Если процесс поиска еще идет
            if ioc.status_code == 202:
                self._logger.debug('Task is running')
                continue
            # Если IoC успешно нашелся
            elif ioc.status_code == 200:
                if ioc.json()['task']['status'] == 'running':
                    self._logger.debug('Task is running')
                    continue
                # IoC не найден
                elif ioc.json()['task']['status'] == 'not_found':
                    self._logger.debug('IoC not found')
                    return None
                # IoC найден, возвращение результата
                elif ioc.json()['task']['status'] == 'ready':
                    self._logger.debug('IoC found')
                    return ioc.json()['result']
                else:
                    self._logger.error(f'Unknown status')
                    self._logger.debug(ioc.json())
            else:
                self._logger.critical(f'Bad status code ({ioc.status_code}) while getting task result')
                self._logger.debug(ioc.json())
                raise Exception('Bad status code')
    
    
    def _add_ioc(self, data, iocs) -> dict:
        # Если локальный адрес
        if "192.168" in data: return
        # Если уже выполнялся поиск
        if data in iocs.keys(): return
        
        ioc = self.search_ioc(data)
        if ioc != None: 
            self._logger.debug(f'Adding {data} to iocs')
            iocs[data] = ioc
        
    def enrich_traffic_data(self, traffic_data: list, no_dns_str: str) -> dict:
        """Обогащение данных о сетевом траффике при помощи портала TIP

        Args:
            traffic_data (list): Агрегированные данные о трафике

        Returns:
            dict: Словарь с IoC, где ключ - это и есть элемент, а значение -
                  полученные данные
        """
        
        iocs = {}
        for con in traffic_data:
            dns = con['dns']
            ip  = con['destination']
            
            # Если сушествует доменное имя
            # То ищем наличие IoC на него
            if dns != no_dns_str:
                self._logger.debug(f'DNS exists')
                self._add_ioc(dns, iocs)
                
            # Поиск IoC на IP адрес
            self._add_ioc(ip, iocs)
        
        return iocs