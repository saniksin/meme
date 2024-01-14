import time
import random
from datetime import datetime

import ccxt
import asyncio
from better_automation.base import BaseAsyncSession
from sqlalchemy.ext.asyncio import AsyncSession
from tqdm import tqdm

from db_api.database import Wallet, db
from data.config import logger, FEE
from settings.settings import CSRFTOKEN, COOKIES, API_KEY, SECRET, MAX_FEE


class GateWithdraw:
    headers = {
        'authority': 'www.gate.io',
        'accept': '*/*',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'cookie': COOKIES,
        'csrftoken': CSRFTOKEN,
        'origin': 'https://www.gate.io',
        'referer': 'https://www.gate.io/myaccount/withdraw/MEME',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': 'macOS',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }

    def __init__(self, account_data: Wallet):
        self.data: Wallet = account_data
        self.async_session = BaseAsyncSession(verify=True)
        self.current_time = None
        self.current_fee = FEE[0]
        self.disabled = FEE[1]

    async def get_withdrawal_fee(self):
        while True:
            try:
                logger.info(f'{self.data.address} | пробую получить новую комиссию')
                url = 'https://www.gate.io/json_svr/query?u=113'
                data = {
                    'type': 'check_withdraw_chain_by_addr',
                    'curr_type': 'MEME',
                    'addr': self.data.address
                }

                response = await self.async_session.post(
                    url,
                    headers=self.headers,
                    data=data
                )

                response_data = response.json()
                if response.status_code == 200:
                    withdraw_txfee = response_data['datas'][0]['withdraw_txfee']
                    is_disabled = response_data['datas'][0]['is_disabled']

                    if withdraw_txfee > MAX_FEE:
                        time_sleep = 400
                        msg = (f'{self.data.address} | комиссия слишком большая, '
                               f'текущая комиссия = {withdraw_txfee} ухожу на сон {time_sleep} сек')
                        logger.info(msg)
                        for _ in tqdm(range(time_sleep), desc="COН: "):
                            time.sleep(1)
                        continue

                    FEE[0] = withdraw_txfee
                    FEE[1] = is_disabled

                    logger.info('Новая комиссия получена и успешно записана!')

                    return

                elif 'Слишком много попыток' in response_data.values() or \
                     'Too many attempts' in response_data.values():
                    time_sleep = 400
                    msg = (f'{self.data.address} | ухожу на сон {time_sleep} сек. '
                           f'Слишком много попыток получить ком-су | API не отвечает.')
                    logger.warning(msg)
                    for _ in tqdm(range(time_sleep), desc="COН: "):
                        time.sleep(1)
                    continue
                else:
                    logger.error(f"Request failed with status code: {response.status_code}")
                    continue

            except Exception as ex:
                logger.error(f"{self.data.address} - {ex}")
                continue

    async def start_withdraw(self):

        symbol = 'MEME'
        exchange = ccxt.gate({
            'apiKey': API_KEY,
            'secret': SECRET
        })

        try:
            need_update = await self.check_current_time()

            if need_update:
                await self.get_withdrawal_fee()
                self.current_fee = FEE[0]
                self.disabled = FEE[1]

            amount_to_withdrawal = self.current_fee + random.uniform(69.00, 70.00)
            if self.current_fee < MAX_FEE and not self.disabled:
                status = exchange.withdraw(
                    code=symbol,
                    amount=amount_to_withdrawal,
                    address=self.data.address,
                    params={
                        "network": "ETH"
                    }
                )

                if status['status'] == 'pending':
                    msg = (f'{self.data.address} | запрос на вывод {amount_to_withdrawal} {symbol} c '
                           f'[GATE.IO] успешно отправлен.')
                    logger.success(msg)

                    await self.write_to_db()
                    return

        except Exception as error:
            if "Too many tries, please try again later" in str(error):
                logger.warning(f'{self.data.address} | много запросов на вывод сплю 10 минут [GATE.IO].')
                await asyncio.sleep(600)
                await self.get_withdrawal_fee()
                await self.start_withdraw()
            logger.error(f'{self.data.address} | не смог вывести {symbol} c [GATE.IO].')

    async def write_to_db(self):
        async with AsyncSession(db.engine) as session:
            self.data.withdraw_from_gate = True
            await session.merge(self.data)
            await session.commit()

    @staticmethod
    async def check_current_time():
        current_time = datetime.now().strftime("%H:%M")
        if int(current_time[-2:]) % 3 == 0:
            logger.info(f'Необходимо обновить комиссию')
            return True
        return False
