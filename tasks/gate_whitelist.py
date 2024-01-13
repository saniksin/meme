
import time

import pyotp
from tqdm import tqdm
from better_automation.base import BaseAsyncSession
from sqlalchemy.ext.asyncio import AsyncSession

from data.config import logger
from settings.settings import NUMBER_OF_ATTEMPTS, GATE_OTP, TRADE_PASSWORD, CSRFTOKEN, COOKIES
from db_api.database import Wallet, db


class GateAddWhitelist:

    def __init__(self, account_data: Wallet):
        self.data: Wallet = account_data
        self.version = self.data.user_agent.split('Chrome/')[1].split('.')[0]
        self.async_session = BaseAsyncSession(verify=True)

    async def gate_wl_request(self, auth_code: str):
        url = 'https://www.gate.io/json_svr/query?u=116'

        headers = {
            'authority': 'www.gate.io',
            'accept': '*/*',
            'accept-language': 'ru-RU,ru;q=0.9',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'cookie': COOKIES,
            'csrftoken': CSRFTOKEN,
            'origin': 'https://www.gate.io',
            'referer': 'https://www.gate.io/ru/myaccount/withdraw_address',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }

        data = {
            'type': 'set_withdraw_address',
            'curr_type': 'MEME',
            'verified': '1',
            'is_universal': '1',
            'addr': self.data.address,
            'receiver_name': '',
            'address_tag': '',
            'source': '',
            'fundpass': TRADE_PASSWORD,
            'chain': 'ETH',
            'sub_user_id': '',
            'totp': f'{auth_code}',
            'smscode': '',
            'emailcode': '',
            'batch_sub': '1',
            'id': '',
        }

        response = await self.async_session.post(
            url,
            headers=headers,
            data=data
        )

        if response.status_code == 200:
            response_json = response.json()
            return response_json
        else:
            return f"Request failed with status code: {response.status_code}"

    async def start_add_whitelisted_task(self):
        attempts = 0
        while attempts < NUMBER_OF_ATTEMPTS:
            attempts += 1
            totp = pyotp.TOTP(GATE_OTP)
            current_otp = str(totp.now())

            result = await self.gate_wl_request(auth_code=current_otp)

            if result == {'result': False, 'msg': 'Слишком много попыток'}:
                sleep_time = 400
                logger.info(f'{self.data.address} | слишком много попыток')
                for _ in tqdm(range(sleep_time), desc="СОН: "):
                    time.sleep(1)
                continue
            elif not result.get('result', False):
                logger.info(f'{self.data.address} | {result["msg"]}')
                continue
            else:
                if result['result']:
                    logger.success(f'{self.data.address} | {result["msg"]}')
                    self.data.add_to_gate_whitelist = True
                    await self.write_to_db()
                    break
                continue

        if attempts == NUMBER_OF_ATTEMPTS:

            with open('problem_with_add_to_wl.txt', mode='a') as file:
                file.write(f'{self.data.address}\n')

    async def write_to_db(self):
        async with AsyncSession(db.engine) as session:
            await session.merge(self.data)
            await session.commit()
