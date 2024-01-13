import traceback

import asyncio
import aiofiles
from better_automation.base import BaseAsyncSession
from eth_account.messages import encode_defunct
from sqlalchemy.ext.asyncio import AsyncSession
from curl_cffi.requests.errors import RequestsError

from db_api.database import Wallet, db
from eth.eth_clients import EthClient
from data.config import MEME_CONTRACT, logger, PROBLEM_PROXY, LOW_BALANCE
from settings.settings import MIN_BALANCE, NUMBER_OF_ATTEMPTS
from tasks.captha_tasks import CapthaSolver


class EthTasks:

    def __init__(self, account_data: Wallet):
        self.data = account_data
        self.eth_client = EthClient(
            private_key=self.data.private_key,
            proxy=self.data.proxy,
            user_agent=self.data.user_agent
        )
        self.async_session: BaseAsyncSession = BaseAsyncSession(proxy=self.data.proxy, verify=False)
        self.version = self.data.user_agent.split('Chrome/')[1].split('.')[0]
        self.bearer_token = None
        self.old_points_balance = self.data.points
        self.write_lock = asyncio.Lock()

    async def check_meme_balance(self):
        return await self.eth_client.wallet.balance(
            token_address=MEME_CONTRACT,
            address=self.eth_client.account.address
        )

    async def start_tasks(self):
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                logger.info(f'{self.data.address} | Попытка {num}')

                # логинимся
                await self.start_login()

                # проверяем и записываем поинты
                await self.check_points()
                if isinstance(self.data.points, int):
                    if self.data.points != 0 and self.data.points != self.old_points_balance:
                        await self.write_to_db()
                    msg = (f'{self.data.address} | успешно авторизировался через pk | '
                           f'количество поинтов {self.data.points}')
                    logger.success(msg)

                # проверяем баланс и проходим капчу
                actual_meme_balance = await self.check_meme_balance()
                logger.info(f'{self.data.address} | текущий баланс токенов: {actual_meme_balance.Ether} MEME')
                if actual_meme_balance.Wei >= MIN_BALANCE:
                    if not self.data.captha_solved:
                        captcha_solver = CapthaSolver(
                            account_data=self.data,
                            session=self.async_session,
                            bearer_token=self.bearer_token,
                            version=self.version
                        )

                        tasks: list = [
                            asyncio.create_task(coro=captcha_solver.recaptcha_solver()),
                            asyncio.create_task(coro=captcha_solver.hcaptcha_solver())
                        ]

                        await asyncio.gather(*tasks)

                        status = await self.verify_complete()
                        if status:
                            logger.success(f'{self.data.address} | успешно закончил с капчей!')
                        else:
                            logger.error(f'{self.data.address} | не смог подтвердить капчу')
                            continue
                    else:
                        logger.warning(f'{self.data.address} | уже закончил проходить капчу')
                else:
                    msg = f'{self.data.address} | не достаточный баланс токенов. Необходимо минимум 69 токенов!'
                    await self.write_status(status="low balance", path=LOW_BALANCE)
                    logger.error(msg)
                    break

                break

            except RequestsError:
                logger.error(f'{self.data.address} | проблема с прокси! Проверьте прокси!')
                await self.write_status(status="proxy problem", path=PROBLEM_PROXY)
                continue

            except Exception as error:
                logger.error(f'{self.data.address} | неизвестная ошибка: {error}')
                print(traceback.print_exc())

    async def write_status(self, status, path):
        """ Записывает текщий статус проблемного токена в соответсвующий файл """

        async with self.write_lock:
            async with aiofiles.open(file=path, mode='a', encoding='utf-8-sig') as f:
                if status == "proxy problem":
                    await f.write(f'{self.data.proxy}\n')
                elif status == "low balance":
                    await f.write(f'{self.eth_client.account.address}\n')
                else:
                    await f.write(f'{self.data.token} | {self.data.proxy} | {self.data.private_key} | {status}\n')

    async def verify_complete(self) -> bool:
        response: None = None

        while True:
            try:

                headers = {
                    'authority': 'memefarm-api.memecoin.org',
                    'sec-ch-ua': f'" Not A;Brand";v="99", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
                    'accept': 'application/json',
                    'authorization': f'Bearer {self.bearer_token}',
                    'sec-ch-ua-mobile': '?0',
                    'user-agent': self.data.user_agent,
                    'sec-ch-ua-platform': f'"{self.data.platform}"',
                    'origin': 'https://www.memecoin.org',
                    'sec-fetch-site': 'same-site',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-dest': 'empty',
                    'accept-language': 'en-US,en;q=0.9',
                }

                response = await self.async_session.post(
                    url='https://memefarm-api.memecoin.org/user/verify/wallet-balance',
                    headers=headers,
                    json=False,
                )

                if response.json()['status'] == 'success':
                    self.data.captha_solved = 1
                    await self.write_to_db()

                return response.json()['status'] == 'success'

            except Exception as error:
                if response:
                    msg = f'{self.data.address} | Неизвестная ошибка при подтверждении выполнения: ' \
                          f'{error}, ответ: {response.text}'
                    logger.error(msg)

                else:
                    logger.error(f'{self.data.address} | Неизвестная ошибка при подтверждении выполнения: {error}')

    async def write_to_db(self):
        async with AsyncSession(db.engine) as session:
            await session.merge(self.data)
            await session.commit()

    async def start_login(self):
        signature = 'The wallet will be used for MEME allocation. If you referred friends, family, lovers or ' \
                    'strangers, ensure this wallet has the NFT you referred.\n\nBut also...\n\nNever gonna give ' \
                    'you up\nNever gonna let you down\nNever gonna run around and desert you\nNever gonna make ' \
                    'you cry\nNever gonna say goodbye\nNever gonna tell a lie and hurt you\n\nWallet: ' + \
                    self.eth_client.account.address[:5] + "..." + self.eth_client.account.address[-4:]

        # Кодируем сообщение
        message_encoded = encode_defunct(text=signature)

        signed_message = self.eth_client.account.sign_message(message_encoded)

        headers = {
            'authority': 'memefarm-api.memecoin.org',
            'sec-ch-ua': f'" Not A;Brand";v="99", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'accept': 'application/json',
            'content-type': 'application/json',
            'sec-ch-ua-mobile': '?0',
            'user-agent': self.data.user_agent,
            'sec-ch-ua-platform': f'"{self.data.platform}"',
            'origin': 'https://www.memecoin.org',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'accept-language': 'en-US,en;q=0.9',
        }

        response = await self.async_session.post(
            url='https://memefarm-api.memecoin.org/user/wallet-auth',
            json={
                'address': self.eth_client.account.address,
                'delegate': self.eth_client.account.address,
                'message': signature,
                'signature': signed_message.signature.hex()
            },
            headers=headers
        )

        if response.json().get('error', '') == 'unauthorized':
            logger.error(f'{self.data.address} | not registered')
            return None

        self.bearer_token = response.json()['accessToken']

    async def check_points(self):
        headers = {
            'authority': 'memefarm-api.memecoin.org',
            'sec-ch-ua': f'" Not A;Brand";v="99", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'accept': 'application/json',
            'authorization': f'Bearer {self.bearer_token}',
            'sec-ch-ua-mobile': '?0',
            'user-agent': self.data.user_agent,
            'sec-ch-ua-platform': f'"{self.data.platform}"',
            'origin': 'https://www.memecoin.org',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'accept-language': 'en-US,en;q=0.9',
        }

        response = await self.async_session.get(
            'https://memefarm-api.memecoin.org/user/tasks',
            headers=headers
        )

        self.data.points = response.json().get('points')['current']
