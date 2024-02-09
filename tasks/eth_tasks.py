import traceback

import asyncio
import aiofiles
from better_automation.base import BaseAsyncSession
from eth_account.messages import encode_defunct
from sqlalchemy.ext.asyncio import AsyncSession
from curl_cffi.requests.errors import RequestsError

from db_api.database import Wallet, db
from eth.eth_clients import EthClient
from data.config import MEME_CONTRACT, logger, PROBLEM_PROXY, LOW_BALANCE, FINISHED, VERIFICATION, BEARER_TOKEN, RESULT
from settings.settings import MIN_BALANCE, NUMBER_OF_ATTEMPTS
from tasks.captha_tasks import CapthaSolver


class EthTasks:
    write_lock = asyncio.Lock()

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
        #self.write_lock = asyncio.Lock()

    async def check_meme_balance(self):
        return await self.eth_client.wallet.balance(
            token_address=MEME_CONTRACT,
            address=self.eth_client.account.address
        )
    
    async def start_check_result(self):
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                logger.info(f'{self.data.address} | Попытка {num}')

                # логинимся
                await self.start_login()

                status = await self.chech_meme_farming_result()
                if status:
                    logger.info(f'{self.data.address} | успешно получил статус')
                    return 
                else:
                    logger.error(f'{self.data.address} | не смог получить статус')
                    continue
            
            except RequestsError:
                logger.error(f'{self.data.address} | проблема с прокси! Проверьте прокси!')
                await self.write_status(status="proxy problem", path=PROBLEM_PROXY)
                continue

            except Exception as error:
                logger.error(f'{self.data.address} | неизвестная ошибка: {error}')
                print(traceback.print_exc())

    async def chech_meme_farming_result(self):
        headers = {
            'authority': 'memefarm-api.memecoin.org',
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': f'Bearer {self.bearer_token}',
            'origin': 'https://www.memecoin.org',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.data.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.data.user_agent,
        }

        response = await self.async_session.get(
            'https://memefarm-api.memecoin.org/user/results', 
            headers=headers
        )

        if response.status_code == 200:
            answer = response.json()
            async with EthTasks.write_lock:
                if answer.get('results', [])[0].get('won', False):
                    RESULT[0] += 1
                    return True
                else:
                    RESULT[1] += 1
                    return True
        return False


    async def start_tasks(self):

        if self.data.captha_solved:
            self.data.completed = True
            await self.write_to_db()
            return

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

                if self.data.captha_solved:
                    self.data.completed = True
                    await self.write_to_db()
                    logger.success(f'{self.data.address} | успешно закончил все задания!')
                    return

                break

            except RequestsError:
                logger.error(f'{self.data.address} | проблема с прокси! Проверьте прокси!')
                await self.write_status(status="proxy problem", path=PROBLEM_PROXY)
                continue

            except Exception as error:
                logger.error(f'{self.data.address} | неизвестная ошибка: {error}')
                print(traceback.print_exc())

    async def start_check_stats(self):
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                # логинимся
                await self.start_login()
                await self.check_verification_level()

                break
            except RequestsError:
                logger.error(f'{self.data.address} | проблема с прокси! Проверьте прокси!')
                await self.write_status(status="proxy problem", path=PROBLEM_PROXY)
                continue

            except Exception as error:
                logger.error(f'{self.data.address} | неизвестная ошибка: {error}')
                print(traceback.print_exc())
                continue

    async def start_write_bearer_tokens(self):
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                logger.info(f'{self.data.address} | начинаю сбор bearer токенов. Попытка {num}')
                await self.start_login()
                if self.bearer_token:
                    await self.write_status("None", BEARER_TOKEN)
                    logger.success(f'{self.data.address} | закончил сбор bearer токенов')
                    break
                continue
            except RequestsError:
                logger.error(f'{self.data.address} | проблема с прокси! Проверьте прокси!')
                await self.write_status(status="proxy problem", path=PROBLEM_PROXY)
                continue

            except Exception as error:
                logger.error(f'{self.data.address} | неизвестная ошибка: {error}')
                print(traceback.print_exc())
                continue

    async def check_verification_level(self):

        headers = {
            'authority': 'memefarm-api.memecoin.org',
            'accept': 'application/json',
            'accept-language': 'ru-RU,ru;q=0.9,uk;q=0.8',
            'authorization': f'Bearer {self.bearer_token}',
            'origin': 'https://www.memecoin.org',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.data.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.data.user_agent,
        }

        response = await self.async_session.get(
            'https://memefarm-api.memecoin.org/user/info',
            headers=headers
        )

        if response.status_code == 200:
            logger.info(f'{self.data.address} | успешно собрал статистку')
            response_answer = response.json()
            async with EthTasks.write_lock:
                if response_answer["verification"] == 2:
                    FINISHED[0] += 1
                elif response_answer["verification"] == 1:
                    FINISHED[1] += 1
                    await self.write_status("Не полная верификация | 1", VERIFICATION)
                elif response_answer["verification"] == 0:
                    FINISHED[2] += 1
                    await self.write_status("Не проходил капчу | 0", VERIFICATION)
            return
        FINISHED[3] += 1
        await self.write_status("Не смог собрать статистику | NONE", VERIFICATION)
        logger.warning(f'{self.data.address} | не смог собрать статистику')
        return

    async def write_status(self, status, path):
        """ Записывает текщий статус проблемного токена в соответсвующий файл """

        async with EthTasks.write_lock:
            async with aiofiles.open(file=path, mode='a', encoding='utf-8-sig') as f:
                if status == "proxy problem":
                    await f.write(f'{self.data.proxy}\n')
                elif status == "low balance":
                    await f.write(f'{self.eth_client.account.address}\n')
                elif path == VERIFICATION:
                    await f.write(f'{self.eth_client.account.address} | {status}\n')
                elif path == BEARER_TOKEN:
                    await f.write(f'Bearer {self.bearer_token}\n')
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
