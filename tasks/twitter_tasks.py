import re
import traceback

import asyncio
import aiofiles
from better_automation.twitter import TwitterClient, TwitterAccount
from better_automation.base import BaseAsyncSession
from better_automation.twitter.errors import Forbidden, Unauthorized
from curl_cffi.requests.errors import RequestsError
from sqlalchemy.ext.asyncio import AsyncSession
from bs4 import BeautifulSoup

from db_api.models import Wallet
from settings.settings import NUMBER_OF_ATTEMPTS, MIN_BALANCE
from data.config import logger, PROBLEMS, PROBLEM_PROXY, LOW_BALANCE
from db_api.database import db
from tasks.eth_tasks import EthTasks
from tasks.captha_tasks import CapthaSolver


class TwitterTasks:

    def __init__(self, account_data: Wallet) -> None:

        # account_info
        self.data = account_data

        # Сессии
        self.async_session: BaseAsyncSession = BaseAsyncSession(proxy=self.data.proxy, verify=False)
        self.twitter_client: TwitterClient | None = None
        self.twitter_account: TwitterAccount = TwitterAccount(self.data.token)
        self.twitter_name = None
        self.bearer_token = None

        # Статусы
        self.register = True

        self.eth_tasks = EthTasks(account_data)
        self.api_answer_address = None

        self.write_lock = asyncio.Lock()
        self.version = self.data.user_agent.split('Chrome/')[1].split('.')[0]
        self.old_points_balance = self.data.points

    async def start_tasks(self):

        if self.data.captha_solved and self.data.follow_stakeland:
            self.data.completed = True
            await self.write_to_db()
            return

        # Количество попыток в случае неудачи
        for num, _ in enumerate(range(NUMBER_OF_ATTEMPTS), start=1):
            try:
                logger.info(f'{self.twitter_account} | Попытка {num}')
                async with TwitterClient(
                        account=self.twitter_account,
                        proxy=self.data.proxy,
                        verify=False
                ) as twitter:

                    self.twitter_client = twitter

                    try:
                        await self.get_name()
                    except Unauthorized:
                        msg = (f'{self.twitter_account} | Не удалось авторизироваться по данному токену! '
                               f'Проверьте токен.')
                        logger.error(msg)
                        await self.raise_error('BAD_TOKEN')
                        break

                    except Forbidden:
                        if self.twitter_account.status != 'GOOD':
                            msg = (f'{self.twitter_account} | Возникла проблема с аккаунтом!'
                                   f' Текущий статус аккаунта = {self.twitter_account.status}')
                            logger.error(msg)

                            if self.twitter_account.status == 'SUSPENDED':
                                msg = f'Действие учетной записи приостановлено (бан)! Токен - {self.twitter_account}'
                                logger.warning(msg)
                                await self.raise_error('SUSPENDED')
                                break

                            elif self.twitter_account.status == "LOCKED":
                                msg = (f'Учетная запись заморожена (лок)! Требуется прохождение капчи. '
                                       f'Токен - {self.twitter_account}')
                                logger.warning(msg)
                                await self.raise_error('LOCKED')
                                break

                    # Авторизируемся и записываем поинты в бд, проверяем совпадают ли кошельки
                    self.data.points, status = await self.login_via_twitter()
                    if status:
                        if isinstance(self.data.points, int):
                            if self.data.points != 0 and self.data.points != self.old_points_balance:
                                await self.write_to_db()
                        msg = (f'{self.twitter_account} | успешно авторизировался | адреса совпадают | '
                               f'количество поинтов {self.data.points}')
                        logger.success(msg)
                    else:
                        logger.error(f'{self.twitter_account} | не смог авторизироватся или не был зарегистрирован раньше!')
                        break

                    actual_meme_balance = await self.eth_tasks.check_meme_balance()
                    logger.info(f'{self.twitter_account} | текущий баланс токенов: {actual_meme_balance.Ether} MEME')
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
                                logger.success(f'{self.twitter_account} | успешно закончил с капчей!')
                            else:
                                logger.error(f'{self.twitter_account} | не смог подтвердить капчу')
                                continue
                        else:
                            logger.warning(f'{self.data.address} | уже закончил проходить капчу')
                    else:
                        msg = f'{self.twitter_account} | не достаточный баланс токенов. Необходимо минимум 69 токенов!'
                        await self.write_status(status="low balance", path=LOW_BALANCE)
                        logger.error(msg)
                        break

                    if not self.data.follow_stakeland:
                        status = await self.follow_quest("stakeland")
                        if status:
                            logger.success(f'{self.twitter_account} | успешно подписался на @stakeland')
                            self.data.follow_stakeland = 1
                            await self.write_to_db()
                        else:
                            logger.warning(f'{self.twitter_account} | не смог подписаться на @stakeland')

                    if self.data.captha_solved and self.data.follow_stakeland:
                        self.data.completed = True
                        await self.write_to_db()
                        logger.success(f'{self.twitter_account} | успешно закончил все задания')
                        return

                    break

            except RequestsError:
                logger.error(f'{self.twitter_account} | проблема с прокси! Проверьте прокси!')
                await self.write_status(status="proxy problem", path=PROBLEM_PROXY)
                continue

            except Exception as error:
                logger.error(f'{self.twitter_account} | неизвестная ошибка: {error}')
                print(traceback.print_exc())

    async def follow_quest(self, username: str):
        """ Подписываемся на пользователя """
        user_info = await self.twitter_client.request_user_data(username)
        status = await self.twitter_client.follow(user_id=user_info.id)
        if status:
            status = await self.follow_confirm()
            if status:
                return True
        return False

    async def follow_confirm(self):
        headers = {
            'authority': 'memefarm-api.memecoin.org',
            'sec-ch-ua': f'" Not A;Brand";v="99", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'accept': 'application/json',
            'content-type': 'application/json',
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

        json_data = {
            'followId': 'followStakeland',
        }

        response = await self.async_session.post(
            'https://memefarm-api.memecoin.org/user/verify/twitter-follow',
            headers=headers,
            json=json_data
        )

        if response.json()['status'] in ['success', 'reward_already_claimed']:
            return True
        return False

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
                    msg = f'{self.twitter_account} | Неизвестная ошибка при подтверждении выполнения: ' \
                          f'{error}, ответ: {response.text}'
                    logger.error(msg)

                else:
                    logger.error(f'{self.twitter_account} | Неизвестная ошибка при подтверждении выполнения: {error}')

    async def login_via_twitter(self):
        wallet = False

        headers = {
            'authority': 'memefarm-api.memecoin.org',
            'sec-ch-ua': f'" Not A;Brand";v="99", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.data.platform}"',
            'upgrade-insecure-requests': '1',
            'user-agent': self.data.user_agent,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            'accept-language': 'en-US,en;q=0.9',
        }

        params = {
            'callback': 'https://www.memecoin.org/farming',
        }

        response = await self.async_session.get(
            'https://memefarm-api.memecoin.org/user/twitter-auth',
            params=params,
            headers=headers
        )

        soup = BeautifulSoup(response.text, 'html.parser')
        oauth_token_input = soup.find('input', {'name': 'oauth_token'})
        oauth_token = oauth_token_input['value'] if oauth_token_input else None

        self.async_session.cookies.update({
            'auth_token': self.data.token,
            'ct0': self.twitter_account.ct0
        })

        headers = {
            'authority': 'api.twitter.com',
            'upgrade-insecure-requests': '1',
            'user-agent': self.data.user_agent,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            'sec-ch-ua': f'" Not A;Brand";v="99", "Chromium";v="{self.version}", "Google Chrome";v="{self.version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.data.platform}"',
            'accept-language': 'en-US,en;q=0.9',
        }

        params = {
            'oauth_token': oauth_token,
        }

        response = await self.async_session.get(
            'https://api.twitter.com/oauth/authenticate',
            params=params,
            headers=headers
        )

        soup = BeautifulSoup(response.text, 'html.parser')
        try:
            meta_tag = soup.find('meta', {'http-equiv': 'refresh'})
            url_content = meta_tag['content']
        except TypeError:
            await self.raise_error('NOT_REGISTER')
            return False, False
        oauth_verifier_match = re.search(r'oauth_verifier=([^&]+)', url_content)
        oauth_verifier_value = oauth_verifier_match.group(1) if oauth_verifier_match else None

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
            'accept-language':  'en-US,en;q=0.9',
        }

        json_data = {
            'oauth_token': oauth_token,
            'oauth_verifier': oauth_verifier_value,
        }

        response = await self.async_session.post(
            'https://memefarm-api.memecoin.org/user/twitter-auth1',
            headers=headers,
            json=json_data
        )

        self.bearer_token = response.json().get('accessToken')

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
            'https://memefarm-api.memecoin.org/user/info',
            headers=headers
        )

        self.api_answer_address = response.json().get('wallet')
        if self.api_answer_address == self.eth_tasks.eth_client.account.address:
            wallet = True
        else:
            await self.raise_error('WRONG_ADDRESS')
            return False, False

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

        return response.json().get('points')['current'], wallet

    async def raise_error(self, status):
        await self.write_to_db(status=status)
        await self.write_status(status=status)

    async def write_to_db(self, status="OK"):
        async with AsyncSession(db.engine) as session:
            self.data.twitter_account_status = status
            await session.merge(self.data)
            await session.commit()

    async def write_status(self, status, path=PROBLEMS):

        """ Записывает текщий статус проблемного токена в соответсвующий файл """

        async with self.write_lock:
            async with aiofiles.open(file=path, mode='a', encoding='utf-8-sig') as f:
                if status == "WRONG_ADDRESS":
                    await f.write(f'{self.data.token} | DB addr: {self.data.address} | API addr: '
                                  f'{self.api_answer_address} | {status}\n')
                elif status == "proxy problem":
                        await f.write(f'{self.data.proxy}\n')
                elif status == "low balance":
                    await f.write(f'{self.eth_tasks.eth_client.account.address}\n')
                else:
                    await f.write(f'{self.data.token} | {self.data.proxy} | {self.data.private_key} | {status}\n')

    async def get_name(self):
        """ Возвращает никнейм пользователя, не username """

        await self.twitter_client.request_username()
        await self.twitter_client._request_user_data(self.twitter_account.username)

        return True