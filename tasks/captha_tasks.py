from better_automation.base import BaseAsyncSession

from db_api.database import Wallet
from data.config import logger, WEBSITE_URL, HCAPTCHA_KEY, RECAPTCHA_KEY
from settings.settings import CAPMONSTER_API_KEY


class CapthaSolver:

    def __init__(self, account_data: Wallet, session: BaseAsyncSession, bearer_token: str, version) -> None:
        self.data: Wallet = account_data
        self.async_session = session
        self.bearer_token = bearer_token
        self.version = version

    async def recaptcha_solver(self) -> None:
        response = None

        while True:
            try:
                logger.info(f'{self.data.address} | начинаю решение recaptha')
                recaptcha_token: str = await ReCaptchaSolver(
                    account_data=self.data, session=self.async_session).recaptcha_solver()

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

                response = await self.async_session.post(
                    url='https://memefarm-api.memecoin.org/user/verify/recaptcha',
                    headers=headers,
                    json={
                        'code': recaptcha_token
                    })

                if response.json()['status'] == 'success':
                    logger.success(f'{self.data.address} | Успешно решил reCaptcha')
                    return

                msg = f'{self.data.address} | Ошибка при отправки решения reCaptcha, ответ: {response.text}'
                logger.error(msg)

            except Exception as error:
                if response:
                    msg = (f'{self.data.address} | Неизвестная ошибка при решении Google reCaptcha: {error}, '
                           f'ответ: {response.text}')
                    logger.error(msg)

                else:
                    logger.error(f'{self.data.address} | Неизвестная ошибка при решении Google reCaptcha: {error}')

    async def hcaptcha_solver(self) -> None:

        response = None

        while True:
            try:
                logger.info(f'{self.data.address} | начинаю решение hCaptha')
                captcha_response, _ = await HCaptchaSolver(
                    account_data=self.data, session=self.async_session).hcaptcha_solver()

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

                response = await self.async_session.post(
                    url='https://memefarm-api.memecoin.org/user/verify/hcaptcha',
                    json={
                        'code': captcha_response
                    },
                    headers=headers,
                )

                if response.json()['status'] == 'success':
                    logger.success(f'{self.data.address} | Успешно решил hCaptcha')
                    return

                msg = f'{self.data.address} | Ошибка при отправки решения hCaptcha, ответ: {response.text}'
                logger.error(msg)

            except Exception as error:
                if response:
                    msg = (f'{self.data.address} | Неизвестная ошибка при решении Google reCaptcha: {error}, '
                           f'ответ: {response.text}')
                    logger.error(msg)

                else:
                    logger.error(f'{self.data.address} | Неизвестная ошибка при решении Google reCaptcha: {error}')


class HCaptchaSolver:

    def __init__(self, account_data: Wallet, session: BaseAsyncSession) -> None:
        self.data: Wallet = account_data
        self.async_session = session

    async def create_task(self) -> int:
        response = None

        while True:
            try:
                response = await self.async_session.post(
                    url='https://api.capmonster.cloud/createTask',
                    json={
                        'clientKey': CAPMONSTER_API_KEY,
                        'task': {
                            'type': 'HCaptchaTaskProxyless',
                            'websiteURL': WEBSITE_URL,
                            'websiteKey':HCAPTCHA_KEY,
                            'fallbackToActualUA': True
                        }
                    }
                )

                return response.json()['taskId']

            except Exception as error:
                if response:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение hCaptcha: '
                           f'{error}, ответ: {response.text}')
                    logger.error(msg)
                else:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение '
                           f'hCaptcha: {error}')
                    logger.error(msg)

    async def get_task_result(self, task_id: int | str) -> tuple[str, str] | None:
        response = None

        while True:
            try:

                response = await self.async_session.post(
                    url='https://api.capmonster.cloud/getTaskResult',
                    json={
                        'clientKey': CAPMONSTER_API_KEY,
                        'taskId': task_id
                    }
                )

                if response.json()['errorId'] != 0:
                    msg = f'{self.data.address} | ошибка при получении результата ответа, ответ: {response.text}'
                    logger.error(msg)
                    return

                if response.json().get('solution'):
                    return (
                        response.json()['solution']['gRecaptchaResponse'],
                        response.json()['solution']['userAgent']
                    )

            except Exception as error:
                if response:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение hCaptcha: '
                           f'{error}, ответ: {response.text}')
                    logger.error(msg)
                else:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение hCaptcha: '
                           f'{error}')
                    logger.error(msg)

    async def hcaptcha_solver(self) -> tuple[str, str]:
        while True:
            task_id: int = await self.create_task()
            captcha_result: tuple[str, str] | None = await self.get_task_result(task_id=task_id)
            if captcha_result:
                return captcha_result


class ReCaptchaSolver:

    def __init__(self, account_data: Wallet, session: BaseAsyncSession) -> None:
        self.data: Wallet = account_data
        self.async_session = session

    async def create_task(self) -> int:
        response = None

        while True:
            try:
                response = await self.async_session.post(
                    url='https://api.capmonster.cloud/createTask',
                    json={
                       'clientKey': CAPMONSTER_API_KEY,
                       'task': {
                           'type': 'RecaptchaV2Task',
                           'websiteURL': WEBSITE_URL,
                           'websiteKey': RECAPTCHA_KEY
                       }
                    }
                )

                return response.json()['taskId']

            except Exception as error:
                if response:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение reCaptcha: '
                           f'{error}, ответ: {response.text}')
                    logger.error(msg)
                else:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение '
                           f'reCaptcha: {error}')
                    logger.error(msg)

    async def get_task_result(self, task_id: int | str) -> str | None:
        response = None

        while True:
            try:

                response = await self.async_session.post(
                    url='https://api.capmonster.cloud/getTaskResult',
                    json={
                       'clientKey': CAPMONSTER_API_KEY,
                       'taskId': task_id
                   }
                )

                if response.json()['errorId'] != 0:
                    msg = f'{self.data.address} | ошибка при получении результата ответа, ответ: {response.text}'
                    logger.error(msg)
                    return

                if response.json().get('solution'):
                    return response.json()['solution']['gRecaptchaResponse']

            except Exception as error:
                if response:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение reCaptcha: '
                           f'{error}, ответ: {response.text}')
                    logger.error(msg)
                else:
                    msg = (f'{self.data.address} | Неизвестная ошибка при создании задачи на решение '
                           f'reCaptcha: {error}')
                    logger.error(msg)

    async def recaptcha_solver(self) -> str:
        while True:
            task_id: int = await self.create_task()
            captcha_result: str | None = await self.get_task_result(task_id=task_id)
            if captcha_result:
                return captcha_result
