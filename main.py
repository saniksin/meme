import sys
import itertools

import asyncio

from data.config import logger, TWITTER_TOKENS, PROXYS, PRIVATE_KEYS, completed_tasks, tasks_lock
from utils.adjust_policy import set_windows_event_loop_policy
from utils.create_files import create_files
from utils.validate_tokens import validate_token
from utils.user_menu import get_action
from settings.settings import ASYNC_SEMAPHORE
from tasks.main import start_task
from db_api.start_import import ImportToDB
from db_api.models import Wallet
from db_api.database import get_accounts, initialize_db


def get_accounts_info(path):
    with open(path, 'r', encoding='utf-8-sig') as file:
        if path == TWITTER_TOKENS:
            info: list[str] = [validate_token(input_string=row.strip()) for row in file]
        else:
            info: list[str] = [row.strip() for row in file]
    return info


async def start_limited_task(semaphore, accounts, account_data, option=1):
    try:
        async with semaphore:
            await start_task(account_data, option)

            async with tasks_lock:
                completed_tasks[0] += 1
                remaining_tasks = len(accounts) - completed_tasks[0]

            logger.info(f'Всего задач: {len(accounts)}. Осталось задач: {remaining_tasks}')
    except asyncio.CancelledError:
        pass


async def main():
    await initialize_db()

    twitter_tokens: list[str] = get_accounts_info(TWITTER_TOKENS)
    proxies: list[str] = get_accounts_info(PROXYS)
    private_keys: list[str] = get_accounts_info(PRIVATE_KEYS)

    cycled_proxies_list = itertools.cycle(proxies) if proxies else None

    logger.info(f'Загружено в twitter_tokens.txt {len(twitter_tokens)} аккаунтов \n'
                f'\t\t\t\t\t\t\tЗагружено в proxys.txt {len(proxies)} прокси \n'
                f'\t\t\t\t\t\t\tЗагружено в private_keys.txt {len(private_keys)} приватных ключей \n')

    formatted_data: list = [{
            'twitter_token': twitter_tokens.pop(0) if twitter_tokens else None,
            'proxy': next(cycled_proxies_list) if cycled_proxies_list else None,
            'private_key': private_key
        } for private_key in private_keys
    ]

    if not formatted_data:
        logger.error('Вы не добавили данные от аккаунтов необходимые файлы!')
        sys.exit(1)

    user_choice = get_action()

    semaphore = asyncio.Semaphore(ASYNC_SEMAPHORE)

    if user_choice == '   1) Импорт в базу данных':

        await ImportToDB.add_account_to_db(accounts_data=formatted_data)

    elif user_choice == '   2) Войти с помощью твиттера':

        accounts: list[Wallet] = await get_accounts(ignore_problem_twitter=True)
        if len(accounts) != 0:
            tasks = []
            for account_data in accounts:
                task = asyncio.create_task(start_limited_task(semaphore, accounts, account_data))
                tasks.append(task)

            await asyncio.wait(tasks)
        else:
            logger.error(f'Вы не добавили аккаунтов в базу данных либо все аккаунты имеют плохой статус')

    elif user_choice == '   3) Войти с помощью приватного ключа':

        accounts: list[Wallet] = await get_accounts()
        if len(accounts) != 0:
            tasks = []
            for account_data in accounts:
                task = asyncio.create_task(start_limited_task(semaphore, accounts, account_data, option=2))
                tasks.append(task)

            await asyncio.wait(tasks)
        else:
            logger.error(f'Вы не добавили приватники в базу данных!')

    else:
        logger.error('Выбрано неверное действие!')


if __name__ == '__main__':
    #try:
    create_files()
    set_windows_event_loop_policy()
    asyncio.run(main())
    # except (KeyboardInterrupt, TypeError):
    #     logger.info('\n\nПрограмма успешно завершена')