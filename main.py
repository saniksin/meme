import sys
import itertools
from datetime import datetime

import asyncio
import time
from tqdm import tqdm

from data.config import logger, TWITTER_TOKENS, PROXYS, PRIVATE_KEYS, completed_tasks, tasks_lock, FEE
from utils.adjust_policy import set_windows_event_loop_policy
from utils.create_files import create_files
from utils.validate_tokens import validate_token
from utils.user_menu import get_action
from settings.settings import ASYNC_SEMAPHORE, MAX_FEE, DELAY_BETWEEN_WITHDRAW
from tasks.main import start_task, start_withdraw
from tasks.gate_whitelist import GateAddWhitelist
from db_api.start_import import ImportToDB
from db_api.models import Wallet
from db_api.database import get_accounts, initialize_db
from tasks.gate_withdraw import GateWithdraw


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

    elif user_choice == '   4) Добавить кошельки в белый список GATE':

        accounts: list[Wallet] = await get_accounts(gate_whitelist=True)
        if len(accounts) != 0:
            total_accounts = len(accounts)
            batch_size = 10
            batch_count = int(total_accounts / batch_size) + 1
            total_num = 0

            logger.info('Начинаю добавлять аккаунты пачками по 10 штук')
            for start_idx in range(0, total_accounts, batch_size):
                end_idx = min(start_idx + batch_size, total_accounts)
                current_batch = accounts[start_idx:end_idx]
                total_num += 1
                logger.info(f'{total_num}/{batch_count} батчей по 10 кошельков')

                if len(current_batch) == 10:
                    await GateAddWhitelist(
                        account_data=current_batch,
                        batch_num=total_num
                    ).start_add_whitelisted_task()
                    sleep_time = 31
                    logger.info(f'я буду спать {sleep_time}')
                    for _ in tqdm(range(sleep_time), desc="СОН: "):
                        time.sleep(1)
                else:
                    for tasks in current_batch:
                        await GateAddWhitelist(
                            account_data=tasks,
                            batch_num=total_num
                        ).start_add_whitelisted_one_by_one_task()
                        sleep_time = 31
                        logger.info(f'я буду спать {sleep_time}. Последние акки добавляем по одному!')
                        for _ in tqdm(range(sleep_time), desc="СОН: "):
                            time.sleep(1)
        else:
            logger.error(f'Вы не добавили приватники в базу данных!')

    elif user_choice == '   5) Вывод с GATE':
        accounts: list[Wallet] = await get_accounts(withdraw=True)
        if len(accounts) != 0:

            current_time = datetime.now().strftime("%H:%M")
            if current_time[-2:] in ["59", "00", "01"]:

                logger.info('Текущее время перед обновлением комиссии! Ухожу на сон до 180 секунд')
                if current_time[-2:] == "59":
                    sleep_time = 180
                elif current_time[-2:] == "00":
                    sleep_time = 120
                else:
                    sleep_time = 60

                for _ in tqdm(range(sleep_time), desc="СОН: "):
                    time.sleep(1)

            gate = GateWithdraw(accounts[0])
            fee, disabled = await gate.get_withdrawal_fee()
            FEE = [fee, disabled]

            while fee > MAX_FEE:
                sleep_time = ((61 - int(current_time[-2:])) * 60)
                logger.info(f'Текущая fee: {fee} | settings max fee {MAX_FEE}. Сон до следующего часа')
                for _ in tqdm(range(sleep_time), desc="СОН: "):
                    time.sleep(1)
                fee, disabled = await gate.get_withdrawal_fee()
                FEE = [fee, disabled]

            task_counter = 0
            for account_data in accounts:
                task_counter += 1
                logger.info(f'Вывод на {task_counter} из {len(accounts)} кошельков. Текущая комиссия {FEE[0]}')
                await start_withdraw(account_data)
                for _ in tqdm(range(DELAY_BETWEEN_WITHDRAW), desc="СОН: "):
                    time.sleep(1)
        else:
            logger.error(f'Вы не добавили приватники в базу данных!')

    else:
        logger.error('Выбрано неверное действие!')


if __name__ == '__main__':
    try:
        create_files()
        set_windows_event_loop_policy()
        asyncio.run(main())
    except (KeyboardInterrupt, TypeError):
        logger.info('\n\nПрограмма успешно завершена')