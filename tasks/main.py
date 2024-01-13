import traceback

from tasks.eth_tasks import EthTasks
from tasks.twitter_tasks import TwitterTasks
from data.config import logger


async def start_task(account_data, option):
    try:
        if option == 1:
            tasks = TwitterTasks(account_data)
            await tasks.start_tasks()
            try:
                await tasks.async_session.close()
            except TypeError:
                pass
        else:
            tasks = EthTasks(account_data)
            await tasks.start_tasks()
            try:
                await tasks.async_session.close()
            except TypeError:
                pass

    except Exception as error:
        logger.error(f'{account_data.token} | Неизвестная ошибка: {error}')
        print(traceback.print_exc())
