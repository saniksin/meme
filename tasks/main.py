import traceback
from tasks.eth_tasks import EthTasks
from tasks.twitter_tasks import TwitterTasks
from tasks.gate_withdraw import GateWithdraw
from data.config import logger


async def start_task(account_data, option):
    try:
        if option == 1:
            current_task = TwitterTasks(account_data)
            await current_task.start_tasks()
            try:
                await current_task.async_session.close()
            except TypeError:
                pass
        else:
            current_task = EthTasks(account_data)
            await current_task.start_tasks()
            try:
                await current_task.async_session.close()
            except TypeError:
                pass

    except Exception as error:
        logger.error(f'{account_data.token} | Неизвестная ошибка: {error}')
        print(traceback.print_exc())


async def start_withdraw(account_data):
    current_task = GateWithdraw(account_data)
    await current_task.start_withdraw()
    try:
        await current_task.async_session.close()
    except TypeError:
        pass
