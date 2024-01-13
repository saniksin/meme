import os
import sys
from pathlib import Path

import asyncio
from loguru import logger


# Определяем путь и устанавливаем root dir
if getattr(sys, 'frozen', False):
    ROOT_DIR = Path(sys.executable).parent.absolute()
else:
    ROOT_DIR = Path(__file__).parent.parent.absolute()


# ETH rpc
ETH_RPC = 'https://rpc.ankr.com/eth'


# Папка accounts
ACCOUNTS_DIR = os.path.join(ROOT_DIR, 'accounts')
TWITTER_TOKENS = os.path.join(ACCOUNTS_DIR, 'twitter_tokens.txt')
PROXYS = os.path.join(ACCOUNTS_DIR, 'proxys.txt')
PRIVATE_KEYS = os.path.join(ACCOUNTS_DIR, 'private_keys.txt')


# Папка status
STATUS_DIR = os.path.join(ROOT_DIR, 'status')
LOG = os.path.join(STATUS_DIR, 'log.txt')
WALLETS_DB = os.path.join(STATUS_DIR, 'accounts.db')
PROBLEMS = os.path.join(STATUS_DIR, 'problems.txt')
PROBLEM_PROXY = os.path.join(STATUS_DIR, 'proxy_problem.txt')
LOW_BALANCE = os.path.join(STATUS_DIR, 'low_balance.txt')
WL_PROBLEM = os.path.join(STATUS_DIR, 'problem_with_add_to_wl.txt')

# Создаем файлы которых не хватает
IMPORTANT_FILES = [TWITTER_TOKENS, PROXYS, PRIVATE_KEYS, LOG, PROBLEMS, PROBLEM_PROXY, LOW_BALANCE, WL_PROBLEM]


# Кол-во выполненных асинхронных задач, блокировщий задач asyncio
completed_tasks = [0]
tasks_lock = asyncio.Lock()


# MEME contracts
MEME_CONTRACT = '0xb131f4A55907B10d1F0A50d8ab8FA09EC342cd74'


# Капча
RECAPTCHA_KEY: str = '6Lf43wspAAAAAI-8g8CuZ6u0BQiDkJ9sbJFelb7J'
HCAPTCHA_KEY: str = '918c0223-e9f6-44e2-b7a0-a13e7fd18fc9'
WEBSITE_URL: str = 'https://www.memecoin.org/farming'


# Логер
logger.add(LOG, format='{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}', level='DEBUG')

# FEE - не трогать!
FEE = [0, 0]