import os
from dotenv import load_dotenv

load_dotenv()

# КОЛ-ВО ПОПЫТОК
NUMBER_OF_ATTEMPTS = 10

# Одновременное кол-во асинк семафоров
ASYNC_SEMAPHORE = 50

# WALLET min balance MEME
MIN_BALANCE = 69000000000000000000

# Ключ от капчи
CAPMONSTER_API_KEY = os.getenv('API_KEY')