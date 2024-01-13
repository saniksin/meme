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

# GATE otp token, нужно для добавления в wl
GATE_OTP = os.getenv('GATE_TOKEN')
TRADE_PASSWORD = os.getenv('TRADE_PASSWORD')
CSRFTOKEN = os.getenv('CSRFTOKEN')
COOKIES = os.getenv('COOKIES')
API_KEY = os.getenv('API_KEY')
SECRET = os.getenv('SECRET')

# MAX_MEME_FEE
MAX_FEE = 150
DELAY_BETWEEN_WITHDRAW = 5