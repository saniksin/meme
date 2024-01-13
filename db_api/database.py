from typing import List, Optional
from sqlalchemy.future import select

from db_api import sqlalchemy_
from db_api.models import Wallet, Base
from data.config import WALLETS_DB


db = sqlalchemy_.DB(f'sqlite+aiosqlite:///{WALLETS_DB}', pool_recycle=3600, connect_args={'check_same_thread': False})


async def get_account(private_key: str) -> Optional[Wallet]:
    return await db.one(Wallet, Wallet.private_key == private_key)


async def get_accounts(ignore_problem_twitter: bool = False, gate_whitelist: bool = False) -> List[Wallet]:
    if ignore_problem_twitter:
        query = select(Wallet).where(Wallet.twitter_account_status == "OK", Wallet.token != None)
    elif gate_whitelist:
        query = select(Wallet).where(Wallet.add_to_gate_whitelist == 0)
    else:
        query = select(Wallet)
    return await db.all(query)


async def initialize_db():
    await db.create_tables(Base)