import re
import random
import traceback

from eth.eth_clients import EthClient
from fake_useragent import UserAgent
from sqlalchemy.ext.asyncio import AsyncSession

from db_api.database import get_account, db
from db_api.models import Wallet
from data.models import logger


class ImportToDB:
    imported = []
    edited = []

    @staticmethod
    async def add_account_to_db(accounts_data: list) -> None:
        async with AsyncSession(db.engine) as session:
            if accounts_data:
                total = len(accounts_data)
                for account in accounts_data:
                    try:
                        token = account['twitter_token'] if account['twitter_token'] else None
                        private_key = account['private_key']
                        proxy = account['proxy']
                        user_agent = UserAgent().chrome
                        platform = random.choice(['macOS', 'Windows', 'Linux'])

                        eth_client = EthClient(private_key=private_key, proxy=proxy, user_agent=user_agent)
                        address = eth_client.account.address

                        if re.match(r'\w' * 63, private_key):
                            wallet_instance = await get_account(private_key=private_key)

                            if wallet_instance:
                                await ImportToDB.update_wallet_instance(
                                    session,
                                    wallet_instance,
                                    token,
                                    private_key,
                                    address,
                                    proxy
                                )
                            elif not wallet_instance:
                                wallet_instance = Wallet(
                                    token=token,
                                    private_key=private_key,
                                    address=address,
                                    proxy=proxy,
                                    user_agent=user_agent,
                                    platform=platform
                                )
                                ImportToDB.imported.append(wallet_instance)
                                session.add(wallet_instance)

                    except Exception as err:
                        logger.error(f'Неизвестная ошибка: {err}')
                        print(traceback.print_exc())

                text = ''
                if ImportToDB.imported:
                    text += (f'\n--- Imported\nN\t{"token & pk":<72}{"address":<16}')
                    for i, wallet in enumerate(ImportToDB.imported):
                        if wallet.token:
                            text += (f'\n{i + 1:<8}{wallet.token:<72}{wallet.address:<16}')
                        else:
                            text += (f'\n{i + 1:<8}{wallet.private_key:<72}{wallet.address:<16}')

                    text += '\n'

                if ImportToDB.edited:
                    text += (f'\n--- Edited\nN\t{"token & pk":<72}{"address":<16}')
                    for i, wallet in enumerate(ImportToDB.edited):
                        if wallet.token:
                            text += (f'\n{i + 1:<8}{wallet.token:<72}{wallet.address:<16}')
                        else:
                            text += (f'\n{i + 1:<8}{wallet.private_key:<72}{wallet.address:<16}')
                    text += '\n'

                print(
                    f'{text}\nDone! {len(ImportToDB.imported)}/{total} wallets were imported, '
                    f'wallet have been changed at {len(ImportToDB.edited)}/{total}.'
                )
                await session.commit()

            else:
                print(f'There are no wallets on the file!')

    @staticmethod
    async def update_wallet_instance(session, wallet_instance, token, private_key, address, proxy):
        has_changed = False
        if wallet_instance.token != token:
            wallet_instance.token = token
            has_changed = True

        if wallet_instance.private_key != private_key:
            wallet_instance.private_key = private_key
            has_changed = True

        if wallet_instance.address != address:
            wallet_instance.address = address
            has_changed = True

        if wallet_instance.proxy != proxy:
            wallet_instance.proxy = proxy
            has_changed = True

        if has_changed:
            ImportToDB.edited.append(wallet_instance)
            await session.merge(wallet_instance)
