from typing import Optional

from web3 import Web3
from web3.eth import AsyncEth

from data.models import Networks, Network, Wallet, Contracts, Transactions
from eth_account.signers.local import LocalAccount


class EthClient:
    network: Network
    account: Optional[LocalAccount]
    w3: Web3

    def __init__(self, private_key: Optional[str] = None, network: Network = Networks.Ethereum,
                 proxy: Optional[str] = None, user_agent: str = None) -> None:
        self.network = network
        self.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'user-agent': user_agent
        }
        self.proxy = proxy

        self.w3 = Web3(
            provider=Web3.AsyncHTTPProvider(
                endpoint_uri=self.network.rpc,
                request_kwargs={'proxy': self.proxy, 'headers': self.headers}
            ),
            modules={'eth': (AsyncEth,)},
            middlewares=[]
        )

        self.account = self.w3.eth.account.from_key(private_key=private_key)

        self.wallet = Wallet(self)
        self.contracts = Contracts(self)
        self.transactions = Transactions(self)
