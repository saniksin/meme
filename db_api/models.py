from data.models import AutoRepr
from sqlalchemy import (Column, Integer, Text, Boolean)
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class Wallet(Base, AutoRepr):
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    token = Column(Text)
    private_key = Column(Text, unique=True)
    address = Column(Text)
    proxy = Column(Text)
    user_agent = Column(Text)
    platform = Column(Text)
    twitter_account_status = Column(Text)
    points = Column(Integer)
    captha_solved = Column(Boolean)
    follow_stakeland = Column(Boolean)

    def __init__(
            self,
            token: str,
            private_key: str,
            address: str,
            proxy: str,
            user_agent: str,
            platform: str,
    ) -> None:
        self.token = token
        self.private_key = private_key
        self.address = address
        self.proxy = proxy
        self.user_agent = user_agent
        self.platform = platform
        self.twitter_account_status = "OK"
        self.points = 0
        self.captha_solved = False
        self.follow_stakeland = False
