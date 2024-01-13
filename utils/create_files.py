import os
from typing import Union

from data.config import IMPORTANT_FILES, ACCOUNTS_DIR, STATUS_DIR, logger


def join_path(path: Union[str, tuple, list]) -> str:
    if isinstance(path, str):
        return path

    return os.path.join(*path)


def touch(path: Union[str, tuple, list], file: bool = False) -> bool:
    path = join_path(path)
    if file:
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write('')
            logger.info(f'Создан файл {path}')
            return True
        else:
            return False
    else:
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
            return True
        else:
            return False


def create_files():
    touch(ACCOUNTS_DIR)
    touch(STATUS_DIR)
    for path in IMPORTANT_FILES:
        touch(path=path, file=True)
