import inquirer
from termcolor import colored
from inquirer.themes import load_theme_from_dict as loadth

from data.config import logger


def get_action() -> str:
    """ Пользователь выбирает действие через меню"""

    # Тема
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    # Варианты для выбора
    question = [
        inquirer.List(
            "action",
            message=colored('Выберете ваше действие', 'light_yellow'),
            choices=[
                '   1) Импорт в базу данных',
                '   2) Войти с помощью твиттера',
                '   3) Войти с помощью приватного ключа',
                '   4) Добавить кошельки в белый список GATE'
            ]
        )
    ]

    return inquirer.prompt(question, theme=loadth(theme))['action']
