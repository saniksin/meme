# <a id="public-software-for-starknet"></a>🌐🛠️ Software for Meme-69
<p align="center">Created by <a href="https://t.me/saniksin">Saniksin</a></p>
<p align="center">📱 <a href="https://t.me/cryptosaniksin">Join our Telegram Group</a></p>

## 

# Необходима минимальная версия python: 3.11 и выше

## Описание

Асинхронный софт для meme, делает все на запросах без взаимодейсвия с UI.
<hr>

1. Устанавливаем виртуальное окружение 
   ```
   python3 -m venv venv
   ```

2. Активируем виртуальное окружение
   
   Windows
   ```
   .\venv\Scripts\activate
   ```

   Linux/WSL
   ```
   source venv/bin/activate
   ```

3. Устанавливаем зависимости

   ```
   pip install -r requirements.txt
   ```
   
4. Запускаем скрипт

   ```
   python main.py
   ```
    При первом запуске создадутся все необходимые файлы.

    > - twitter_tokens.txt | токены твиттер (не обязательно)
    > - proxys.txt        | прокси
    > - private_keys.txt  | приватник (обязательно)
    > - problems.txt      | сюда записываются проблемные токены
    > - log.txt           | лог всех сообщений
    > - accounts.db       | база данных sqlite
    > - proxy_problem.txt | сюда записываются только проблемные прокси
    > - low_balance.txt   | cюда записываются кошельки c балансом меньше 69 меме

5. Добавьте токены twitter_tokens.txt, прокси в proxys.txt, приватники в private_keys.txt и запустите скрипт снова.

   > Прокси в формате http://login:password@ip:port

6. В папке settings есть файл settings.py, там можно поставить задержку между действиями и повторное кол-во попыток в случае ошибки, так же добавить API ключ от Capmonster. И прочие настройки...

7. Базу данных можно открыть и посмотреть с помощью программы DB Browser

## Описание

Софт авторизируется по твиттеру или приватному ключу. 

Если вы начнете работу через твиттер, то будет проверено верно ли вы указали приватный ключ и совпадает ли он с твиттер аккаунтом.
Так же при входе через твиттер вы сможете пройти дополнительное задание на 690 поинтов за подписку на @stakeland.

Количество поинтов запишется в db в колонку points.
