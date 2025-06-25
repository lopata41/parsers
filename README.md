ответы на задание в task_answers



parser.py
Перед запуском установите зависимости:
 Use the command to install dependencies "pip install -r requirements.txt" or 
"pip3 install -r requirements.txt"

Написано на Python 3.9,
проверено на Win10 python 3.10, 3.13
             KaliLinux python 3.12

description
Программа скачивает bz2 архив по ссылке: 'https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2' и преобразует его в новый упрощенный формат
Количество заданных для преобразования уязвимостей = 3
Преобразование выполняется в среднем за ~10 минут на винде, в зависимости от количества изменяемых обьъектов. На линуксе быстрее. Время выполнения оптимизируем в следующий раз :)
