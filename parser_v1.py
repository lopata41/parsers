import requests
from bs4 import BeautifulSoup
import bz2
import time
from tqdm import tqdm
import os


def tag_modify(old_tests):
    '''Функция переносит элемент test в новую структуру'''
    new_tests = soup.find('tests').find_all('red-def:rpminfo_test') + soup.find('tests').find_all(
        'red-def:rpmverifyfile_test') + soup.find('tests').find_all('textfilecontent54_test')
    for old_tag in tqdm(old_tests, unit=f' test element of vuln № {num + 1}/{vulns} '):
        for new_tag in new_tests:
            if str(old_tag).split('"')[1] == str(new_tag).split('"')[3]:
                # print(str(old_tag).split('"')[1], str(new_tag).split('"')[3])
                old_tag.append(new_tag)
    for tag in old_tests:
        if tag.text:
            tag.attrs.clear()


def objects_modify(old_objects):
    '''Функция переносит элемент объект object в новую структуру'''
    objects = soup.find('objects').find_all('rpminfo_object') + soup.find('objects').find_all(
        'red-def:rpmverifyfile_object') + soup.find('objects').find_all('textfilecontent54_object')
    for old_obj in tqdm(old_objects, unit=f' object element of vuln № {num + 1}/vulns '):
        for obj in objects:
            if str(old_obj).split('"')[1] == str(obj).split('"')[1]:
                # print(str(old_obj).split('"')[1], str(obj).split('"')[1])
                old_obj.append(obj)
    for obj in old_objects:
        if obj.text:
            obj.attrs.clear()


def states_modify(old_states):
    '''Функция переносит элемент состояние state в новую структуру'''
    states = soup.find('states').find_all('rpminfo_state') + soup.find('states').find_all('red-def:rpmverifyfile_state')
    for old_state in tqdm(old_states, unit=f' state element of vuln № {num + 1}/vulns '):
        for state in states:
            if str(old_state).split('"')[1] == str(state).split('"')[1]:
                # print(str(old_state).split('"')[1], str(state).split('"')[1])
                old_state.clear()
                old_state.append(state)
    for state in old_states:
        if state.text:
            state.attrs.clear()


def parser_starter(num):
    '''Функция запускает основные функции модернизации OVAL файла'''
    old_tests = soup.find_all('definition')[num].find('criteria').find_all('criterion')  # 0-2 первые 3 уязвимости
    tag_modify(old_tests)
    old_objects = soup.find_all('definition')[num].find('criteria').find_all(
        'red-def:object')  # + ('red-def:rpmverifyfile_test')
    old_states = soup.find_all('definition')[num].find('criteria').find_all('red-def:state')
    objects_modify(old_objects)
    states_modify(old_states)


def data_decompose():
    '''Функция стирает лишние/неиспользуемые элементы'''
    for line in soup.find_all('definition')[vulns:]:
        line.decompose()
    soup.objects.decompose()
    soup.states.decompose()
    soup.tests.decompose()


def data_new_oval_save():
    '''Функция записывает полученный файл в текущую директорию и затем открывает его'''
    result = f"new_oval{time.strftime('%Y-%m-%d_%H%M%S')}.xml"
    with open(result, 'w', encoding='utf-8') as file:
        file.write(soup.prettify())
    print(f'Done! {result} is saved')
    try:
        os.startfile(os.path.join(os.getcwd(), result))
    except FileNotFoundError:
        print('So, linux doesnt support method for open this file, try win or just go to path manually')


def get_bz2_archive(filename, response):
    '''Функция скачивает архив с описанием уязвимостей'''
    with open(filename, 'wb') as file:
        for data in response.iter_content(chunk_size=64000):
            file.write(data)
        print(f"Download of {filename} completed!", '\n',
              'Starting the parsing!', sep='')


def get_oval_data():
    '''Функция считывает содержимое архива'''
    with bz2.open(filename, 'rt', encoding='utf-8') as raw_data:
        data = raw_data.read()
        return data


def url_status_check():
    '''Функция проверяет доступность ресурса'''
    try:
        response = requests.get(url, stream=True)
    except requests.exceptions as error:
        print('Oops, something going wrong...', error)
    else:
        if response.status_code == 200:
            print('Starting downloading the file!')
            get_bz2_archive(filename, response)
        else:
            return 'Oops, something going wrong...', \
                   'status code=', response.status_code


def check_file():
    '''Функция проверяет текущую директорию на существование файла'''
    if os.path.exists(filename):
        print(f'file: {filename} is already exist', '\n',
              'Starting the parsing!', sep='')
    else:
        url_status_check()


if __name__ == "__main__":
    url = 'https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2'
    filename = url.split('/')[-1]
    check_file()
    try:
        soup = BeautifulSoup(get_oval_data(), 'xml')
    except Exception as error:
        print(error, 'Check the requirements!')
    vulns = 3
    try:
        for num in range(vulns):
            parser_starter(num)
    except KeyboardInterrupt:
        print('Exit from the program')
    else:
        data_decompose()
        data_new_oval_save()
