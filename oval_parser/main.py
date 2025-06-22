import os
import time
import requests
from bs4 import BeautifulSoup
import bz2


def get_bz2_archive(filename, response):
    '''Функция скачивает архив с описанием уязвимостей'''
    with open(filename, 'wb') as file:
        for data in response.iter_content(chunk_size=64000):
            file.write(data)
        print(f"Download of {filename} completed!", '\n',
              'Starting the parsing!', sep='')


def get_oval_data(filename):
    '''Функция считывает содержимое архива'''
    with bz2.open(filename, 'rt', encoding='utf-8') as raw_data:
        data = raw_data.read()
        return data


def get_metadata(soup):
    '''Функция возвращает элемент metadata из Oval-документа'''
    res_metadata = []
    num = 0
    while num <= 2:
        res_metadata.append(soup.find_all('metadata')[num])
        num += 1
    return res_metadata


def get_criteria(soup):
    '''Функция возвращает элемент criteria из Oval документа'''
    num = 0
    res_criteria = []
    while num <= 2:
        res_criteria.append(soup.find_all('definition')[num].find('criteria'))
        num += 1
    return data_modify(res_criteria)


def data_modify(data):
    '''Функция преобразует selfClosingTag в ClosingTag набора элементов Criteria'''
    old_data = []
    new_data = []
    for num, lst in enumerate(data):
        old_data.append(str(data[num]).split())
    for lst in old_data:
        for line in lst:
            if line[0] == '<' and line[-1] != '>':
                num = lst.index(line)
                new_name = line + '>' + '\n'
                lst.remove(line)
                lst.insert(num, new_name)
    for name in old_data:
        new_data.append(BeautifulSoup(' '.join(name), 'xml'))
    return new_data


def data_save(res_metadata, res_criteria):
    '''Функция сохраняет данные об уязвимостях в текущей директории в текстовом файле'''
    result = f"{filename.split('.')[0]}_{time.strftime('%Y-%m-%d_%H%M%S')}.txt"
    num = 0
    with open(result, 'a') as file:
        while num <= 2:
            file.write(res_metadata[num].text + res_criteria[num].text + '\n\n\n' + '----' * 30)
            num += 1
        print('Got it!', os.path.join(os.getcwd(), result))
        try:
            os.startfile(os.path.join(os.getcwd(), result))
        except FileNotFoundError:
            print('So, linux doesnt support method for open this file, just go to path manually')


def url_status_check(url):
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
        url_status_check(url)


def parser_starter():
    check_file()
    data = get_oval_data(filename)
    soup = BeautifulSoup(data, 'xml')
    res_metadata = get_metadata(soup)
    res_criteria = get_criteria(soup)
    data_save(res_metadata, res_criteria)


if __name__ == "__main__":
    url = 'https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2'
    filename = url.split('/')[-1]
    try:
        parser_starter()
    except KeyboardInterrupt:
        print('Exit from the program...')


