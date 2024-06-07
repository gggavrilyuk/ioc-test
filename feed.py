import requests
import csv
import logging
import os
import subprocess

# Настройка логирования
level = logging.INFO
format_log = "%(asctime)s %(processName)s %(name)-8s %(levelname)s: %(message)s"
if not os.path.exists("./logs/"):
    os.mkdir("./logs/")
logfile = "./logs/script_gts_log.log"
logging.basicConfig(format=format_log, level=level, filename=logfile, filemode='a', encoding='utf-8')
logger = logging.getLogger(__name__)

HEADERS = [
    "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
    "fk_malware", "malware_alias", "malware_printable", "last_seen_utc",
    "confidence_level", "reference", "tags", "anonymous", "reporter"
]

def download_csv(url):
    """
    Загружает CSV данные с указанного URL.
    """
    response = requests.get(url)
    response.raise_for_status()
    logger.info(f"Данные успешно загружены c URL: {url}")
    return response.text

def save_temp_file(content, temp_file_path):
    """
    Сохраняет данные во временный файл.
    """
    #logger.info("Сохранение данных во временный файл")
    with open(temp_file_path, "w", newline='', encoding='utf-8') as temp_file:
        temp_file.write(content)
    #logger.info("Данные сохранены во временный файл")

def extract_last_updated_line(temp_file_path):
    """
    Извлекает строку с датой последнего обновления из временного файла.
    """
    #logger.info("Извлечение строки с датой последнего обновления")
    last_updated_line = None
    with open(temp_file_path, "r", newline='', encoding='utf-8') as temp_file:
        for line in temp_file:
            if line.startswith("# Last updated:"):
                last_updated_line = line.strip()
                break
    logger.info(f"Строка с датой последнего обновления: {last_updated_line}")
    return last_updated_line

def write_to_file(file_path, headers, data):
    """
    Записывает данные в указанный файл, удаляя экранирование кавычек.
    """
    #logger.info(f"Запись данных в файл {file_path}")
    file_exists = os.path.isfile(file_path)
    with open(file_path, "a", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(headers)
        writer.writerow([field.replace('"', '') for field in data])
    #logger.info(f"Данные успешно записаны в файл {file_path}")

def remove_duplicates(file_path):
    """
    Удаляет дублирующиеся строки из файла на основании значения ioc_value.
    """
    #logger.info(f"Удаление дубликатов в файле {file_path}")
    if not os.path.isfile(file_path):
        return

    unique_values = set()
    rows = []

    with open(file_path, "r", newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        headers = next(reader)
        for row in reader:
            ioc_value = row[2].strip()
            if ioc_value not in unique_values:
                unique_values.add(ioc_value)
                rows.append(row)

    with open(file_path, "w", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)
    #logger.info(f"Дубликаты успешно удалены из файла {file_path}")

def process_csv(temp_file_path):
    """
    Обрабатывает CSV файл и записывает строки в соответствующие файлы в зависимости от значения поля 'ioc_type'.
    """
    #logger.info("Обработка данных из временного файла")
    try:
        with open(temp_file_path, "r", newline='', encoding='utf-8') as temp_file:
            csv_reader = csv.reader(temp_file)
            for row in csv_reader:
                if row[0].startswith("#"):
                    continue  # Пропуск строк, начинающихся с символа #
                if len(row) < 4:
                    logger.warning(f"Пропущена строка: {row}. Неверное количество элементов")
                    continue

                # Обработка ioc_value и ioc_type для удаления данных после :
                row[2] = row[2].split(':')[0]
                row[3] = row[3].split(':')[0]

                ioc_type = row[3].replace('"', '').strip()  # Удаление экранированных кавычек и лишних пробелов
                file_name = f"{ioc_type}_threats.csv"
                write_to_file(file_name, HEADERS, row)
                remove_duplicates(file_name)  # Удаление дубликатов после записи
    except Exception as e:
        logger.error(f"Ошибка при обработке CSV файла: {e}")


def git_commit_and_push(last_updated_line):
    """
    Коммитит и пушит изменения в репозиторий GitHub.
    """
    #logger.info("Коммит и пуш изменений в репозиторий GitHub")
    try:
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run(["git", "commit", "-m", f"{last_updated_line}"], check=True)
        subprocess.run(["git", "push", "origin", "main"], check=True)
        #logger.info("Изменения успешно запушены в репозиторий")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка при выполнении команды git: {e}")


def main():
    url = "https://threatfox.abuse.ch/export/csv/recent/"
    temp_file_path = "recent_threats_temp.csv"

    try:
        csv_content = download_csv(url)
        save_temp_file(csv_content, temp_file_path)
        last_updated_line = extract_last_updated_line(temp_file_path)

        process_csv(temp_file_path)
        print(f"Данные успешно сохранены в соответствующие файлы\n{last_updated_line}")
        
       # git_commit_and_push(last_updated_line)  # Коммит и пуш 

        
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
    
   
if __name__ == "__main__":
    main()
