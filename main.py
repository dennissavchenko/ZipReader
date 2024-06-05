import zipfile
import pyminizip
import time
import hashlib
import zlib
import shutil
import requests
import PyPDF2
import re
import os
from tabulate import tabulate
from steganography import encode_message, decode_message
from random_image import generate_random_photo


def query_virustotal(file_hash):
    url = 'https://www.virustotal.com/api/v3/files/' + file_hash
    headers = {'x-apikey': 'd22e40948a39b3cbc3ba5ecb91c2020c70932ad27f45a96839823902f7298d81'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return 404


# The method generates checksum (sha256) for a given file
def generate_checksum(file_path):
    hash_function = hashlib.new('sha256')
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            hash_function.update(data)
    return hash_function.hexdigest()


def write_report(files, keywords):
    file_status_rapport = ["File name", "Checksum (sha256)", "Result"]
    keywords_rapport = ['Keyword', 'Occurrence']
    with open('files/report.txt', 'w') as f:
        f.write('FILE STATUS RAPPORT\n\n')
        f.write(tabulate(files, headers=file_status_rapport))
        f.write(
            "\n\n=================================================================================================\n\n")
        f.write('KEYWORDS RAPPORT\n\n')
        for key in keywords.keys():
            f.write(key + "\n\n")
            f.write(tabulate(keywords[key][:-1], headers=keywords_rapport))
            f.write("\n\nUnique emails:\n")
            for email in keywords[key][-1]:
                f.write(email + '\n')
            f.write('\n')
    print(log("Report is done!"))


# Checking if a string is an email
def is_email(word):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, word) is not None


# Generating keywords rapport for pdf file
def keyword_rapport_pdf(file_name):
    text = ""
    data = []
    emails = []
    pesel = 0
    password = 0
    with open(file_name, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text() + " "
        for word in text.split():
            if word.lower() == 'pesel':
                pesel += 1
            if word.lower() == 'password':
                password += 1
            if is_email(word) and emails.count(word) == 0:
                emails.append(word)
        data.append(["PESEL", str(pesel)])
        data.append(["PASSWORD", str(password)])
        data.append(emails)
    return data


# Generating keywords rapport for txt file
def keyword_rapport_txt(file_name):
    with open(file_name, 'r') as f:
        data = []
        emails = []
        pesel = 0
        password = 0
        for line in f:
            for word in line.split():
                if word.lower() == 'pesel':
                    pesel += 1
                if word.lower() == 'password':
                    password += 1
                if is_email(word) and emails.count(word) == 0:
                    emails.append(word)
        data.append(["PESEL", str(pesel)])
        data.append(["PASSWORD", str(password)])
        data.append(emails)
    return data


# The method lists names of files that were found in a ZIP file
def process_extracted_files():
    print(log("Files extracted from the ZIP file: "))
    files = []
    keywords_info = {}
    # Going through the extracted files from the zip
    for filename in os.listdir('files/extracted_files'):
        file_info = []
        # Checking if the file is a directory
        if os.path.isdir("files/extracted_files/" + filename):
            print(log(filename + " (directory)"))
        else:
            print(log('<> ' + filename))
            file_info.append(filename)
            # Generating checksome for current file
            checksum = generate_checksum("files/extracted_files/" + filename)
            file_info.append(checksum)
            # Querying virustotal for the file analysis
            result = query_virustotal(checksum)
            if result == 404:
                # In case file was not found on virustotal, result is 'unknown'
                file_info.append('unknown')
            else:
                # In case file was found, result is the most common classification of the file
                dictionary = {}
                for key in result['data']['attributes']['last_analysis_results'].keys():
                    d_key = result['data']['attributes']['last_analysis_results'][key]['category']
                    dictionary[d_key] = dictionary.get(d_key, 0) + 1
                file_info.append(max(dictionary, key=dictionary.get))
            files.append(file_info)
            # Looking for keywords in .txt or .pdf files
            if filename.endswith(".txt"):
                keywords_info[filename] = keyword_rapport_txt("files/extracted_files/" + filename)
            elif filename.endswith(".pdf"):
                keywords_info[filename] = keyword_rapport_pdf("files/extracted_files/" + filename)
    write_report(files, keywords_info)
    rapport_hash()


# Logs text to the log.txt file and returns the logged text
def log(text):
    with open('files/log.txt', 'a') as f:
        f.write(text + '\n')
    return text


# Deleting folder executed_files from the previous usage
def delete_folder(folder_path):
    try:
        shutil.rmtree(folder_path)
    except OSError:
        pass


def rapport_hash():
    if os.path.exists("files/report.txt"):
        with open('files/hash.txt', 'w') as f:
            f.write(generate_checksum('files/report.txt'))
        print(log("Report checksum was generated!"))


def pack_zip():
    files = ["files/report.txt", "files/hash.txt"]
    for file in os.listdir("files/extracted_files"):
        if not os.path.isdir("files/extracted_files/" + file):
            files.append("files/extracted_files/" + file)
    try:
        pyminizip.compress_multiple(files, [], "new_zipfile.zip", "P4$$w0rd!", 5)
        print(log("All necessary files were compressed!"))
        image = generate_random_photo()
        encode_message(image, 'Password for the new ZIP file is P4$$w0rd!')
        print('Hidden message:', decode_message('password_clue.png'))
    except OSError as e:
        print(log("Error occurred: " + str(e)))


def read_zip(file_path):
    # Deleting folder executed_files from the previous usage
    delete_folder("files")
    # Checking if the file exists and is a ZIP file
    if zipfile.is_zipfile(file_path):
        # Opening the ZIP file
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            # Trying to read extract files (will work if the ZIP is not protected by a password)
            try:
                zip_file.extractall(path="files/extracted_files")
                print(log("The ZIP file has no password!"))
                process_extracted_files()
                pack_zip()
                return True
            # In case the file is protected an error is thrown
            except RuntimeError as e:
                # Error says that file is encrypted. Start looking for a password
                if "encrypted" in str(e):
                    print(log("File is encrypted. Looking for the password!"))
                    password_found = False
                    # Start time of password searching procedure
                    start_time = time.time()
                    # Opening the 10k-most-common passwords file
                    with open('10k-most-common.txt', 'r') as file:
                        for line in file:
                            # Setting password one by one
                            zip_file.setpassword(line.strip().encode('utf-8'))
                            # Trying to extract files with a current password
                            try:
                                zip_file.extractall(path="files/extracted_files")
                                password_found = True
                                # Printing correct password and time it took to find the work in 10k-most-common.txt
                                print(log('Password for the ZIP file: ' + line.strip() + ' (found in ' + str(
                                    round(time.time() - start_time, 2)) + ' seconds)'))
                                process_extracted_files()
                                pack_zip()
                                break
                            except (RuntimeError, zlib.error, zipfile.BadZipfile):
                                pass
                    if not password_found:
                        print(log("Password was not found."))
                        delete_folder("files/extracted_files")
                        return False
                    else:
                        return True
                else:
                    print(log("Unexpected error"))
                    return False
    else:
        print(log("The file does not exist or is not a ZIP file."))
        return False


read_zip('new_zipfile.zip')
