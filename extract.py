import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Util import Counter

DEFAULT_BACKUP_DIR = Path('.')

parser = argparse.ArgumentParser(
    description="Decrypts a password-protected Huawei backup database when the password is known.")
parser.add_argument("-i", "--input", type=str, help="Backup directory", required=False, default=DEFAULT_BACKUP_DIR)
parser.add_argument("-p", "--password", type=str, help="Password", required=True)
parser.add_argument("-o", "--output", type=str, help="Decrypted database output filepath", required=False, default=None)
args = parser.parse_args()

backup_dir = Path(args.input)
password = args.password
decrypted_db_filepath = args.output

if decrypted_db_filepath is not None:
    decrypted_db_filepath = Path(decrypted_db_filepath)

ROW_TABLES = [
    "HeaderInfo",
    "BackupFilePhoneInfo",
    "BackupFileVersionInfo",
    "BackupFilesTypeInfo",
    "BackupFileModuleInfo_SystemData"
]

DEFAULT_ENCRYPTED_DB_FILENAME = "{}.db"
DEFAULT_DECRYPTED_DB_FILENAME = "{}-decrypted.db"

HASH_NAME = 'sha256'
ITERATION = 5000

def extract(col):
    assert len(col) == 1
    val_tag = col[0]
    assert val_tag.tag == "value"
    return val_tag

def extract_string(col):
    val_tag = extract(col)
    return val_tag.attrib["String"]

def extract_integer(col):
    val_tag = extract(col)
    return int(val_tag.attrib["Integer"])

assert backup_dir.exists()

info_xml_filepath = Path(backup_dir, "info.xml")
assert info_xml_filepath.exists() and info_xml_filepath.is_file()

tree = ET.parse(info_xml_filepath)
root = tree.getroot()

rows = [row for row in root]

for i in range(len(rows)):
    assert rows[i].attrib["table"] == ROW_TABLES[i]

header_info, backup_file_phone_info,\
backup_file_version_info, backup_files_type_info,\
backup_file_module_info_system_data,\
    = rows

backup_files_type_info_col_dict = {child.attrib["name"]: child for child in backup_files_type_info}

type_attch_col = backup_files_type_info_col_dict["type_attch"]
check_msg_col = backup_files_type_info_col_dict["checkMsg"]
type_attch = extract_integer(type_attch_col)
check_msg_hex = extract_string(check_msg_col)

backup_file_module_info_system_data_col_dict = {child.attrib["name"]: child for child in backup_file_module_info_system_data}

enc_msg_v3_col = backup_file_module_info_system_data_col_dict["encMsgV3"]
db_name_col = backup_file_module_info_system_data_col_dict["name"]
enc_msg_v3_hex = extract_string(enc_msg_v3_col)
db_name = extract_string(db_name_col)

encrypted_db_filepath = Path(backup_dir, DEFAULT_ENCRYPTED_DB_FILENAME.format(db_name))
assert encrypted_db_filepath.exists() and encrypted_db_filepath.is_file()

encryption_key_extracted_hex = check_msg_hex[:64]
encryption_salt_hex = check_msg_hex[-64:]

decryption_salt_hex = enc_msg_v3_hex[:64]
decryption_counter_init_hex = enc_msg_v3_hex[-32:]

password_bytes = bytes(password, 'utf-8')
encryption_salt = unhexlify(encryption_salt_hex)
encryption_key_computed = pbkdf2_hmac(HASH_NAME, password_bytes, encryption_salt, ITERATION)

encryption_key_extracted = unhexlify(encryption_key_extracted_hex)
try:
    assert encryption_key_computed == encryption_key_extracted
except AssertionError:
    encryption_key_computed_hex = str(hexlify(encryption_key_computed), 'utf-8')
    raise Exception("Computed encryption key ({}) does not match extracted encryption key ({}) - password is incorrect."
                    .format(encryption_key_computed_hex, encryption_key_extracted_hex))

decryption_salt = unhexlify(decryption_salt_hex)
decryption_key_computed = pbkdf2_hmac(HASH_NAME, password_bytes, decryption_salt, ITERATION)

decryption_counter_init_bytes = unhexlify(decryption_counter_init_hex)
decryption_counter_init = int.from_bytes(decryption_counter_init_bytes, byteorder='big')
decryption_counter = Counter.new(128, initial_value=decryption_counter_init)
cipher = AES.new(decryption_key_computed, AES.MODE_CTR, counter=decryption_counter)

if decrypted_db_filepath is None:
    decrypted_db_filepath = Path(backup_dir, DEFAULT_DECRYPTED_DB_FILENAME.format(db_name))

with open(encrypted_db_filepath, 'rb') as encrypted_db_file:
    encrypted_db_data = encrypted_db_file.read()

decrypted_db_data = cipher.decrypt(encrypted_db_data)

with open(decrypted_db_filepath, 'wb') as decrypted_db_file:
    decrypted_db_file.write(decrypted_db_data)