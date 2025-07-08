from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
if not os.path.exists('keys'):
    os.makedirs('keys')

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
password_input = input("enter the password:").encode() # هنا عشان اضيف كلمة سر و يتم طلب كلمة مرور من المستخدم 

import shutil

#  Key Rotation تدوير المفاتيح 
def rotate_keys():
    if not os.path.exists('keys/old'):
        os.makedirs('keys/old')
    if os.path.exists('keys/private_key.pem'):
        shutil.move('keys/private_key.pem', 'keys/old/private_key_old.pem')
    if os.path.exists('keys/public_key.pem'):
        shutil.move('keys/public_key.pem', 'keys/old/public_key_old.pem')
    print(" Key rotation done, old keys moved to keys/old/.")

rotate_keys()



# توليد المفتاح الخاص
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# استخراج المفتاح العام
public_key = private_key.public_key()


# حفظ المفتاح الخاص
with open("keys/private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password_input)
        )
    )


# حفظ المفتاح العام
with open("keys/public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
             
        )
    )

print("تم توليد وحفظ المفاتيح بنجاح!")



# توليد مفتاح AES (256 بت = 32 بايت)
aes_key = secrets.token_bytes(32)

# توليد IV (لازم يكون 16 بايت)
iv = secrets.token_bytes(16)

print("تم توليد مفتاح AES و IV بنجاح!")

def encrypt_data(data, aes_key, iv):
    # نضيف Padding عشان حجم البيانات يصير مناسب للتشفير
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # نحدد خوارزمية AES بوضع CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # تشفير البيانات
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# تأكد من وجود مجلد encrypted
if not os.path.exists('encrypted'):
    os.makedirs('encrypted')

# تشفير ملف fake_data.json
with open('test_data/fake_data.json', 'rb') as f:
    file_data = f.read()

encrypted_file_data = encrypt_data(file_data, aes_key, iv)

# حفظ الملف المشفر
with open('encrypted/encrypted_fake_data.bin', 'wb') as f:
    f.write(encrypted_file_data)

# تشفير ملف fake_message.txt
with open('test_data/fake_message.txt', 'rb') as f:
    file_message = f.read()

encrypted_file_message = encrypt_data(file_message, aes_key, iv)

# حفظ الملف المشفر
with open('encrypted/encrypted_fake_message.bin', 'wb') as f:
    f.write(encrypted_file_message)

print("تم تشفير الملفات بنجاح!")

from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

# تشفير مفتاح AES بالمفتاح العام
encrypted_aes_key = public_key.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# حفظ مفتاح AES المشفر
with open('encrypted/encrypted_aes_key.bin', 'wb') as f:
    f.write(encrypted_aes_key)

# حفظ IV
with open('encrypted/iv.bin', 'wb') as f:
    f.write(iv)

print("تم تشفير وحفظ مفتاح AES و IV بنجاح!")


# 
with open('keys/private_key.pem', 'rb') as f:
    private_key_loaded = serialization.load_pem_private_key(
        f.read(),
        password=password_input,
  #هنا عدلت مفتاح الحمايه 
        backend=default_backend()
    )

with open('encrypted/encrypted_aes_key.bin', 'rb') as f:
    encrypted_aes_key = f.read()

decrypted_aes_key = private_key_loaded.decrypt(
    encrypted_aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open('encrypted/iv.bin', 'rb') as f:
    iv_loaded = f.read()

print("تم فك تشفير مفتاح AES و IV بنجاح!")

# دالة فك التشفير
def decrypt_data(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

# فك تشفير fake_data.json
with open('encrypted/encrypted_fake_data.bin', 'rb') as f:
    encrypted_file_data = f.read()

decrypted_file_data = decrypt_data(encrypted_file_data, decrypted_aes_key, iv_loaded)

with open('decrypted_fake_data.json', 'wb') as f:
    f.write(decrypted_file_data)

# فك تشفير fake_message.txt
with open('encrypted/encrypted_fake_message.bin', 'rb') as f:
    encrypted_file_message = f.read()

decrypted_file_message = decrypt_data(encrypted_file_message, decrypted_aes_key, iv_loaded)

with open('decrypted_fake_message.txt', 'wb') as f:
    f.write(decrypted_file_message)

print("تم فك تشفير الملفات بنجاح!") 
# هنا راح نضيف كود عشان نقدر نسوي مطابقة للبيانات 

#  اختبار التطابق بعد فك التشفير
files = ['fake_data.json', 'fake_message.txt']
for file_name in files:
    with open(f'test_data/{file_name}', 'rb') as original_file:
        original_data = original_file.read()
    with open(f'decrypted_{file_name}', 'rb') as decrypted_file:
        decrypted_data = decrypted_file.read()

    if original_data == decrypted_data:
        print(f"✅ {file_name} matches the original exactly.")
    else:
        print(f"❌{file_name} does NOT match the original.")







