from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64
import os
import os.path
from os.path import isfile, join
from os import listdir

def en_get(file):
    fd = open(file, "rb")
    unencrypted_blob = fd.read()
    fd.close()
    encrypted_blob = encrypt_blob(unencrypted_blob)
    fd = open(file+".enc", "wb")
    fd.write(encrypted_blob)
    fd.close()
    os.remove(file)

def de_get(file):
    fd = open(file+".enc", "rb")
    encrypted_blob = fd.read()
    fd.close()
    #Write the decrypted contents to a file
    fd = open(file, "wb")
    fd.write(decrypt_blob(encrypted_blob))
    fd.close()
    os.remove(file+".enc")
    
def dee_get(file):
    fd = open(file, "rb")
    encrypted_blob = fd.read()
    fd.close()
    #Write the decrypted contents to a file
    fd = open(file, "wb")
    fd.write(decrypt_blob(encrypted_blob))
    fd.close()
    #os.remove(file)
    
    
def getAllFiles():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    dirs = []
    for dirName, subdirList, fileList in os.walk(dir_path):
        for fname in fileList:
           if (fname != 'locker.py' and fname != 'public_key.pem' and fname != 'private_key.pem'):
                dirs.append(dirName + "\\" + fname)
    return dirs

   

#Our Decryption Function
def decrypt_blob(encrypted_blob):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted = ("").encode()

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #return the decompressed decrypted data
    return zlib.decompress(decrypted)


#Our Encryption Function
def encrypt_blob(blob):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #compress the data first
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  ("").encode()

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += (" " * (chunk_size - len(chunk))).encode()

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #Base 64 encode the encrypted file
    return base64.b64encode(encrypted)
if os.path.isfile('public_key.pem')==False:
    
#Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=65537)
    
    #The private key in PEM format
    private_key = new_key.exportKey("PEM")
    
    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")
    
    
    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()
    
    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close() 
fd = open("public_key.pem", "rb")
public_key = fd.read()
fd.close()
#Use the private key for decryption
fd = open("private_key.pem", "rb")
private_key = fd.read()
fd.close()

while True:
    choice = int(input(
    "1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3.\n2. Press '3' to encrypt all file.\n3.\n2. Press '4' to decrypt all file.\n3. Press '5' to exit.\n"))
    if choice == 1:
        file=str(input("Enter name of file to encrypt: "))
        en_get(file)
    elif choice == 2:
        file=str(input("Enter name of file to decrypt: "))
        de_get(file)
        
    elif choice == 3:
        dirs = getAllFiles()
        for file_name in dirs:
            en_get(file_name)
    elif choice == 4:
        dirs = getAllFiles()
        for file_name in dirs:
            dee_get(file_name)
            
    elif choice == 5:
        break
    else:
        print("Please select a valid option!")
        


