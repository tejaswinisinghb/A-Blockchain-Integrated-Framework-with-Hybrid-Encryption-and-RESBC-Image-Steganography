from django.shortcuts import render
from datetime import datetime
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import os
import json
from web3 import Web3, HTTPProvider
import base64
from PIL import Image
import numpy as np
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
import pyaes, pbkdf2, binascii, os, secrets
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES
import random
import numpy as np
import pickle
import base64
from datetime import datetime

global username, keysList, usersList, filename, message, num_chunks, receiver, image_data
global contract, web3

#function to call contract
def getContract():
    global contract, web3
    blockchain_address = 'http://127.0.0.1:8545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'Encryption.json' #Encryption contract file
    deployed_contract_address = '0x057dc01Aa94EFA2438eE1A9f57E13511f67b3617' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
getContract()

def getUsersList():
    global usersList, contract
    usersList = []
    count = contract.functions.getUserCount().call()
    for i in range(0, count):
        user = contract.functions.getUsername(i).call()
        password = contract.functions.getPassword(i).call()
        phone = contract.functions.getPhone(i).call()
        email = contract.functions.getEmail(i).call()
        address = contract.functions.getAddress(i).call()
        usersList.append([user, password, phone, email, address])

def getKeyList():
    global keysList, contract
    keysList = []
    count = contract.functions.getKeyCount().call()
    for i in range(0, count):
        key_id = contract.functions.getKeyid(i).call()
        hashcode = contract.functions.getHash(i).call()
        image = contract.functions.getImage(i).call()
        sender = contract.functions.getSender(i).call()
        receiver = contract.functions.getReceiver(i).call()
        upload_date = contract.functions.getUploadDate(i).call()
        keysList.append([key_id, hashcode, image, sender, receiver, upload_date])

getUsersList()
getKeyList()

def getRSAKeys():
    key = RSA.generate(2048)
    private_key = key.export_key('PEM')
    public_key = key.publickey().exportKey('PEM')
    return private_key, public_key

def getDesKey():
    word = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9']
    key = ""
    for i in range(0, 8):
        key += word[random.randint(0, len(word)-1)]
    return key.encode()

def getAESKey(): #generating AES key based on Diffie common secret shared key
    password = getDesKey()
    passwordSalt = str("0986543")#get AES key using diffie
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encryptAes(plaintext, key): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext.encode())
    return ciphertext

def decryptAes(enc, key): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def encryptDes(plain_text, key): #des algorithm
    padded_text = pad(plain_text.encode(), DES.block_size)
    des = DES.new(key, DES.MODE_ECB)
    encrypted = des.encrypt(padded_text)
    return encrypted

def decryptDes(encrypted_text, key): #des algorithm
    des = DES.new(key, DES.MODE_ECB)
    decrypted = des.decrypt(encrypted_text)
    return unpad(decrypted, DES.block_size)

def encryptRsa(plain_text, public_key):
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    return rsa_public_key.encrypt(plain_text)

def decryptRsa(encrypted_text, private_key):
     rsa_private_key = RSA.importKey(private_key)
     rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
     return rsa_private_key.decrypt(encrypted_text)  

def read_secret(filename):
    with open(filename,'r') as f:
        b = f.read()
    return b

def import_image(filename):    
    return np.array(Image.open(filename))

def reset(pixel, n_lsb):
    return (pixel >> n_lsb) << n_lsb

def bits_representation(integer, n_bits=8):
    return ''.join(['{0:0',str(n_bits),'b}']).format(integer)

def find_capacity(img, code):
    medium_size = img.size - 12
    # number of 2 bits slots the code needs
    secret_size = (len(code)*8) // 2
    print(f'Total Available space: {medium_size} 2-bit slots')
    print(f'Code size is: {secret_size} 2-bit slots')
    print('space consumed: {:.2f}%'.format((secret_size/medium_size) * 100))
    return medium_size, secret_size

def size_payload_gen(secret_size, n_bits_rep=8):
    rep = bits_representation(secret_size,n_bits_rep)
    for index in range(0, len(rep), 2):
        yield rep[index:index+2]

def secret_gen(secret, n_bits_rep=8):
    for byte in secret:
        bin_rep = bits_representation(ord(byte),8)
        for index in range(0,len(bin_rep),2):
            yield bin_rep[index: index+2]

def encode_capacity(img_copy, sec_size):
    g = size_payload_gen(sec_size, 24)
    for index, two_bits in enumerate(g):        
        # reset the least 2 segnificant bits
        img_copy[index] = reset(img_copy[index], 2)        
        # embed 2 bits carrying info about secret length
        img_copy[index] += int(two_bits,2)

def encode_secret_blocks(img_copy, secret):
    gen = secret_gen(secret)
    for block_no, two_bits in enumerate(gen):        
        img_copy[block_no+12] = reset(img_copy[block_no+12], 2)
        img_copy[block_no+12] += int(two_bits,2)

def encodeRESBC(img_file, secret_file):
    status = 0
    secret = read_secret(secret_file)
    img = import_image('EncryptionApp/static/'+img_file)
    medium_size, secret_size = find_capacity(img,secret)
    if secret_size >= medium_size:
        status = 1
    else:
        img_dim = img.shape
        img = img.flatten()
        encode_capacity(img, secret_size)
        encode_secret_blocks(img, secret)
        img = img.reshape(img_dim)
        im = Image.fromarray(img)
        im.save('EncryptionApp/static/files/'+img_file)        
    return status

def import_image(filename):    
    return np.array(Image.open(filename))

def decode_capacity(img_copy):
    bin_rep = ''.join([bits_representation(pixel)[-2:] for pixel in img_copy[:12]])
    return int(bin_rep, 2)

def bits_representation(integer, n_bits=8):
    return ''.join(['{0:0',str(n_bits),'b}']).format(integer)

def decode_secret(flat_medium, sec_ext, length):
    with open('EncryptionApp/static/extracted.txt','w') as file:
        # extract 1 byte at a type (2 bits from each of the 4 pixels)
        for pix_idx in range(12,len(flat_medium[12:]),4):
            # convert the byte to character then write to file
            byte = ''.join([bits_representation(pixel)[-2:] for pixel in flat_medium[pix_idx:pix_idx+4]])
            file.write(chr(int(byte,2)))
            if pix_idx > length+4:
                break

def decode(stego_img, sec_ext):
    img = import_image(stego_img).flatten()
    secret_size = decode_capacity(img)
    decode_secret(img, sec_ext, secret_size)

def getChunks(text, chunk_size):
    chunks = []
    for i in range(0, len(text), chunk_size):
        chunks.append(text[i:i + chunk_size])
    return chunks

def encryptChunks():
    msg_chunks = []
    global keysList, username, filename, message, num_chunks, receiver, image_data
    chunks = getChunks(message, int(num_chunks))
    output = '<table border=1 align=center>'
    output+='<tr><th><font size=3 color=black>Chunk No</font></th>'
    output+='<th><font size=3 color=black>Chunk Data</font></th>'
    output+='<th><font size=3 color=black>RSA Private Key</font></th>'
    output+='<th><font size=3 color=black>RSA Public Key</font></th>'
    output+='<th><font size=3 color=black>AES Key</font></th>'
    output+='<th><font size=3 color=black>DES Key</font></th>'
    output+='<th><font size=3 color=black>Encryption Type</font></th>'
    output+='<th><font size=3 color=black>Encrypted Data</font></th></tr>'
    enc_type = ""
    for i in range(len(chunks)):
        rsa_private_key, rsa_public_key = getRSAKeys()
        des_key = getDesKey()
        aes_key = getAESKey()
        encrypt_type = random.randint(0, 1)
        encrypted_chunk = None
        if encrypt_type == 0:
            enc_type = "AES"
            encrypted_chunk = encryptAes(chunks[i], aes_key)
        else:
            enc_type = "DES"
            encrypted_chunk = encryptDes(chunks[i], des_key)
        encrypted_aes_key = encryptRsa(aes_key, rsa_public_key)
        encrypted_des_key = encryptRsa(des_key, rsa_public_key)        
        msg_chunks.append([rsa_private_key, encrypted_aes_key, encrypted_des_key, encrypt_type, encrypted_chunk])
        output+='<tr><td><font size=3 color=black>'+str(i+1)+'</font></td>'
        output+='<td><font size=3 color=black>'+chunks[i]+'</font></td>'
        output+='<td><font size=3 color=black>'+str(rsa_private_key[0:20])+'</font></td>'
        output+='<td><font size=3 color=black>'+str(rsa_public_key[0:20])+'</font></td>'
        output+='<td><font size=3 color=black>'+str(aes_key[0:3])+'</font></td>'
        output+='<td><font size=3 color=black>'+str(des_key[0:3])+'</font></td>'
        output+='<td><font size=3 color=black>'+str(enc_type)+'</font></td>'
        output+='<td><font size=3 color=black>'+str(encrypted_chunk[0:10])+'</font></td></tr>'
    msg_chunks = pickle.dumps(msg_chunks)
    sha_code = sha256(msg_chunks).hexdigest()
    msg_chunks = base64.b64encode(msg_chunks).decode()
    with open("EncryptionApp/static/encrypted.txt", "w") as file:
        file.write(msg_chunks)
    file.close()
    return output, sha_code

def HybridEncryption(request):
    if request.method == 'GET':
        global keysList, username, filename, message, num_chunks, receiver, image_data
        if os.path.exists('EncryptionApp/static/'+filename):
            os.remove('EncryptionApp/static/'+filename)
        with open('EncryptionApp/static/'+filename, 'wb') as file:
            file.write(image_data)
        file.close()
        output, sha_code = encryptChunks()
        current_date = str(datetime.now().date())
        output += "</table><br/>"        
        status = encodeRESBC(filename, 'EncryptionApp/static/encrypted.txt')
        if status == 0:
            key_id = str(len(keysList) + 1)
            output += "Keys successfully hidden in Image Blocks<br/><br/>"
            msg = contract.functions.saveKeys(key_id, sha_code, filename, username, receiver, current_date).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(msg)
            keysList.append([key_id, sha_code, filename, username, receiver, current_date])
            output += "Blockchain Storage Log Details<br/>"+str(tx_receipt)
        else:
            output += "sufficient image not found in image block to hide keys<br/><br/>"
        context= {'data':output}
        return render(request, 'UserScreen.html', context)

def Verify(request):
    if request.method == 'GET':
        global keysList
        image_name = ""
        code = ""
        kid = request.GET['kid']
        for i in range(len(keysList)):
            klist = keysList[i]
            if klist[0] == kid:
                image_name = klist[2]
                code = klist[1]
                break
        decode('EncryptionApp/static/files/'+image_name, 'py')
        with open("EncryptionApp/static/extracted.txt", "r") as file:
            msg_chunks = file.read()
        file.close()    
        msg_chunks = base64.b64decode(msg_chunks)
        sha_code = sha256(msg_chunks).hexdigest()
        msg_chunks = pickle.loads(msg_chunks)
        output = "Blockchain Sha256 : "+code+"<br/>Generated Sha256 : "+sha_code+"<br/>"
        if sha_code == code:
            output += "<font size=3 color=green>Verification Successful</font>"
        else:
            output += "<font size=3 color=red>Verification Failed</font>"
        context= {'data':output}
        return render(request, 'UserScreen.html', context)        

def KeyVerification(request):
    if request.method == 'GET':
        global username, keysList
        output = '<table border=1 align=center>'
        output+='<tr><th><font size=3 color=black>Key ID</font></th>'
        output+='<th><font size=3 color=black>Key Hash</font></th>'
        output+='<th><font size=3 color=black>Image Name</font></th>'
        output+='<th><font size=3 color=black>Sender</font></th>'
        output+='<th><font size=3 color=black>Receiver</font></th>'
        output+='<th><font size=3 color=black>Upload Date</font></th>'
        output+='<th><font size=3 color=black>Image</font></th>'
        output+='<th><font size=3 color=black>Click Here to Verify</font></th></tr>'
        for i in range(len(keysList)):
            klist = keysList[i]
            if klist[3] == username or klist[4] == username:
                output+='<tr><td><font size=3 color=black>'+str(klist[0])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[1][0:20])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[2])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[3])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[4])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[5])+'</font></td>'
                output+='<td><img src="static/files/'+klist[2]+'" width="180" height="200"/></td>'
                output+='<td><a href=\'Verify?kid='+klist[0]+'\'><font size=3 color=red>Click to Verify</font></a></td></tr>'
        context= {'data':output}
        return render(request, 'UserScreen.html', context)

def DecryptAction(request):
    if request.method == 'GET':
        global keysList
        image_name = ""
        code = ""
        kid = request.GET['kid']
        for i in range(len(keysList)):
            klist = keysList[i]
            if klist[0] == kid:
                image_name = klist[2]
                code = klist[1]
                break
        decode('EncryptionApp/static/files/'+image_name, 'py')
        with open("EncryptionApp/static/extracted.txt", "r") as file:
            msg_chunks = file.read()
        file.close()    
        msg_chunks = base64.b64decode(msg_chunks)
        msg_chunks = pickle.loads(msg_chunks)
        output = ""
        for i in range(len(msg_chunks)):
            rsa_private_key, encrypted_aes_key, encrypted_des_key, encrypt_type, encrypted_chunk = msg_chunks[i]
            decrypted_aes_key = decryptRsa(encrypted_aes_key, rsa_private_key)
            decrypted_des_key = decryptRsa(encrypted_des_key, rsa_private_key)
            if encrypt_type == 0:
                aes_decrypt = decryptAes(encrypted_chunk, decrypted_aes_key)
                output += str(aes_decrypt.decode())
            else:
                des_decrypt = decryptDes(encrypted_chunk, decrypted_des_key)
                output += str(des_decrypt.decode())
        context= {'data':"Decrypted & Extracted Chunks = "+output}
        return render(request, 'UserScreen.html', context)      

def DataDecryption(request):
    if request.method == 'GET':
        global username, keysList
        output = '<table border=1 align=center>'
        output+='<tr><th><font size=3 color=black>Key ID</font></th>'
        output+='<th><font size=3 color=black>Key Hash</font></th>'
        output+='<th><font size=3 color=black>Image Name</font></th>'
        output+='<th><font size=3 color=black>Sender</font></th>'
        output+='<th><font size=3 color=black>Receiver</font></th>'
        output+='<th><font size=3 color=black>Upload Date</font></th>'
        output+='<th><font size=3 color=black>Image</font></th>'
        output+='<th><font size=3 color=black>Click Here to Decrypt</font></th></tr>'
        for i in range(len(keysList)):
            klist = keysList[i]
            if klist[3] == username or klist[4] == username:
                output+='<tr><td><font size=3 color=black>'+str(klist[0])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[1][0:20])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[2])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[3])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[4])+'</font></td>'
                output+='<td><font size=3 color=black>'+str(klist[5])+'</font></td>'
                output+='<td><img src="static/files/'+klist[2]+'" width="180" height="200"/></td>'
                output+='<td><a href=\'DecryptAction?kid='+klist[0]+'\'><font size=3 color=red>Click to Decrypt</font></a></td></tr>'
        context= {'data':output}
        return render(request, 'UserScreen.html', context)    

def UploadImageAction(request):
    if request.method == 'POST':
        global keysList, username, filename, message, num_chunks, receiver, image_data
        receiver = request.POST.get('t1', False)
        message = request.POST.get('t2', False)
        num_chunks = request.POST.get('t3', False)
        filename = request.FILES['t4'].name
        image_data = request.FILES['t4'].read()
        output = "Image & message details received. Click on 'Hybrid Encryption & Steganography' link to proceed" 
        context= {'data':output}
        return render(request, 'UserScreen.html', context)

def UploadImage(request):
    if request.method == 'GET':
        global usersList, username
        output = '<tr><td><font size="3" color="black">Choose&nbsp;Receiver</td><td><select name="t1">'
        for i in range(len(usersList)):
            ulist = usersList[i]
            if ulist[0] != username:
                output += '<option value="'+ulist[0]+'">'+ulist[0]+'</option>'
        output += '</select></td></tr>'
        context= {'data1':output}
        return render(request, 'UploadImage.html', context)

def index(request):
    if request.method == 'GET':
        return render(request,'index.html', {})

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})
    
def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})

def RegisterAction(request):
    if request.method == 'POST':
        global usersList
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        status = "none"
        for i in range(len(usersList)):
            users = usersList[i]
            if username == users[0]:
                status = "exists"
                break
        if status == "none":
            msg = contract.functions.saveUser(username, password, contact, email, address).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(msg)
            usersList.append([username, password, contact, email, address])
            context= {'data':'Signup Process Completed<br/>'+str(tx_receipt)}
            return render(request, 'Register.html', context)
        else:
            context= {'data':'Given username already exists'}
            return render(request, 'Register.html', context)

def UserLoginAction(request):
    if request.method == 'POST':
        global username, contract, usersList
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        status = 'none'
        for i in range(len(usersList)):
            ulist = usersList[i]
            user1 = ulist[0]
            pass1 = ulist[1]
            if user1 == username and pass1 == password:
                status = "success"
                break
        if status == 'success':
            output = 'Welcome '+username
            context= {'data':output}
            return render(request, "UserScreen.html", context)
        if status == 'none':
            context= {'data':'Invalid login details'}
            return render(request, 'UserLogin.html', context)

        
