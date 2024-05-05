from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import random, sys, os
from math import gcd
from Crypto.Cipher import AES
import pyaes
import chardet
import hashlib
import hmac
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def countPrimitiveRoots(p):
    result=0
    for i in range(2, p, 1):
        if (gcd(i, p) == 1):
            result = i
            return result

def isPrime(n, k):
    if n == 1 or n == 4:
        return False
    elif n == 2 or n == 3:
        return True
    else:
        for i in range(k):             
            # Chọn 1 số ngẫu nhiên trong [2..n-2] Để đảm bảo rằng n luôn lớn hơn 4
            a = random.randint(2, n - 2)
             
            # Fermat nhỏ
            if power(a, n - 1, n) != 1:
                return False                 
    return True

def generateLargePrime(keysize):
   while True:
      num = random.randrange(2**(keysize-1), 2**(keysize))
      if isPrime(num, 3):
        return num

def power(a, n, p):
    res = 1
    a = a % p 

    while n > 0:         
        if n % 2:
            res = (res * a) % p
            n = n - 1
        else:
            a = (a ** 2) % p
            n = n // 2
             
    return res % p


def decrypt_challenge_RSA(encrypted_message, private_key):
    try:
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message.decode()
    except ValueError:
        return "error"

def generate_key_pair():
    key = RSA.generate(1024)  # Tạo một cặp khóa RSA với độ dài 2048 bit
    private_key = key.export_key()  # Lấy khóa riêng tư
    public_key = key.publickey().export_key()  # Lấy khóa công khai
    return public_key, private_key

def receive():
    global sA
    global sB
    global indexNameA
    global indexNameB
    global signature
    global first_text_is_name
    global indexName
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)

            the_encoding = chardet.detect(msg)['encoding']
            print("msg: ",msg)
            print(the_encoding)
            # Kiểm tra enconding
            if msg == b"{quit}":
                #top.destroy()  # Đóng cửa sổ nếu nhận được "{quit}"
                on_closing()
            if (the_encoding == "ascii"):
                # Kiểm tra statement encoding
                if (msg.decode("utf-8")[0]) == "N" and len(msg.decode("utf8")) >= 9:
                    if msg.decode("utf-8")[1] == "," and msg.decode("utf-8")[8] == "$":
                        testWord = "N,FInDEx$"
                        count = len(testWord)
                        indexNameA = ""
                        indexNameB = ""
                        for i in range (count, len(msg.decode("utf8"))):
                            indexNameA += msg.decode("utf8")[count]
                            indexNameB += msg.decode("utf8")[count]
                            count+=1
                
                # Nếu là chữ kí
                elif (msg.decode("utf8")[0]) == "M" and msg.decode("utf8")[1] == "@"  and len(msg) == 68:
                    count = 4
                    signature = ""
                    for i in range (count, len(msg.decode("utf8"))):
                        signature += msg.decode("utf8")[count]
                        count+=1
            if (msg == b"YOurFirSTtImE"):
                public_key_luuDB, private_key_luuDB = generate_key_pair()
                client_socket.send(public_key_luuDB)
                print(type(public_key_luuDB))
                with open(f"./privateKey_{indexName}.key", 'wb') as file:
                    file.write(private_key_luuDB)
            elif (msg[:5] == b"xThUc"):
                msg = msg[5:]
                print("msg sau khi loại bỏ: ", msg)
                print("indexname ở xác thực: ", indexName)
                # Mở file khoá bí mật ở phía Client để giải mã challenge
                with open(f"privateKey_{indexName}.key", 'rb') as file:
                    privatekey = file.read()
                
                # Giải mã Challenge
                decrypted_challenge_RSA = decrypt_challenge_RSA(msg, privatekey)
                print ("Challenge giãi mã là: ", decrypted_challenge_RSA)
                #  Chuyển đổi tin nhắn thành dạng byte trước khi băm
                message_bytes = decrypted_challenge_RSA.encode('utf-8')
                
                # # Sử dụng SHA-256 để băm tin nhắn
                hash_object = hashlib.sha256(message_bytes)
                
                # # Lấy giá trị băm dưới dạng chuỗi hex
                hashed_message = hash_object.hexdigest()

                # # Gửi giá trị vừa băm cho server
                print(hashed_message)
                print(type(hashed_message))
                client_socket.send(hashed_message.encode("utf8"))
            #  decrypt
            elif msg[:8] == b"p0FInDEx":
                msg = msg[8:]
                p =int(msg.decode("utf8"))
            elif msg[:8] == b"g0FInDEx":
                msg = msg[8:]
                g =int(msg.decode("utf8"))
            elif msg[:8] == b"A0FInDEx":
                print(f"./privateKey_DiffieHellman_{indexName}.key")
                if os.path.exists(f"./privateKey_DiffieHellman_{indexName}.key"):
                    with open(f"./privateKey_DiffieHellman_{indexName}.key", 'r') as file:
                        content = file.read()
                        b = int(content)
                    print ("a content: ", b)
                    print ("p content: ", p)
                    msg = msg[8:]
                    Ato =int(msg.decode("utf8"))
                    # Tính toán bí mật chung từ khóa chung Ato
                    sB = power(Ato,b, p)
                    print("A content: ", Ato)
                    testlen = str(sB)
                
                    if (len(testlen) == 15):
                        sB *= 10
                    print("sB tính được: ",sB)
                    sA = 0
            elif msg[:8] == B"B0FInDEx":
                if os.path.exists(f"./privateKey_DiffieHellman_{indexName}.key"):
                    with open(f"./privateKey_DiffieHellman_{indexName}.key", 'r') as file:
                        content = file.read()
                        a = int(content)
                    print ("a content: ", a)
                    print ("p content: ", p)
                    
                    msg = msg[8:]
                    Bto =int(msg.decode("utf8"))
                    # Tính toán bí mật chung từ khóa chung Ato
                    sA = power(Bto,a,p)
                    testlen = str(sA)
                    print("Bto content: ", Bto)
                    if (len(testlen) == 15):
                        sA *= 10
                    sB = 0
            elif (sA != 0) and msg!= b"Start Pr@tocol" and msg[:8]!= b"B,FInDEx" and msg[:8]!=b"A,FInDEx" and msg[:8]!=b"g,FInDEx" and msg[:8]!=b"p,FInDEx" and msg!=b'User \xc4\x91ang kh\xc3\xb4ng Online n\xc3\xaan kh\xc3\xb4ng th\xe1\xbb\x83 trao \xc4\x91\xe1\xbb\x95i kho\xc3\xa1.' and msg!=b'B\xe1\xba\xa1n v\xc3\xa0 ng\xc6\xb0\xe1\xbb\x9di n\xc3\xa0y c\xe1\xba\xa7n c\xc3\xb9ng ph\xc3\xb2ng \xc4\x91\xe1\xbb\x83 trao kho\xc3\xa1.' and msg!=b'B\xe1\xba\xa1n v\xc3\xa0 ng\xc6\xb0\xe1\xbb\x9di n\xc3\xa0y \xc4\x91\xc3\xa3 trao kho\xc3\xa1 th\xc3\xa0nh c\xc3\xb4ng.':
                print("Đã tới sA: ", sA)
                sA = str(sA).encode("utf8")
                aes = pyaes.AESModeOfOperationCTR(sA)

                sig = hmac.new(sA, msg, hashlib.sha256).hexdigest()
                sA = int(sA.decode("utf8"))
    
                msg = aes.decrypt(msg)
                print("msg sau khi giải mã: ", msg)
                the_encoding_test = chardet.detect(msg)['encoding']
                print("encoding sau giãi mã: ", the_encoding_test)
                if (the_encoding_test == "ascii"):
                    if (sig == signature):
                        msg_list.insert(tkinter.END,bytes(indexNameA, encoding='utf-8') + msg)
                    # elif sig != 0 and signature == "":
                    #     msg_list.insert(tkinter.END, bytes(indexNameB, encoding='utf-8')+  msg)
                    else:
                        #msg_list.insert(tkinter.END, bytes(indexNameB, encoding='utf-8')+  msg)
                        msg_list.insert(tkinter.END,"Error !!! Can't load message")

            elif sB != 0 and msg!= b"Start Pr@tocol" and msg[:8]!= b"B,FInDEx" and msg[:8]!=b"A,FInDEx" and msg[:8]!=b"g,FInDEx" and msg[:8]!=b"p,FInDEx" and msg!=b'User \xc4\x91ang kh\xc3\xb4ng Online n\xc3\xaan kh\xc3\xb4ng th\xe1\xbb\x83 trao \xc4\x91\xe1\xbb\x95i kho\xc3\xa1.' and msg!=b'B\xe1\xba\xa1n v\xc3\xa0 ng\xc6\xb0\xe1\xbb\x9di n\xc3\xa0y c\xe1\xba\xa7n c\xc3\xb9ng ph\xc3\xb2ng \xc4\x91\xe1\xbb\x83 trao kho\xc3\xa1.' and msg!=b'B\xe1\xba\xa1n v\xc3\xa0 ng\xc6\xb0\xe1\xbb\x9di n\xc3\xa0y \xc4\x91\xc3\xa3 trao kho\xc3\xa1 th\xc3\xa0nh c\xc3\xb4ng.': # decrypt
                sB = str(sB).encode("utf8")
                aes = pyaes.AESModeOfOperationCTR(sB)

                sig = hmac.new(sB, msg, hashlib.sha256).hexdigest()
                sB = int(sB.decode("utf8"))
                print("sB: ", sB)
                msg = aes.decrypt(msg)
                print("msg ở sb sau khi giãi mã: ",msg)
                the_encoding_test = chardet.detect(msg)['encoding']
                print("the encoding o sb: ", the_encoding_test)
                if (the_encoding_test == "ascii"):
                    if (sig == signature):
                        msg_list.insert(tkinter.END, bytes(indexNameB, encoding='utf-8')+  msg)
                    # elif sig != 0 and signature == "":
                    #     msg_list.insert(tkinter.END, bytes(indexNameB, encoding='utf-8')+  msg)
                    else:
                        #msg_list.insert(tkinter.END, bytes(indexNameB, encoding='utf-8')+  msg)
                        msg_list.insert(tkinter.END,"Error !!! Can't load message")

            # Trao đổi khóa Ato
            elif ((msg.decode("utf-8")) == "Start Pr@tocol"):
                if os.path.exists(f"./privateKey_DiffieHellman_{indexName}.key"):
                    with open(f"./privateKey_DiffieHellman_{indexName}.key", 'r') as file:
                        content = file.read()
                    a = int(content)
                else:
                    a = generateLargePrime(53)
                    with open(f"./privateKey_DiffieHellman_{indexName}.key", 'w') as file:
                        file.write(str(a))
                print("XXXXX GIÁ TRỊ a: ", a)
                p = generateLargePrime(53)
                g = countPrimitiveRoots(p)
                Ato = power(g,a,p)
                client_socket.send(str(p).encode('utf8'))
                client_socket.send(str(g).encode('utf8'))
                client_socket.send(str(Ato).encode('utf8'))
                print("Đã tới đây r nhé")

            # nhận khóa B
            elif (msg.decode("utf-8")[0]) == "B" and msg.decode("utf-8")[1] == ",":
                testWord = "B,FInDEx"
                count = len(testWord)
                indexBto = ""
                for i in range (0 , len(testWord)-1):
                    if (testWord[i] == msg.decode("utf-8")[i]):
                        continue
                    else:
                        msg_list.insert(tkinter.END, msg)
                        break
                if (msg.decode("utf-8")[count] >= "0" and msg.decode("utf-8")[count] <= "9"):
                    
                    # lấy khóa chung B
                    for i in range (count, len(msg.decode("utf-8"))):
                        indexBto += msg.decode("utf-8")[i]

                    # Tính toán khóa bí mật chung từ Bto
                    sA = power(int(indexBto),a,p)
                    testlen = str(sA)
                    if (len(testlen) == 15):
                        sA *= 10
                    sB = 0
                    print("sA: ",sA)
            
            # Nhận số nguyên tố
            elif msg.decode("utf-8")[0] == "p" and msg.decode("utf-8")[1] == ",":
                testWord = "p,FInDEx"
                count = len(testWord)
                indexp = ""
                for i in range (0 , len(testWord)-1):
                    if (testWord[i] == msg.decode("utf-8")[i]):
                        continue
                    else:
                        msg_list.insert(tkinter.END, msg)
                        break
                if (msg.decode("utf-8")[count] >= "0" and msg.decode("utf-8")[count] <= "9"):
                    for i in range (count, len(msg.decode("utf-8"))):
                        indexp += msg.decode("utf-8")[i]

            # nhận phần tử sinh
            elif msg.decode("utf-8")[0] == "g" and msg.decode("utf-8")[1] == ",":
                testWord = "g,FInDEx"
                count = len(testWord)
                indexg = ""
                for i in range (0 , len(testWord)-1):
                    if (testWord[i] == msg.decode("utf-8")[i]):
                        continue
                    else:
                        msg_list.insert(tkinter.END, msg)
                        break
                if (msg.decode("utf-8")[count] >= "0" and msg.decode("utf-8")[count] <= "9"):
                    for i in range (count, len(msg.decode("utf-8"))):
                        indexg += msg.decode("utf-8")[i]

            # nhận khóa A
            elif msg.decode("utf-8")[0] == "A" and msg.decode("utf-8")[1] == ",":
                testWord = "A,FInDEx"
                count = len(testWord)
                indexAto = ""
                # Kiem tra header msg = A,FInDEx
                for i in range (0 , len(testWord)-1):
                    
                    # Nếu đúng header
                    if (testWord[i] == msg.decode("utf-8")[i]):
                        continue
                    else:
                        # Khong gửi khóa, thì Hiển thị tin nhắn
                        msg_list.insert(tkinter.END, msg)
                        break
                
                # Nếu đúng header kiểm tra chuỗi phía sau
                if (msg.decode("utf-8")[count] >= "0" and msg.decode("utf-8")[count] <= "9"):
                    
                    # gán Ato
                    for i in range (count, len(msg.decode("utf-8"))):
                        indexAto += msg.decode("utf-8")[i]

                    # Tạo khóa riêng B
                    if os.path.exists(f"./privateKey_DiffieHellman_{indexName}.key"):
                        with open(f"./privateKey_DiffieHellman_{indexName}.key", 'r') as file:
                            content = file.read()
                        b = int(content)
                    else:
                        b = generateLargePrime(53)
                        with open(f"./privateKey_DiffieHellman_{indexName}.key", 'w') as file:
                            file.write(str(b))
                    
                    print("XXXXX GIÁ TRỊ b: ", b)
                    Bto = power(int(indexg),b,int(indexp))

                    # Tính toán bí mật chung từ khóa chung Ato
                    sB = power(int(indexAto),b,int(indexp))

                    # Gửi Bto
                    client_socket.send(("BIndex:"+str(Bto)).encode("utf8"))
                    time.sleep(0.25)
                    print("Bto: ", Bto)
                    print("sB: ",sB)
                    testlen = str(sB)
                    sA = 0
                    if (len(testlen) == 15):
                        sB *= 10
            else:
                if (msg.decode("utf8")[:7] == "DSuser:"):
                    msg = msg[7:]
                    users_list.insert(tkinter.END, msg.decode("utf-8"))
                # elif (msg.decode("utf8")[:9] != "N,FInDEx$"):
                #     msg_list.insert(tkinter.END, indexNameA+msg.decode("utf-8"))
                elif(msg.decode("utf8")!="N,FInDEx$" and msg[:4]!=b"M@C:"):
                    msg_list.insert(tkinter.END, msg.decode("utf-8"))

        except OSError:  # Possibly client has left the chat.
            break

sA = 0
sB = 0
indexNameA=""
indexNameB = ""
signature = ""
indexName = ""
first_text_is_name = 0

def send(event=None):  # event is passed by binders.
    global sA
    global sB
    global the_encoding
    global first_text_is_name
    global indexName
    msg = my_msg.get()
    if msg == "{quit}":
        client_socket.close()
        top.quit()
    elif sA != 0:
        sA = str(sA)
        sA = sA.encode("utf8")
        aes = pyaes.AESModeOfOperationCTR(sA)    
        msg = aes.encrypt(msg)

        signature_send = hmac.new(sA, msg, hashlib.sha256).hexdigest()
        signature_send = "M@C:" + signature_send
        signature_send= signature_send.encode("utf8")
        my_msg.set("")  # Clears input field.

        client_socket.send(signature_send)

        client_socket.send(msg)
        sA = int(sA.decode("utf8"))
    elif sB != 0:
        sB = str(sB)
        sB = sB.encode("utf8")
        aes = pyaes.AESModeOfOperationCTR(sB)    
        msg = aes.encrypt(msg)

        signature_send = hmac.new(sB, msg, hashlib.sha256).hexdigest()
        signature_send = "M@C:" + signature_send
        signature_send= signature_send.encode("utf8")

        my_msg.set("")  # Clears input field.

        client_socket.send(signature_send)

        client_socket.send(msg)
        sB = int(sB.decode("utf8"))
    elif first_text_is_name == 0:
        first_text_is_name += 1
        indexName = msg
        my_msg.set("")  # Clears input field.

        # Chỉ nói chuyện một mình với server
        client_socket.send(msg.encode('utf8'))
    else:
        my_msg.set("")  # Clears input field.

        # Chỉ nói chuyện một mình với server
        client_socket.send(msg.encode('utf8'))

def on_closing(event=None):
    my_msg.set("{quit}")
    send()

def handle_click(event):
    msg_list.delete(0, tkinter.END)
    # Lấy chỉ số của dòng đã được chọn
    index = users_list.curselection()
    # Lấy nội dung của dòng đã được chọn
    selected_message = users_list.get(index)
    # Xử lý tin nhắn đã chọn, ví dụ in ra nội dung của nó
    print("Đã chọn:", selected_message)
    selected_message = "LayTN:"+ selected_message
    print("selected message: ",selected_message.encode("utf8"))
    client_socket.send(selected_message.encode('utf8'))

top = tkinter.Tk()
top.title("App Chat Project")

# Khung chứa danh sách người đang có mặt
users_frame = tkinter.Frame(top)
users_label = tkinter.Label(users_frame, text="Danh sách users:")
users_label.pack()
scrollbar0 = tkinter.Scrollbar(users_frame)
users_list = tkinter.Listbox(users_frame, height=11, width=11, yscrollcommand=scrollbar0.set)
scrollbar0.pack(side=tkinter.RIGHT, fill=tkinter.Y)
users_list.pack(side=tkinter.RIGHT, fill=tkinter.BOTH)
users_frame.pack(side=tkinter.RIGHT, padx = 5, pady=0)


messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Nhập tên của bạn!.")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()


entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Gửi", command=send)
send_button.pack()

users_list.bind("<ButtonRelease-1>", handle_click)

top.protocol("WM_DELETE_WINDOW", on_closing)

#Ket noi toi server
HOST = '127.0.0.1'
PORT = 33000
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

BUFSIZ = 8092 
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.