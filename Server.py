from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import time
import hashlib
import os, random, string
import chardet
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def accept_incoming_connections():
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Nhập tên của bạn rồi bắt đầu chat!", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()

def encrypt_challenge_RSA(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def generate_random_challenge(length=50):
    # Tạo chuỗi ngẫu nhiên có độ dài length
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def handle_client(client):  # Takes client socket as argument.
    global indexP
    global indexG
    global indexAto
    global indexBto
    global tester
    global DS_users_online
    global loop
    global batmotlan
    global rangbuoc_deluu4giatri
    global firstauthenuser
    name = client.recv(BUFSIZ).decode("utf8") # nhận tên client
    if name in DS_users_online:
        welcome = 'Bạn đã đăng nhập rồi !!!'
        client.send(bytes(welcome, "utf8"))
        time.sleep(0.25)
        welcome1 = "Cửa sổ sẽ bị đóng trong {} giây."
        # Gửi thông điệp từ 3 xuống 1
        for i in range(3, 0, -1):
            client.send(bytes(welcome1.format(i), "utf8"))
            time.sleep(1)  # Tạm dừng 1 giây trước khi gửi thông điệp tiếp theo
        client.send(bytes("{quit}", "utf8"))
        client.close()
    else:
        conn = sqlite3.connect('./instance/Database.db')
        c = conn.cursor()
        # Kiểm tra User có trong database không ?
        # c.execute('SELECT username FROM users')
        # users = c.fetchall()
        # usernames = [user[0] for user in users]
        c.execute('SELECT username FROM users WHERE username = ?', (name,))
        result = c.fetchall()
        conn.close()
    
        if result:
            conn = sqlite3.connect('./instance/Database.db')
            c = conn.cursor()
            # Tạo tin nhắn ngẫu nhiên rồi mã hoá bằng PublicKey của Client
            c.execute('SELECT publicKey_RSA FROM users WHERE username = ?', (name,))
            takefirstone = c.fetchone()
            publicKey_RSA_fromDB = takefirstone[0]
            # Publickey_RSA_fromDB là kiểu bytes khi lấy từ DB
            random_challenge = generate_random_challenge()
            encrypted_challenge = encrypt_challenge_RSA(random_challenge, publicKey_RSA_fromDB)

            print(type(encrypted_challenge))
            # Gửi challenge cho Client
            client.send(b"xThUc"+encrypted_challenge)

            # Nhận Hash của Challenge sau khi Client đã giải mã xong
            Hashed_Challenge_From_Client = client.recv(BUFSIZ)

            #  Chuyển đổi tin nhắn thành dạng byte trước khi băm
            message_bytes = random_challenge.encode('utf-8')
                    
            # Sử dụng SHA-256 để băm tin nhắn
            hash_object = hashlib.sha256(message_bytes)
                    
            # Lấy giá trị băm dưới dạng chuỗi hex
            hashed_message = hash_object.hexdigest()

            # Xác thực, so sánh hai chuỗi băm có giống nhau không, nếu giống thì xác thực thành công
            if hashed_message == Hashed_Challenge_From_Client.decode("utf-8"):
                print(f" Xác thực {name} thành công !!!")

                welcome = 'Xin chào %s! Nếu bạn muốn thoát gõ, {quit} để thoát.' % name
                client.send(bytes(welcome, "utf8"))

                # Truy vấn các Users có trong DB để hiện lên cho Client chọn để nhắn tin
                c.execute('SELECT username FROM users')
                danh_sach_users = c.fetchall()

                for user in danh_sach_users:
                    if user[0] != name:
                        print("test\n")
                        client.send(bytes("DSuser:"+user[0],"utf8"))
                        time.sleep(0.25)

                #msg = "%s đã tham gia phòng chat!" % name
                
                #broadcast(bytes(msg, "utf8")) #
                rangbuoc[name] = None
                clients[client] = name # dict
                DS_users_online.append(name)
                print(client) # in ra client hiện tại ( ko có tên ) vd: <socket.socket,...>
                print(clients) # in ra toàn bộ giá trị clients, vd: <socket.socket,... : '2'>
                print(clients.values()) # in ra các giá trị của dict clients vd: dict_values(['2'], ['b'])
                print(clients[client]) # giá trị tên của client hiện tại vd: 2
                print("chấm hết\n") # chấm hết
                conn.close()
                while True:
                    msg = client.recv(BUFSIZ)
                    print("msg: ", msg)
                    if msg != bytes("{quit}", "utf8"):
                            if b"LayTN:" in msg:
                                print("\nmsg cho64 true: ", msg)
                                msg = msg[6:]
                                rangbuoc[clients[client]] = msg.decode("utf8")
                                # Lấy các message từ DB vào để đồng bộ
                                conn = sqlite3.connect('./instance/Database.db')
                                c = conn.cursor()
                                c.execute('SELECT username_send, message, username_receive,nguoixacthuctruoc, p, Ato, Bto, g FROM messages WHERE (username_send = ? and username_receive = ? ) or (username_send = ? and username_receive = ?) ',(name, msg.decode("utf8"),msg.decode("utf8"),name))
                                result1 = c.fetchall()
                                if result1:                                           
                                    indexP="p0FInDEx" + str(result1[0][4]) # p
                                    indexG="g0FInDEx" + str(result1[0][7]) # g
                                    indexAto1 = "A0FInDEx" + str(result1[0][5]) # Ato
                                    indexBto1 = "B0FInDEx" + str(result1[0][6]) # Bto
                                    userxacthuctruoc = result1[0][3]
                                    # Gửi P, G cho client
                                    client.send(indexP.encode("utf8"))
                                    time.sleep(0.25)
                                    client.send(indexG.encode("utf8"))
                                    time.sleep(0.25)
                                    if result1[0][3] == clients[client]: # Nếu người xác thực trước thì gửi Bto để tính s
                                        # gửi Bto
                                        client.send(indexBto1.encode("utf8"))
                                        
                                        time.sleep(0.25)
                                    else:
                                        # Gửi Ato
                                        client.send(indexAto1.encode("utf8"))  
                                        time.sleep(0.25)
                                    
                                    for i in result1:
                                        broadcast(i[1],client,i[0]+": ")
                                        batmotlan = 1
                                        time.sleep(0.25)
                                    rangbuoc_deluu4giatri[name+" - "+msg.decode("utf8")] = [indexG[8:],indexAto1[8:],indexBto1[8:],indexP[8:],userxacthuctruoc]
                                    print(rangbuoc_deluu4giatri)
                                    conn.close()
                                # elif kiểm tra xem rangbuoc_deluu4giatri đã có chưa, nếu có r thì 
                                # cứ gửi cho nó thông tin thôi về những gì mà client đó cần
                                # ví dụ nếu client đó là userfirstauthen thì gửi cho nó Ato thôi
                                elif name + " - " + msg.decode("utf8") in rangbuoc_deluu4giatri:
                                    indexP_taiday="p0FInDEx" + str(rangbuoc_deluu4giatri[name+" - "+msg.decode("utf8")][3]) # p
                                    indexG_taiday="g0FInDEx" + str(rangbuoc_deluu4giatri[name+" - "+msg.decode("utf8")][0]) # g
                                    indexAto1_taiday = "A0FInDEx" + str(rangbuoc_deluu4giatri[name+" - "+msg.decode("utf8")][1]) # Ato
                                    indexBto1_taiday = "B0FInDEx" + str(rangbuoc_deluu4giatri[name+" - "+msg.decode("utf8")][2]) # Bto

                                    client.send(indexP_taiday.encode("utf8"))
                                    time.sleep(0.25)
                                    client.send(indexG_taiday.encode("utf8"))
                                    time.sleep(0.25)
                                    if rangbuoc_deluu4giatri[name+" - "+msg.decode("utf8")][4] == name : # Nếu người xác thực trước thì gửi Bto để tính s
                                        # gửi Bto
                                        client.send(indexBto1_taiday.encode("utf8"))
                                        time.sleep(0.25)
                                    else:
                                        # Gửi Ato
                                        client.send(indexAto1_taiday.encode("utf8"))  
                                        time.sleep(0.25)
                                        
                                else:
                                    user_ban_muon_nhan = msg.decode("utf8")
                                    #msg1 = "%s đã tham gia phòng chat!" % name
                
                                    #broadcast(bytes(msg1, "utf8"),client)
                                    #time.sleep(0.25)
                                    if (msg.decode("utf8") in DS_users_online):
                                        if rangbuoc[user_ban_muon_nhan] == name:
                                            
                                            # tester = provider = client 1
                                            tester=client
                                            firstauthenuser = clients[client]
                                            client.send("Start Pr@tocol".encode("utf-8")) # Bắt đầu protocol

                                            # Chờ P, G, Ato
                                            indexP=client.recv(BUFSIZ).decode("utf8")
                                            indexG=client.recv(BUFSIZ).decode("utf8")
                                            indexAto=client.recv(BUFSIZ).decode("utf8")

                                            print("P = ",indexP)
                                            print("G = ",indexG)
                                            print("Ato = ",indexAto)

                                        #if(len(clients) == 2):
                                            # khởi tạo, thêm header
                                            indexP="p,FInDEx" + indexP
                                            indexG="g,FInDEx" + indexG
                                            indexAto = "A,FInDEx" + indexAto

                                            print("P2 = ",indexP)
                                            print("G2 = ",indexG)
                                            print("Ato2 = ",indexAto)

                                            # Hoán vị để gửi Bto *
                                            # tester1= client
                                            #indexBto = ""
                                            # client = tester
                                            search_value = user_ban_muon_nhan
                                            print("search value đầu:" , search_value)
                                            # Duyệt qua từng cặp khóa-giá trị trong từ điển
                                            for key, value in clients.items():
                                                # Nếu giá trị trùng khớp với giá trị tìm kiếm
                                                if value == search_value:
                                                    # In ra khóa tương ứng
                                                    client = key
                                                    # Dừng vòng lặp nếu bạn chỉ muốn in ra một khóa duy nhất
                                                    break
                                            print ("Index Bto trước khi gửi: ", indexBto)
                                            # Gửi P, G cho client 2
                                            client.send(indexP.encode("utf8"))
                                            time.sleep(0.25)
                                            client.send(indexG.encode("utf8"))
                                            time.sleep(0.25)

                                            # gửi Ato 1
                                            client.send(indexAto.encode("utf8"))
                                            time.sleep(0.25)
                                            # nhận Bto 1
                                    
                                            #khúc này có vấn đè
                                            # Thử hoán vị
                                            # client = tester
                                            while (indexBto == ""):
                                                si = "0"

                                            #indexBto = client.recv(BUFSIZ).decode("utf8")
                                            #print("chua toi day")
                                        
                                            print ("Index Bto sau khi gửi: ", indexBto)
                                            indexBto = "B,FInDEx" + indexBto
                                            # Hoán vị lần nữa
                                            #client = tester
                                            # test nè
                                            # error = 'Bạn và người này trao đổi khoá thành công !!!'
                                            # client.send(bytes(error, "utf8"))

                                            search_value = name
                                            print("serach value 2: ",search_value)
                                            for key, value in clients.items():
                                                # Nếu giá trị trùng khớp với giá trị tìm kiếm
                                                if value == search_value:
                                                    # In ra khóa tương ứng
                                                    client = key
                                                    # Dừng vòng lặp nếu bạn chỉ muốn in ra một khóa duy nhất
                                                    break

                                            client.send(indexBto.encode("utf8"))

                                            print("Trao đổi khoá thành công")                                                                         
                                            rangbuoc_deluu4giatri[name+" - "+user_ban_muon_nhan] = [indexG[8:],indexAto[8:],indexBto[8:],indexP[8:],firstauthenuser]
                                            rangbuoc_deluu4giatri[user_ban_muon_nhan + " - "+name] = [indexG[8:],indexAto[8:],indexBto[8:],indexP[8:],firstauthenuser]
                                            print(rangbuoc_deluu4giatri)
                                            # Đoạn này để trả về thông tin cả hai đã trao đổi khoá thành công
                                            tukhoa1 = name
                                            tukhoa2 = user_ban_muon_nhan
                                            new_dict = {key: value for key, value in clients.items() if value in (tukhoa1, tukhoa2)}
                                            information = 'Bạn và người này đã trao khoá thành công.'
                                            for sock in new_dict:
                                                sock.send(bytes(information, "utf8"))
                                                time.sleep(0.25)
                                        else:
                                            error = 'Bạn và người này cần cùng phòng để trao khoá.'
                                            client.send(bytes(error, "utf8"))
                                    else:
                                        error = "User đang không Online nên không thể trao đổi khoá."
                                        client.send(bytes(error, "utf8"))

                            elif rangbuoc[clients[client]] == None:
                                error = "Xin hãy chọn người bạn muốn nhắn."
                                client.send(bytes(error, "utf8"))
                                # rồi dưới đây có thể đưa máy6 cái như các điều kiện trao đổi ở trên xuống đây,
                                # client 1 thì cho bằng clients[client] hoặc name, còn client 2 thì bằng msg sau khi đã gỡ bỏ "LayTN:"
                                # Lưu ý: Khi message lấy từ DB ra là kiểu string, gửi broadcast thì cần kiểu bytes
                                # Nên phải đổi tin nhắn thành bytes trước khi dùng broadcast, name thì xem xét username_sent
                                # sau khi lấy từ db nếu cả 2 có tin nhắn thì sẽ thực thi
                                # truyền khoá cho client yêu cầu (ng gửi clients[client] or name) để tính khoá chung rồi gửi tin nhắn
                                # trong trường hợp đối phương đang offline
                                # vậy thì phải lưu khoá bí mật dùng để tính khoá chung ở dưới máy tính

                                # TH2: Nếu cả 2 ko có bất kì tin nhắn nào trong DB thì sẽ bắt đầu giao thức trao đổi khoá
                                # Vấn đề là: cả hai phải cùng online mới trao đổi khoá được ??? Cần giải quyết chỗ này
                            # elif loop == 1: # cách giải quyết: elfi rangbuoc[clients[client]] not in DS_user_online
                            elif rangbuoc[clients[client]] not in DS_users_online and name+" - "+rangbuoc[clients[client]] not in rangbuoc_deluu4giatri:
                                            # and rangbuoc_deluu4giatri[name+" - "+rangbuoc[clients[client]]] == rỗng
                                            # thì nghĩa là thằng mà thg client hiện tại muốn nhắn ko online và cũng chưa trao đổi khoá
                                error = "User đang không Online nên không thể trao đổi khoá."
                                client.send(bytes(error, "utf8"))
                            elif b"BIndex:" not in msg and rangbuoc[clients[client]] in DS_users_online and name+" - "+rangbuoc[clients[client]] not in rangbuoc_deluu4giatri: # TH2: cách giải quyết: elfi rangbuoc[clients[client]] in DS_user_online
                                            # and rangbuoc_deluu4giatri[name+" - "+rangbuoc[clients[client]]] == rỗng
                                            # thì nghĩa là thằng mà thg client hiện tại muốn nhắn đang online nhưng chưa trao đổi khoá
                                error = 'Bạn và người này cần cùng phòng để trao khoá.'
                                client.send(bytes(error, "utf8"))
                                # print("msg ở loop: ",msg)
                                # print("kẹt ở đây nè 1")
                                # if (rangbuoc[clients[client]] in DS_users_online):
                                #         print("kẹt ở đây nè")
                                #         loop == 0
                                #         broadcast(msg, client,name + ": " )
                                #         if b"M@C:" not in msg:                     
                                #             conn = sqlite3.connect('./instance/Database.db')
                                #             c = conn.cursor()
                                #             c.execute("INSERT INTO messages (username_send, username_receive, message,nguoixacthuctruoc,g,Ato,Bto,p) VALUES (?,?,?,?,?,?,?,?)", (clients[client], rangbuoc[clients[client]],msg, rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][4], rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][0],rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][1],rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][2],rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][3]))
                                #             conn.commit()
                                #             conn.close()
                                # else:
                                #     error = 'Bạn và người này chưa trao đổi khoá.'
                                #     client.send(bytes(error, "utf8"))
                            else:
                                print("Chạy dc cai nay r")
                                if b"BIndex:" in msg:
                                        msg = msg[7:]
                                        indexBto = msg.decode("utf8")
                                        print ("BIndex o day nè: ", indexBto)
                                else:
                                    broadcast(msg, client,name + ": ")
                                    print ("test msg: ", msg)
                                    if b"M@C:" not in msg:                     
                                        conn = sqlite3.connect('./instance/Database.db')
                                        c = conn.cursor()
                                        c.execute("INSERT INTO messages (username_send, username_receive, message,nguoixacthuctruoc,g,Ato,Bto,p) VALUES (?,?,?,?,?,?,?,?)", (clients[client], rangbuoc[clients[client]],msg, rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][4], rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][0],rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][1],rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][2],rangbuoc_deluu4giatri[clients[client]+" - "+rangbuoc[clients[client]]][3]))
                                        conn.commit()
                                        conn.close()
                                        
                                    print("\nclient đang nhắn: ", clients[client])
                            
                            # if b"M@C:" not in msg:

                            #     c.execute('SELECT id FROM users WHERE username = ?', (clients[client],))
                            #     takefirstone = c.fetchone()
                            #     id_sender = takefirstone[0]

                            #     c.execute("INSERT INTO messages (user_id, message_text) VALUES (?, ?)", (id_sender, message_text))
                            #     print("message ko mac: ", msg)
                    else:
                        client.send(bytes("{quit}", "utf8"))
                        client.close()
                        del clients[client]
                        #broadcast(bytes("%s đã thoát phòng chat." % name, "utf8"))
                        break
            else:
                welcome = 'Xin chào ! Có vẻ như bạn không phải là %s.' % name
                client.send(bytes(welcome, "utf8"))
                
                welcome1 = "Cửa sổ sẽ bị đóng trong {} giây."

                # Gửi thông điệp từ 3 xuống 1
                for i in range(3, 0, -1):
                    client.send(bytes(welcome1.format(i), "utf8"))
                    time.sleep(1)  # Tạm dừng 1 giây trước khi gửi thông điệp tiếp theo
                
                client.send(bytes("{quit}", "utf8"))
                client.close()   
        else:
            conn = sqlite3.connect('./instance/Database.db')
            c = conn.cursor()
            client.send(bytes("YOurFirSTtImE", "utf8"))
            public_key_luuDB = client.recv(BUFSIZ)
            print(public_key_luuDB)
            print(type(public_key_luuDB))
            c.execute("INSERT INTO users (username, publicKey_RSA) VALUES (?, ?)", (name, public_key_luuDB))
            conn.commit()
            conn.close()
            

            welcome = 'Xin chào ! Đây là lần đầu xác thực của bạn.'
            client.send(bytes(welcome, "utf8"))
            time.sleep(0.25)
            welcome = 'Vui lòng mở lại cửa sổ để đăng nhập.'
            client.send(bytes(welcome, "utf8"))
            time.sleep(0.25)
            welcome1 = "Cửa sổ sẽ bị đóng trong {} giây."
            # Gửi thông điệp từ 3 xuống 1
            for i in range(3, 0, -1):
                client.send(bytes(welcome1.format(i), "utf8"))
                time.sleep(1)  # Tạm dừng 1 giây trước khi gửi thông điệp tiếp theo
            client.send(bytes("{quit}", "utf8"))
            client.close()
    

def broadcast(msg,indexclient, prefix=""):  # prefix is for name identification.  
    global batmotlan
    prefix = "N,FInDEx$" + prefix
    print("\nprefix o broadcast: ", prefix)
    print("msg o broadcast: ", msg)
    the_encoding = chardet.detect(msg)['encoding']
    print("the encoding: ", the_encoding)
    print ("Bat mot lan", batmotlan)
    if batmotlan == 1:
        tukhoa1 = clients[indexclient]
        new_dict = {key: value for key, value in clients.items() if value in (tukhoa1)}
        for sock in new_dict:
            sock.send(prefix.encode("utf8"))
            sock.send(msg)
        batmotlan = 0
    elif the_encoding == "ascii" and len(msg)==68: # không cần gửi prefix
        if (msg.decode("utf8")[0]=="M" and msg.decode("utf8")[1]=="@"): # ??? gui di chu ki
            if rangbuoc[clients[indexclient]] in DS_users_online: # nếu client 2 trong ds online
                if rangbuoc[rangbuoc[clients[indexclient]]] == clients[indexclient]:# nếu ràng buộc của client2 có tên client\
                    tukhoa1 = clients[indexclient]
                    tukhoa2 = rangbuoc[clients[indexclient]]

                    new_dict = {key: value for key, value in clients.items() if value in (tukhoa1, tukhoa2)}

                    for sock in new_dict:
                        sock.send(prefix.encode("utf8"))
                        time.sleep(0.25)
                        sock.send(msg)
                else:
                    tukhoa1 = clients[indexclient]
                    new_dict = {key: value for key, value in clients.items() if value in (tukhoa1)}
                    for sock in new_dict:
                        sock.send(prefix.encode("utf8"))
                        time.sleep(0.25)
                        sock.send(msg)
            # for sock in clients:
            #     sock.send(msg)
        time.sleep(0.1)
    else:
        # Ràng buộc là từ điển rangbuoc = {tenc_client1 : "ten_client1 - ten_client2"}
        # Trước tiên kiểm tra xem ten_client1 và ten_client2 có đang online cùng nhau không
        # Nếu có thì kiểm tra tiếp ràng buộc của client 2 có phải là ten_client2 - tenclient1 không?
        # Nếu có thì cho sock chạy trong client_moi[ chứa 2 giá trị là ten_client1 và ten_client2] r gửi về
        # Nếu ràng buộc của client 2 không phải giống trên thì chỉ gửi mỗi thông tin cho client 1
        if rangbuoc[clients[indexclient]] in DS_users_online: # nếu client 2 trong ds online
            if rangbuoc[rangbuoc[clients[indexclient]]] == clients[indexclient]:# nếu ràng buộc của client2 có tên client\
                tukhoa1 = clients[indexclient]
                tukhoa2 = rangbuoc[clients[indexclient]]
                print ("no dang o day, tukhoa1, tu khoa2:", tukhoa1, tukhoa2)
                new_dict = {key: value for key, value in clients.items() if value in (tukhoa1, tukhoa2)}
                print("new_dict: ", new_dict)
                for sock in new_dict:
                    sock.send(prefix.encode("utf8"))
                    time.sleep(0.25)
                    sock.send(msg)

            else:
                print ("no dang o day2")
                tukhoa1 = clients[indexclient]
                new_dict = {key: value for key, value in clients.items() if value in (tukhoa1)}
                for sock in new_dict:
                    sock.send(prefix.encode("utf8"))
                    time.sleep(0.25)
                    sock.send(msg)
        else:
            print("no dang o day ba")
            tukhoa1 = clients[indexclient]
            new_dict = {key: value for key, value in clients.items() if value in (tukhoa1)}
            for sock in new_dict:
                sock.send(prefix.encode("utf8"))
                time.sleep(0.25)
                sock.send(msg)

indexP = ""
indexG = ""
indexAto = ""
indexBto = ""
firstauthenuser = ""
batmotlan = 0
DS_users_online = []
rangbuoc = {}
rangbuoc_deluu4giatri = {}
clients = {}
addresses = {}
loop = 0

HOST = '127.0.0.1'
PORT = 33000
BUFSIZ = 8092 
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

def database_exists():
    return os.path.exists('./instance/Database.db')

def create_database():
    
    conn = sqlite3.connect('./instance/Database.db')
    c = conn.cursor()
    # Tạo bảng users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username STRING NOT NULL,
                 publicKey_RSA BLOB NOT NULL)''')

    # Tạo bảng messages
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username_send STRING NOT NULL,
                 username_receive STRING NOT NULL,
                 message BLOB NOT NULL,
                 nguoixacthuctruoc STRING NOT NULL,
                 g STRING NOT NULL,
                 Ato STRING NOT NULL,
                 Bto STRING NOT NULL,
                 p STRING NOT NULL,
                 FOREIGN KEY (username_send) REFERENCES users (username))''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    if not database_exists():
        create_database()
    SERVER.listen(2)
    print("Chờ kết nối từ các client...")
    
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()