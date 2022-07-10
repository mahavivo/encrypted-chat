#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import threading
import queue
import json  # json.dumps(some)打包   json.loads(some)解包
import time

import rsa
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


IP = ''
# IP = '127.0.0.1'
PORT = 9999  # 端口
BUFF = 1024

# key = ''
mode = AES.MODE_CBC
# iv = b'\xd5\x0f\xaa\x8dn\x8a(\xd3\xdcj\x19q\xf0\x01\x93\x10'

users = []  # 0:user_name 1:user_key 2:user_iv 3:connection

messages = queue.Queue()
lock = threading.Lock()


# AES加密解密

def encrypt(text, key, iv):
    text = text.encode('utf-8')

    cryptor = AES.new(key, mode, iv)
    # 这里密钥key 长度必须为16（AES-128）,
    # 24（AES-192）,或者32 （AES-256）Bytes 长度
    # 目前AES-128 足够目前使用
    length = 16
    count = len(text)
    if count < length:
        add = (length - count)
        # \0 backspace
        # text = text + ('\0' * add)
        text = text + ('\0' * add).encode('utf-8')
    elif count > length:
        add = (length - (count % length))
        # text = text + ('\0' * add)
        text = text + ('\0' * add).encode('utf-8')
    ciphertext = cryptor.encrypt(text)
    # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
    # 所以这里统一把加密后的字符串转化为16进制字符串
    return b2a_hex(ciphertext)

def decrypt(text, key, iv):
    cryptor = AES.new(key, mode, iv)
    plain_text = cryptor.decrypt(a2b_hex(text))
    # return plain_text.rstrip('\0')
    return bytes.decode(plain_text).rstrip('\0')


# 统计当前在线人员
def user_counter():
    onlines = []
    for i in range(len(users)):
        onlines.append(users[i][0])
    return onlines


# 接受来自客户端的用户名，如果用户名为空，使用用户的IP与端口作为用户名。如果用户名出现重复，则在出现的用户名依此加上后缀“2”、“3”、“4”……
def recv_msg(conn, addr):  # 接收消息

    conn_data = conn.recv(BUFF)

    if conn_data.decode('utf-8') == 'exchangekey':
        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' start to exchange key!')

        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' create pubkey & privkey')
        (pubkey, privkey) = rsa.newkeys(1024)
        modulus = pubkey.n
        exponent = pubkey.e

        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' send pubkey')
        conn.send(str(modulus).encode('utf-8'))
        conn.send(str(exponent).encode('utf-8'))

        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' recv encrypted cipher-key')
        cipher_key = conn.recv(BUFF)

        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' decrypt cipher-key')
        key = rsa.decrypt(cipher_key, privkey)
        # print(key)
        # key = key.decode('utf-8')

        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' recv encrypted cipher-iv')
        cipher_iv = conn.recv(BUFF)

        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' decrypt cipher-iv')
        iv = rsa.decrypt(cipher_iv, privkey)
        # print(iv)


        user = conn.recv(BUFF)  # 用户名称
        user = decrypt(user, key, iv)
        if user == '用户名不存在':
            user = addr[0] + ':' + str(addr[1])
        tag = 1
        temp = user
        for i in range(len(users)):  # 检验重名，则在重名用户后加数字
            if users[i][0] == user:
                tag = tag + 1
                user = temp + str(tag)

        users.append((user, key, iv, conn))
        users_online = user_counter()
        # print(users_online)
        load_queue(users_online, addr)

        # 在获取用户名后便会不断地接受用户端发来的消息（即聊天内容），结束后关闭连接。
        try:
            while True:
                message = conn.recv(BUFF)  # 发送消息
                message = decrypt(message, key, iv)
                message = user + ': ' + message
                load_queue(message, addr)
        # 如果用户断开连接，将该用户从用户列表中删除，然后更新用户列表。
        except:
            j = 0  # 用户断开连接
            for man in users:
                if man[0] == user:
                    users.pop(j)  # 服务器段删除退出的用户
                    break
                j = j + 1

            users_online = user_counter()
            load_queue(users_online, addr)
            conn.close()

# 将地址与数据（需发送给客户端）存入messages队列。
def load_queue(data, addr):
    lock.acquire()
    try:
        messages.put((addr, data))
    finally:
        lock.release()

# 服务端在接受到数据后，会对其进行一些处理然后发送给客户端，如下图，对于聊天内容，服务端直接发送给客户端，而对于用户列表，便由json.dumps处理后发送。
def send_data():  # 发送数据
    while True:
        if not messages.empty():
            message = messages.get()
            if isinstance(message[1], str):
                for i in range(len(users)):
                    data = ' ' + message[1]
                    users[i][3].send(encrypt(data, users[i][1], users[i][2]))
                    # users[i][3]为user_conn，users[i][1]为user_key， users[i][2]为user_iv
                    print(data + '\n')
                    # print(encrypt(data, users[i][1], users[i][2]))

            if isinstance(message[1], list):
                data = json.dumps(message[1])
                for i in range(len(users)):
                    try:
                        users[i][3].send(encrypt(data, users[i][1], users[i][2]))
                    except:
                        pass


s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
s.bind( (IP, PORT) )
s.listen(5)
print('chat server is running on ' + IP + ':'+ str(PORT))

q = threading.Thread(target=send_data)
q.start()

while True:
    conn, addr = s.accept()

    t = threading.Thread(target=recv_msg, args=(conn, addr))
    t.start()