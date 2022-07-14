#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import threading
import json
import time

import tkinter
import tkinter.messagebox
import tkinter.filedialog
from tkinter.scrolledtext import ScrolledText

import rsa
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from binascii import b2a_hex, a2b_hex


IP = ''
PORT = ''
BUFF = 1024

key = get_random_bytes(32)
# key = 'keyskeyskeyskeyskeyskeyskeyskeys' # 使用字符串要加.encode('utf-8')
mode = AES.MODE_CBC
iv = Random.new().read(AES.block_size)
# iv = b'\xd5\x0f\xaa\x8dn\x8a(\xd3\xdcj\x19q\xf0\x01\x93\x10'

t = 0.2
user = ''
listbox_users = ''  # 显示在线用户的列表框
users = []  # 在线用户列表
chat_obj = '--Group chat'  # 聊天对象


# AES加密解密

def encrypt(text):
    text = text.encode('utf-8')

    cryptor = AES.new(key, mode, iv)
    # 这里密钥key 长度必须为16（AES-128）,
    # 24（AES-192）,或者32 （AES-256）Bytes 长度
    # 通常AES-128 足够使用
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

def decrypt(text):
    cryptor = AES.new(key, mode, iv)
    plain_text = cryptor.decrypt(a2b_hex(text))
    # return plain_text.rstrip('\0')
    return bytes.decode(plain_text).rstrip('\0')

# 登录窗口

root_login = tkinter.Tk()
root_login.geometry("300x150")
root_login.title('用户登录窗口')
root_login.resizable(0, 0)
one = tkinter.Label(root_login, width=300, height=150, bg="LightBlue")
one.pack()

IP0 = tkinter.StringVar()
IP0.set('')
USER = tkinter.StringVar()
USER.set('')

labelIP = tkinter.Label(root_login, text='IP地址', bg="LightBlue")
labelIP.place(x=20, y=20, width=100, height=40)
entryIP = tkinter.Entry(root_login, width=60, textvariable=IP0)
entryIP.place(x=120, y=25, width=100, height=30)

labelUSER = tkinter.Label(root_login, text='用户名', bg="LightBlue")
labelUSER.place(x=20, y=70, width=100, height=40)
entryUSER = tkinter.Entry(root_login, width=60, textvariable=USER)
entryUSER.place(x=120, y=75, width=100, height=30)


def login(*args):
    global IP, PORT, user
    IP, PORT = entryIP.get().split(':')
    user = entryUSER.get()
    if not user:
        tkinter.messagebox.showwarning('warning', message='用户名为空！')
    else:
        root_login.destroy()


loginButton = tkinter.Button(root_login, text="登录", command=login, bg="Yellow")
loginButton.place(x=135, y=110, width=40, height=25)
root_login.bind('<Return>', login)

root_login.mainloop()


# 建立连接
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, int(PORT)))


# 交换密钥
print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' start to exchange key!')
s.send('exchangekey'.encode('utf-8'))

modulus = int(s.recv(BUFF).decode('utf-8'))
exponent = int(s.recv(BUFF).decode('utf-8'))

print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' start to build pubkey')
pubkey = rsa.PublicKey(modulus, exponent)

print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' encrypt key')
cipher_key = rsa.encrypt(key, pubkey)
# print(cipher_key)

print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' send encrypted cipher-key')
s.send(cipher_key)

time.sleep(t)  # 暂停，避免处理“粘包”的麻烦

print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' encrypt iv')
cipher_iv = rsa.encrypt(iv, pubkey)
# print(cipher_iv)
print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + ' send encrypted cipher-iv')
s.send(cipher_iv)


# 发送用户名
if user:
    time.sleep(t)
    s.send(encrypt(user))
else:
    s.send(encrypt('用户名不存在'))
    user = IP + ':' + PORT


# 聊天窗口
root_chat = tkinter.Tk()
root_chat.geometry("640x480")
root_chat.title('群聊')
root_chat.resizable(0, 0)
# root_chat.config(bg='#f4f4f4')

# 消息界面
listbox_msg = ScrolledText(root_chat)
listbox_msg.place(x=5, y=0, width=520, height=360)
listbox_msg.tag_config('tag1', foreground='red', background="yellow")
listbox_msg.insert(tkinter.END, '欢迎进入群聊，大家开始聊天吧！', 'tag1')

INPUT = tkinter.StringVar()
INPUT.set('')
entryIuput = tkinter.Entry(root_chat, width=120, textvariable=INPUT)
entryIuput.place(x=5, y=400, width=540, height=32)

# 在线用户列表
listbox_users = tkinter.Listbox(root_chat)
listbox_users.place(x=510, y=0, width=130, height=360)


def send_data(*args):
    message = entryIuput.get() + '~' + user + '~' + chat_obj
    s.send(encrypt(message))
    INPUT.set('')


sendButton = tkinter.Button(root_chat, text='send', anchor='center', command=send_data, font=('Helvetica', 14))
sendButton.place(x=560, y=400, width=65, height=32)
root_chat.bind('<Return>', send_data)


def recv_msg():
    global users_update

    while True:
        data = s.recv(1024)
        data = decrypt(data)
        print(data)
        try:
            users_update = json.loads(data)
            listbox_users.delete(0, tkinter.END)
            listbox_users.insert(tkinter.END, "当前在线用户")
            listbox_users.insert(tkinter.END, "------Group chat-------")
            for x in range(len(users_update)):
                listbox_users.insert(tkinter.END, users_update[x])
            users.append('--Group chat')
        except:
            data = data.split('~')
            message = data[0]
            user_name = data[1]
            chatwith = data[2]
            message = '\n' + message
            if chatwith == '--Group chat':  # 群聊
                if user_name == user:
                    listbox_msg.insert(tkinter.END, message)
                else:
                    listbox_msg.insert(tkinter.END, message)
            elif user_name == user or chatwith == user:  # 私聊
                if user_name == user:
                    listbox_msg.tag_config('tag2', foreground='red')
                    listbox_msg.insert(tkinter.END, message, 'tag2')
                else:
                    listbox_msg.tag_config('tag3', foreground='green')
                    listbox_msg.insert(tkinter.END, message, 'tag3')

            listbox_msg.see(tkinter.END)


r = threading.Thread(target=recv_msg)
r.start()  # 开始线程接收信息

root_chat.mainloop()
s.close()