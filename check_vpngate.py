#!/usr/bin/python3.8
#coding=utf8

import requests
from contextlib import closing
import base64
import socket
import datetime

proxy_servers = {
	'http': 'http://192.168.1.1:8888',
	'https': 'http://192.168.1.1:8888',
}
#成功连接的配置文件保存路径
output_path = "/home/vpngate/"

def filter_config(c) :
	conf = ""
	p = ""
	s = ""
	t = ""
	for i in c.decode().split("\r\n") :
		if i[:1] != "#" and i[:1] != ";" and len(i)>0 :     #跳过注释和空行
#			print("({}) {}".format(len(i),i))
			conf = conf + i + "\r\n"
			if i == "proto tcp" :
				p = "tcp"
			elif i == "proto udp" :
				p = "udp"
			if i[:6] == "remote" :
				s = i.split(" ")[1]
				t = i.split(" ")[2]
	return p,s,t,conf
			
def scan(SCAN_IP, port):
	result = False
	"""使用socket扫描主机是否开放某个端口"""
	# 创建socket
	scan_socket = socket.socket()
	# 设置超时时间
	scan_socket.settimeout(10)
	# s.connect_ex()  connect()函数的扩展版本,出错时返回出错码,而不是抛出异常
	if scan_socket.connect_ex((SCAN_IP, port)) == 0:  # 当返回0时, 表示端口开放
		# 记录开放的端口
		result = True
		print("success")
	else :
		print("timeout")
	# 必须关闭这个套接字
	scan_socket.close()
	return result
	
def check(vpn):
	if vpn[:1] != "#" and vpn[:1] != "*" :
		data=vpn.split(",")
		if len(data) > 10 :
			print("checking {}({})".format(data[0],data[6]))
			proto, server, port, config = filter_config(base64.b64decode(data[14]))
			print("  config: {}, {}:{} ".format(proto,server,port), end=" ")
      #只检查TCP协议的，UDP不检查
			if proto == "tcp" :
				if scan(server, int(port)) :
          #保存成功连接端口的配置文件：日期－名称－国别.ovpn
					filename = datetime.datetime.now().strftime('%Y-%m-%d')+"-"+data[0]+"-"+data[6] +".ovpn"
					fo = open(output_path + filename, "w")
					fo.write(config)
					fo.close()
			else :
				print("skip")
		
def get_pag():
	url = "http://www.vpngate.net/api/iphone/"
	# 读取数据
	with closing(requests.get(url, stream=True, proxies=proxy_servers)) as r:
		print("headers: {}".format(r.headers))
		f = (line.decode('utf-8') for line in r.iter_lines())
		for k in f:
			check(k)

if __name__ == '__main__':
	reader = get_pag()
