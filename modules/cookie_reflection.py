#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
import sys
import random

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)



def check_cookie_reflection(url, custom_header):
	print("\033[36m ├ Cookies Cache poisoning analyse\033[0m")

	matching_forward = "ndvyepenbvtidpvyzh.com"

	req = requests.get(url, verify=False, timeout=10, headers=custom_header)
	res_cookie = req.cookies

	reflected = False

	cookie_obj = {}

	for rc in res_cookie:
		if rc.value in req.text:
			print("\033[36m --├ {}\033[0m value for the\033[36m {}\033[0m cookie seems to be reflected in text".format(rc.value, rc.name))
			reflected = True
			cookie_obj = {rc.name: matching_forward}
			#s.cookies.set("{}".format(rc.name), "{}".format(matching_forward), domain="{}".format(rc.domain))
		else:
			pass
			#s.cookies.set("{}".format(rc.name), "{}".format(rc.value), domain="{}".format(rc.domain))
			#cookie_obj.update({rc.name: rc.value})
	
	#print(cookie_obj)
	#print(s.cookies)
	for co in cookie_obj:
		payload = "{}={}".format(co, cookie_obj[co])


	if reflected:
		url = "{}?cb={}".format(url, random.randint(0, 1337)) 
		for i in range(10):
			try:
				req_cookie = requests.get(url, cookies=cookie_obj, verify=False)
				#print(req_cookie.text)
			except:
				traceback.print_exc()


	req_verif = requests.get(url, verify=False, headers=custom_header)
	if matching_forward in req_verif.text:
			print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | COOKIE HEADER REFLECTION | \033[34m{}\033[0m | PAYLOAD: Cookie: {}".format(url, payload))
	


if __name__ == '__main__':
	url = "https://0afc0000043c969a805c9e5c00830085.web-security-academy.net/?cb=69"
	#url = "http://httpbin.org/cookies"
	matching_forward = "titi.com"
	cookie_reflection(url, matching_forward)