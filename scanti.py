#!/usr/bin/env python
# RCE Finder
# By Rudra Sarkar - twitter.com/rudr4_sarkar
import re
import urllib
from header import *
from payload import *

print ga.green+'''
  _______                   _       _       _____       _           _   _             
 |__   __|                 | |     | |     |_   _|     (_)         | | (_)            
    | | ___ _ __ ___  _ __ | | __ _| |_ ___  | |  _ __  _  ___  ___| |_ _  ___  _ __  
    | |/ _ \ '_ ` _ \| '_ \| |/ _` | __/ _ \ | | | '_ \| |/ _ \/ __| __| |/ _ \| '_ \ 
    | |  __/ | | | | | |_) | | (_| | ||  __/_| |_| | | | |  __/ (__| |_| | (_) | | | |
    |_|\___|_| |_| |_| .__/|_|\__,_|\__\___|_____|_| |_| |\___|\___|\__|_|\___/|_| |_|
                     | |                              _/ |                            
                     |_|                             |__/                             
                                                             By Rudra Sarkar - @rudr4_sarkar

  For More help : http://blog.portswigger.net/2015/08/server-side-template-injection.html

        '''+ga.end

def urls_or_list():
	url_or_list = raw_input(" [!] Scan URL or List of URLs? [1/2]: ")
	if url_or_list == "1":
	 	 url = raw_input(" [!] Enter the URL: ")
	 	 
		 if "?" in url:
		 	rce_func(url)
		 else:
			print ga.red +"\n [Warning] "+ ga.end + ga.bold+"%s"%url +ga.end + ga.red +" is not a valid URL"+ga.end			
			print ga.red +" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n"+ ga.end
			exit()
	if url_or_list =="2":
		 urls_list = raw_input( ga.green+" [!] Enter the list file name .e.g [list.txt]: "+ga.end)
		 open_list = open(urls_list).readlines()
		 for line in open_list:
			 if "?" in line:
			 	links = line.strip()
		  	 	url = links
		  	 	print ga.green+" \n [!] Now Scanning %s"%url +ga.end
		  	 	rce_func(url)
			 else:
			 	links = line.strip()
		  	 	url = links
				print ga.red +"\n [Warning] "+ ga.end + ga.bold+"%s"%url +ga.end + ga.red +" is not a valid URL"+ga.end				
				print ga.red +" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n"+ ga.end
		 exit()				

urls_or_list()



