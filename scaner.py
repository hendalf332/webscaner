import argparse
import readchar
import os
import mimetypes
import requests
from requests.exceptions import ConnectionError
from requests.auth import HTTPBasicAuth
import psutil
from itertools import product,combinations
from multiprocessing import Pool,Process,Queue,Lock,Manager
import multiprocessing
import time
from datetime import datetime
import re
from collections import Counter
import sys
import glob
from urllib.parse import urlparse

DEBUGFLAG=False
HELP_MSG=f"""
USAGE python {sys.argv[0]} <URL> -d <PATH_OR_LINK_TO_DICTIONARY>

-d You can add list of dictionaries separated by comma 				
-s you can scan directories on a website
HOTKEYS:
's' - 	suspend scaning
'r' - 	resume scaning
'q' - 	quit program
'n' -   go to the next directory if -s

EXAMPLES:
python {sys.argv[0]} https://www.yourwebsite.com -s -r
python {sys.argv[0]} https://www.yourwebsite.com -N 403,424,505 --not "any string shouldn't be in titles"
python {sys.argv[0]} https://anywebsite.com -d https://github.com/trickest/wordlists/raw/main/technologies/bagisto-all-levels.txt 
"""
if os.name=='nt':
	sep='\\'
else:
	sep='/'
template_list=list()
def clr():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def get_arguments():
    parser=argparse.ArgumentParser(HELP_MSG)
    parser.add_argument('http_template')
    parser.add_argument('-l', required=False, default=None,dest='http_length',help='<MAXURLLENGTH>')
    parser.add_argument('-a', required=False, default=None,dest='useragent',help='<USERAGENT>')
    parser.add_argument('-d', required=False, default=None,dest='dictionary',help='Dictionary(PATH|URL)')
    parser.add_argument('-H', required=False, default=None,dest='header_string',help='Add a custom header to the HTTP request.')
    parser.add_argument('-loc', action="store_true",dest='location',help='Print "Location" header when found')
    parser.add_argument('-N', required=False, default=None,dest='nf_code',help='Ignore responses with this HTTP code.')
    parser.add_argument('-o', required=False, default=None,dest='output_file',help='Save output to disk')
    parser.add_argument('-p', required=False, default=None,dest='proxyaddr_port',help='Use this proxy. (Default port is 1080)')
    parser.add_argument('-P', required=False, default=None,dest='proxy_data',help='Proxy Authentication <username:password>.')
    parser.add_argument('-v',  action="store_true",dest='NOT_FOUND_PAGES',help='Show also NOT_FOUND pages.')
    parser.add_argument('-s',  action="store_true",dest='scan_dirs',help='scan directories on the specific website.')
    parser.add_argument('-r',  action="store_true",dest='recurs',help='search in all found directoies.')
    parser.add_argument('-f',  action="store_true",dest='NOT_FOUND',help='Fine tunning of NOT_FOUND (404) detection.')
    parser.add_argument('-z', required=False, default=None,dest='delay',help='Add a millisecond delay to not cause excessive Flood.')
    parser.add_argument('-c', required=False, default=None,dest='cookie',help='cookiestring')
    parser.add_argument('-n', required=False, default=None,dest='procnum',help='number of processes')
    parser.add_argument('-M', required=False, default=None,dest='extfound',help='Try variations on a found filename.')
    parser.add_argument('-X', required=False, default=None,dest='extvar',help='Add file extensions to wordlist contents.')
    parser.add_argument('--not', required=False, default=None,dest='notintitle',help='Show URLS if not substring in title.')
    parser.add_argument('-u', required=False, default=None,dest='basicauth',help='Basic authorization user:password.')
    parser.add_argument('-E', required=False, default=None,dest='certpath',help='Path to certificate.')
    parser.add_argument('-e', required=False, default=None,dest='excludestr',help='Exclude path from search.')


    options = parser.parse_args()

    return options

def myprint(*msg, **kwargs):
	global DEBUGFLAG
	if DEBUGFLAG:
		print(*msg, **kwargs)

def myinput(*msg, **kwargs):
	global DEBUGFLAG
	if DEBUGFLAG:
		input(*msg, **kwargs)

def find(s, ch):
    return [i for i, ltr in enumerate(s) if ltr == ch]

def superProc(options,queue,number,totalNumber,dirlist,globaldirlist,notexistingdirlist,lock):
	HEADERS= {'User-Agent':'Mozilla/5.0 (X11; U; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.140 Safari/537.36'}
	PROXIES={}
	reqparam={'headers':HEADERS}
	user=password=None
	myprint("superproc started")
	nf_codes=[]
	mimetypes.add_type('text/html','.php',strict=True)
	mimetypes.add_type('text/html','.aspx',strict=True)
	mimetypes.add_type('text/plain','.ini',strict=True)
	mimetypes.add_type('text/plain','.log',strict=True)
	if options.certpath:
		reqparam['verify']=options.certpath
	if options.basicauth:
		username,password=options.basicauth.split(':')
		reqparam['auth']=HTTPBasicAuth(user, password)
	if options.cookie:
		HEADERS['Cookie']=options.cookie
	if options.proxyaddr_port:
		proxyaddr,proxyport=options.proxyaddr_port.split(':')
		PROXIES['http']=f'http://{proxyaddr}:{proxyport}'
		PROXIES['https']=f'https://{proxyaddr}:{proxyport}'
		if options.proxy_data:
			user,password=options.proxy_data.split(':')
			for ky,vl in PROXIES.items():
				PROXIES[ky]=PROXIES[ky].replace(f'{ky}://',f'{ky}://{user}:{password}@')
		print(PROXIES)
		reqparam['proxies']=PROXIES
	if options.useragent:
		HEADERS['User-Agent']=options.useragent
	if options.header_string:
		ky,vl=options.header_string.split(':')
		HEADERS[ky]=vl
		# print(HEADERS)
	if options.nf_code:
		nf_codes=list(map(int,options.nf_code.split(',')))
		myprint(nf_codes)

	while True:


		while not queue.empty():
			title=''
			link=queue.get()	
			myprint(link)
			if link.startswith('TERMINATE'):
				print('superproc TERMINATED')
				return
			precentage=0
			try:
				if totalNumber.value>0:
					precentage=number.value/(totalNumber.value/100)
				if options.delay:
					time.sleep(int(options.delay)/1000)

				path=urlparse(link).path
				website=urlparse(link).scheme+'://'+urlparse(link).netloc
				if '//' in path:
					path=re.sub('\/+','/',path)
				while os.path.dirname(path)!='/':
					path=os.path.dirname(path)
					if not path.endswith('/'):
					
						mypath=path+'/'
					else:
						mypath=path
					reqparam['url']=website+path
					if mypath in globaldirlist or mypath in notexistingdirlist or mypath=='//':
						continue
					else:
						res=requests.get(**reqparam)
						# print(globaldirlist)
						if res.status_code==200 or res.status_code==301:
								if mypath not in globaldirlist:
									globaldirlist.append(mypath)
								else:
									continue

								if not "Index of" in res.text:
									print(f"+++++DIRECTORY {reqparam['url']}")
								else:
									print(f"+++++OPEN DIRECTORY {reqparam['url']}")
								for fl in ['index.html','index.php','default.aspx']:
									try:
										fl=website+mypath+fl
										reqparam['url']=fl
										res=requests.get(**reqparam)
										if res.status_code==200:
											code2=res.status_code
											length2=len(res.text)
											print(f"Default file {fl} exists (CODE={code2}|LEN={length2})")											
									except ConnectionError:
										pass									
						else:
							notexistingdirlist.append(mypath)


				reqparam['url']=link
				res=requests.get(**reqparam)
				code=res.status_code
				contenttType=res.headers['Content-Type']
				contenttType=contenttType.split(';')[0]
				length=len(res.text)
				mimtype=mimetypes.guess_type(link,strict=True)

				if code==200 and options.extfound:
					extfound=options.extfound.split(",")
					for ext in extfound:
						print(link+ext)
						try:
							reqparam['url']=link+ext
							rs=requests.get(**reqparam)
							mimtype=mimetypes.guess_type(link+ext,strict=True)
							if rs.status_code not in nf_codes:
								if rs.status_code in [403,200,301]:
									if mimtype[0]==contenttType:
										print(f"+{link+ext} ((CODE={rs.status_code}|LEN={len(rs.text)}))\n{number.value} Links %{precentage}")
									else:
										print(f"-{link+ext} ((CODE={rs.status_code}|LEN={len(rs.text)}))\n{number.value} Links %{precentage}")
								else:
									print(f"-{link+ext} ((CODE={rs.status_code}|LEN={len(rs.text)}))\n{number.value} Links %{precentage}")
								if options.output_file:
									with open(options.output_file,'a',encoding='utf-8') as fl:
										fl.write(f"+{link+ext} ((CODE={rs.status_code}|LEN={len(rs.text)}))\n")
						except ConnectionError:
							pass

				if options.NOT_FOUND and code==404:
					print(linkres)
					if options.output_file:
						with open(options.output_file,'a',encoding='utf-8') as fl:
							fl.writelines(linkres+"\n")					
				if code not in nf_codes:
					try:
						res1=re.search(r'<title>([^>]+)<\/title>',res.text)
						title=res1[1]
						if options.notintitle and options.notintitle in title:
							continue

						title=re.sub('\s+',' ',title)
						if res1:
							if (not options.NOT_FOUND and code!=404) or (options.NOT_FOUND and code==404) :
								print(f"{link=} Title:{res1[1]}")
								if options.output_file:
									with open(options.output_file,'a',encoding='utf-8') as fl:
										fl.writelines(f"{link=} Title:{res1[1]}\n")



					except TypeError:
						pass
				if 200<=code<=301:
					if contenttType=='text/html' and options.recurs:
						# Scan dirs should be here
						listdirs=dirScan(link,reqparam)

						myprint('listdir ',listdirs)
						for dirr in listdirs:
							myprint(dirr)

							try:
								with lock:								
									if  dirr not in dirlist:
										myprint(f'newdir detected {dirr}')
										myprint(dirlist)
										dirlist.append(dirr)
										myprint(dirlist)
									else:
										listdirs.remove(dirr)
							except multiprocessing.managers.RemoteError:
						 		print("RemoteError")
						with lock:
							if "/" in dirlist:
								dirlist.remove('/')
							dirlist.insert(0,'/')
						websiteurl=re.sub(r'^(\w{3,5}:\/\/(?:[\w\d\._-]+)+)\/.+',r'\1',link)
						myprint(f"{websiteurl=}")
						for dirr in listdirs:
							if dirr in globaldirlist or dirr in notexistingdirlist:
								continue
							url=websiteurl+dirr
							myprint(f"{url=}")
							res=requests.get(url,headers=HEADERS)
							if 200<=res.status_code<400:
								globaldirlist.append(dirr)
								print(f'+++++DIRECTORY {url}')
								if "Index of" in res.text:
									print(f"{url} is opendirectory")
								for fl in ['index.html','index.php','default.aspx']:
									try:
										fl=url+fl
										reqparam['url']=fl
										res=requests.get(**reqparam)
										if res.status_code==200:
											code2=res.status_code
											length2=len(res.text)
											print(f"Default file {fl} exists (CODE2={code2}|LEN2={length2})")											
									except ConnectionError:
										pass
							else:
								if dirr in dirlist:
									myprint(f"remove {dirr} {res.status_code}")
									dirlist.remove(dirr)


							# print(dirlist)

					if mimtype[0]==contenttType or re.search(r"\/\.\w+$",link) and 200<=code<400:
						linkres=f"+{link} (CODE={code}|LEN={length})\n {number.value} %{precentage}"
					else:
						linkres=f"-{link} (CODE={code}|LEN={length}|Type={contenttType}) {mimtype}"
				else:
					linkres=f"-{link} (CODE={code}|LEN={length})"
				if options.location:
				 	headers=res.headers
				 	try:
				 		linkres+=f"Location {headers['Location']}"
				 	except:
				 		pass

				if nf_codes:
					if code not in nf_codes and length>0:
						print(linkres)
						if options.output_file:
							with open(options.output_file,'a',encoding='utf-8') as fl:
								fl.writelines(linkres+"\n")
				else:
					if code!=404 and length>0:
						print(linkres)
						if options.output_file:
							with open(options.output_file,'a',encoding='utf-8') as fl:
								fl.writelines(linkres+"\n")					


			except ConnectionError:
				if options.NOT_FOUND_PAGES:
					print(f"NOT_FOUND_PAGE: {link}")
				myprint("[-]Connection problems")
			finally:
				precentage=0
				if totalNumber.value>0:
					precentage=number.value/(totalNumber.value/100)
				print(f"\rPROGRESS: {number.value} or {totalNumber.value} %{precentage:00.2f}",end='\r')
				number.value+=1

def dirScan(link,reqparam):
	dirlist=list()
	try:
		reqparam['url']=link
		res=requests.get(**reqparam)
		websiteurl=re.sub(r'^(\w{3,5}:\/\/)',r'',link)
		results=re.findall(re.escape(websiteurl)+"((?:\/[\w\d\._-]+)+\/).*",res.text)
		myprint(results)
		for dir in results:
			dirlist.append(dir)		
		results=re.findall(r'href=([\'\"])(\/?(?:[\w\d_-]+\/)+)[^\'\"]+\1',res.text)
		myprint(results)
		for dir in results:
			if dir[1][0]!='/':
				myprint('/'+dir[1])
				dirlist.append('/'+dir[1])
			else:
				dirlist.append(dir[1])
		dirlist=list(set(dirlist))
		return dirlist
	except ConnectionError:
		return dirlist


def scanDirs(websiteurl,HEADERS):
	dirlist=list()
	myprint(f"scanDirs {websiteurl}")
	try:

		res=requests.get(websiteurl,headers=HEADERS)
		websiteurl=re.sub(r'^(\w{3,5}:\/\/)',r'',websiteurl)
		results=re.findall(re.escape(websiteurl)+"((?:\/[\w\d\._-]+)+\/).*",res.text)
		myprint(results)
		for dir in results:
			dirlist.append(dir)

		results=re.findall(r'href=([\'\"])(\/?(?:[\w\d_-]+\/)+)[^\'\"]+\1',res.text)
		myprint(results)
		for dir in results:
			if dir[1][0]!='/':
				myprint('/'+dir[1])
				dirlist.append('/'+dir[1])
			else:
				dirlist.append(dir[1])
		myprint(websiteurl+"/robots.txt+sitemap.xml")
		for file in ["robots.txt","sitemap.xml"]:
			try:
				res=requests.get('https://'+websiteurl+file,headers=HEADERS)
				results=re.findall(r"(?:\s|^)(\/[^\.]+\/)(?:\s*|$)",res.text)
				myprint(results)
				for dir in results:
					myprint(dir)
					dirlist.append(dir)

			except:
				pass			
		dirlist=list(set(dirlist))
		# print(dirlist)
		return dirlist
	except:
		print('no results')
		return dirlist

def myput(queue,options,url):
	if options.excludestr:
		excludestr=options.excludestr
		if '*' in excludestr:
			beg,endstr=excludestr.split('*')
			if url.startswith(beg) and url.endswith(endstr):
				return
			else:
				queue.put(url)
				return
		else:
			if not url.startswith(excludestr):
				queue.put(url)
				return
			else:
				return		
	else:
		queue.put(url)	

def main(dirCounter):
	global DEBUGFLAG
	HEADERS= {'User-Agent':'Mozilla/5.0 (X11; U; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.140 Safari/537.36'}
	queue=Queue()
	chrStr="qwertyuiopasdfghjklzxcvbnm1234567890-_"
	masks_list=[]
	wildcharlist=[]
	stringlist=[]
	all_http_results=[]
	supercharlist=[]
	http_template_list=[]
	word_list=list()
	word_dictionary=None
	PROC_NUM=5
	numbcomb=1 #number of possible urls 
	wordCounter=0
	wordProduct=None


	options=get_arguments()
	extvars=list()
	manager=Manager()
	number=manager.Value('i',0)	
	dirlist=manager.list()
	globaldirlist=manager.list()
	notexistingdirlist=manager.list()
	totalnumber=manager.Value('i',0)	
	lock=manager.Lock()
	if options.extvar:
		extvars=options.extvar.split(',')

	if options.procnum:
		PROC_NUM=int(options.procnum)
	if options.http_template:
		http_template=options.http_template
	

	websiteurl=options.http_template
	procs=[]
	dt=datetime.now()
	print(dt.strftime('START_TIME: %a %b %d %H:%M:%S %Y'))
	for num in range(0,PROC_NUM):
		prc=Process(target=superProc,args=(options,queue,number,totalnumber,dirlist,globaldirlist,notexistingdirlist,lock,))
		prc.start()
		procs.append(prc)	
	if not options.http_length:
		http_length=44

	else:
		http_length=options.http_length
	if options.dictionary:
		dictionaryList=list()
		word_dictionary=options.dictionary
		dictionaryList=options.dictionary.split(',')

	else:
		dictionaryList=glob.glob(os.path.dirname(sys.argv[0])+f"{sep}userdicts{sep}*.txt")
		print(dictionaryList)
		time.sleep(3)

	print(f"WORDLIST_FILES: {dictionaryList} ")
	for word_dictionary in dictionaryList:
		if word_dictionary:
			if re.match(r'^(https?|ftp)',word_dictionary):
				res=requests.get(word_dictionary,headers=HEADERS)
				if res.status_code==200:
					word_list_item=res.text.split('\n')
				else:
					print('[-] The dictionary incorrect')	
					return

			elif os.path.exists(word_dictionary):
				word_list_item=open(word_dictionary,'r',encoding='utf-8').read().split('\n')	
			else:
				word_dictionary=None
				print('[-] The dictionary incorrect')
				return
		word_list.extend(word_list_item)
	word_list=list(set(word_list))
	word_list=[re.sub(r"\d+","",el) for el in word_list if len(el.strip())>2 ]
	totalnumber.value=len(word_list)*(len(extvars)+1)
	print(f"GENERATED WORDS: {totalnumber.value}")
	myinput()

	prevdir=0
	if options.scan_dirs:

		
		websiteurl=re.sub('^(\w{3,5}:\/\/(?:[\w\d_-]+\.)+[\w\d_-]+)\/.*',r'\1',http_template)			
		print(f"URLBASE: {websiteurl}")
		mydirlist=scanDirs(websiteurl,HEADERS)
		with lock:
			for it in mydirlist:
				if not it in dirlist:
					dirlist.append(it)
			for dirr in mydirlist:
				myprint(dirr)
				while dirr!='/':
					dirr=re.sub(r'\/[^/]+\/$','/',dirr)
					if not dirr in dirlist:
						dirlist.append(dirr)

		with lock:
			#dirlist=manager.list(list(set(dirlist)))
			if "/" in dirlist:
				dirlist.remove('/')
			dirlist.insert(0,'/')
			myprint("dirlist ",dirlist)
		# with lock:
			for dirr in dirlist:
				if dirr in globaldirlist or dirr in notexistingdirlist:
					continue
				url=websiteurl+dirr

				res=requests.get(url,headers=HEADERS)
				if 200<=res.status_code<400:
					globaldirlist.append(dirr)
					print(f'+++++DIRECTORY {url}')
					if "Index of" in res.text:
						print(f"{url} is opendirectory")
					for fl in ['index.html','index.php','default.aspx']:
						try:
							fl=url+fl
							res=requests.get(fl,headers=HEADERS)
							if res.status_code==200:
								code=res.status_code
								length=len(res.text)
								print(f"Default file {fl} exists (CODE={code}|LEN={length})")
								queue.put(fl)

						except ConnectionError:
							pass

				else:
					notexistingdirlist.append(dirr)
					dirlist.remove(dirr)
		# with lock:
			myprint(dirlist)

		if options.recurs:
			print("recurs")
			# with lock:
			totalnumber.value=len(word_list)*len(dirlist)
			while dirCounter.value!=len(dirlist):
				for words in word_list:
					if len(dirlist)==0:
						dirIndex=0
						print('len 0')
						break
					else:
						dirIndex=dirCounter.value % len(dirlist)
						time.sleep(0.005)
						curidx=dirlist[dirIndex]
						if prevdir!=curidx:
							print(f"[!]Scan directory {curidx}")
							prevdir=curidx
					url=websiteurl+dirlist[dirIndex]+words
					if extvars:
						myput(queue,options,url)
						for ext in extvars:
							myput(queue,options,url+ext)
					else:
						myput(queue,options,url)					
				dirCounter.value+=1
			for _ in range(PROC_NUM):
				queue.put('TERMINATE')
			for prc in procs:
				prc.join()
			dt=datetime.now()
			print(dt.strftime('END_TIME: %a %b %d %H:%M:%S %Y'))			
			return

	for words in word_list:
		if len(dirlist)==0:
			dirIndex=0
			print('len 0')
			dirlist.append('/')
		else:
			dirIndex=dirCounter.value % len(dirlist)
			time.sleep(0.005)
			curidx=dirlist[dirIndex]
			if prevdir!=curidx:
				print(f"[!]Current directory {curidx}")
				prevdir=curidx
		url=websiteurl+dirlist[dirIndex]+words
		if extvars:
			myput(queue,options,url)
			for ext in extvars:
				myput(queue,options,url+ext)
		else:
			myput(queue,options,url)

	for _ in range(PROC_NUM):
		queue.put('TERMINATE')
	for prc in procs:
		prc.join()
	dt=datetime.now()
	print(dt.strftime('END_TIME: %a %b %d %H:%M:%S %Y'))			
	# input()
	return


if __name__ == '__main__':
	mypid=os.getpid()
	multiprocessing.freeze_support()
	clr()	
	manager=Manager()
	dirCounter=manager.Value('i',0)
	prc=Process(target=main,args=(dirCounter,))
	prc.start()
	while True:
		p=psutil.Process(mypid)
		ch=readchar.readchar()
		try:
			ans=str(ch,encoding='UTF-8').lower()
		except:
			ans=ch.lower()
		if ans=='s':
			print('[!]Suspendprocesses')
			chldlist=p.children(recursive=True)
			for prc in chldlist:
				prc.suspend()
		elif ans=='r':
			print('[!]Resume processes')
			chldlist=p.children(recursive=True)
			for prc in chldlist:
				prc.resume()			
		elif ans=='q':
			print('[!]Terminated processes')
			chldlist=p.children(recursive=True)
			for prc in chldlist:
				prc.kill()	
			sys.exit(0)		
		elif ans=='n':
			dirCounter.value+=1
			print(f"[!] Go to next directory")


