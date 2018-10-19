# C:\Users\fernandomoreira\AppData\Local\Programs\Python\Python37-32\python.exe C:\Users\fernandomoreira\Documents\Python\Projects\argparser\app.py -h

import argparse
from argparse import RawTextHelpFormatter
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, gethostbyname,getaddrinfo,gethostbyaddr,gethostbyaddr
from datetime import datetime
from time import time, strftime,gmtime

import requests,lxml
import os,sys

from bs4 import BeautifulSoup
from googlesearch import search

func_dicts = {
    'Ports':'get_OpenPorts',
    'Links':"get_Links",
    'Robots':'get_Robots',
    'Dorks':'get_Dorks',
    'Scrap':'get_Sources'
}

def get_OpenPorts(c,t):
    port_dict = {20:'FTP (default data channel)',
        21:'FTP (control channel)',
        23:'Telnet',
        43:'Whois',
        53:'Domain Name System',
        67:'Bootp server',
        68:'Bootp client',
        69:'Trivial FTP',
        70:'Gopher',
        80:'HYPERTEXT TRANSFER PROTOCOL',
        88:'Kerberos',
        109:'POP-2 (Post Office Protocol)',
        110:'POP-3',
        119:'NNTP (Network News Transfer Protocol)',
        123:'NTP (Network Time Protocol)',
        135:'NT RPC endpoint mapper',
        137:'NetBIOS Name Service',
        138:'NetBIOS Datagram Service',
        139:'NetBIOS Session Service',
        143:'IMAP (Internet Message Access Protocol)',
        161:'SNMP',
        162:'SNMP Trap',
        179:'BGP (Border Gateway Protocol)',
        194:'IRC (Internet Relay Chat)',
        216:'Computer Associates License Server',
        256:'Checkpoint Firewall Management',
        257:'Checkpoint Firewall Log Management',
        258:'Checkpoint Firewall Management',
        259:'Checkpoint VPN-1 FWZ Key Management',
        260:'Checkpoint Alternate SNMP',
        261:'Checkpoint Firewall Management',
        264:'Checkpoint Firewall Topology Download',
        265:'Checkpoint VPN-1 Public Key Transfer Protocol',
        389:'LDAP (Lightweight Directory Access Protocol)',
        443:'HTTP over SSL',
        444:'SNPP (Simple Network Paging Protocol)',
        445:'Microsoft Direct SMB',
        464:'Kerberos Password',
        500:'IKE (IPSEC Internet Key Exchange)',
        520:'RIP (Routing Information Protocol)',
        524:'Netware Core Protocol',
        543:'Kerberos Login',
        544:'Kerberos Shell',
        563:'NNTPS (Secure NNTP)',
        599:'HTTP RPC Endpoint Mapper',
        1080:'SOCKS Proxy',
        1081:'SOCKS Proxy alternate',
        1214:'Kazaa Network',
        1241:'Nessus',
        1270:'Microsoft Operations Manager (MOM)',
        1433:'Microsoft SQL Server',
        1434:'Microsoft SQL Monitor service',
        1494:'Citrix',
        1498:'Sybase',
        1521:'Oracle TNS Listener',
        1723:'Point-to-Point Tunneling Protocol (PPTP)',
        1745:'Winsock-proxy',
        2000:'Remotely Anywhere',
        2001:'Cisco device management, Remotely Anywhere',
        2301:'Compaq Insight Manager',
        2381:'Secure Compaq Insight Manager',
        3389:'Terminal Services',
        4001:'Cisco device management',
        5631:'PC Anywhere'}
    port_len = len(port_dict)
    ports_range  = list(port_dict.keys())
    
    try:
        _adress = str(c)
        _timeout = int(t)
        _range = ports_range

        ip = gethostbyname(_adress)

        startTime = time()
        print('''Starting Port scan ({1}) \nPort scan report for ({0})'''.format(ip,datetime.now()))

        print("{0:<10} {1:<10} SERVICE".format("PORT","STATE"))

        for i in range(port_len):
            sock = socket(AF_INET, SOCK_STREAM) #OPEN TCP SOCKET
            sock.settimeout(_timeout)
            port = _range[i]
            if sock.connect_ex((ip, port)) == 0:                    
                print("{0:<10} {1:<10} {2}".format(port,"open",port_dict[port]))

            sock.close() #CLOSE SOCKET
        endTime  = time()

        elapsedTime = endTime-startTime
        finalTime = strftime("%Hh:%Mm:%Ss", gmtime(elapsedTime))
        print("done: 1 IP address ({0}) scanned in {1}".format(ip,finalTime))
    except Exception as error:
        print(error,"critical")
def get_Links (c,t,max):
    _adress = str(c)
    url = str(_adress)

    r = ""
    try:
        try:r = requests.get(url)
        except:pass
        try:r = requests.get("http://{0}".format(url))
        except:pass
        try:r = requests.get("https://{0}".format(url))
        except:pass
        
        data = r.text
        soup = BeautifulSoup(data, "lxml")

        for link in soup.find_all("a"):
            f_link = link.get('href')
            print(f_link)
    except Exception as error:
        print("{0}\nFile: {1}".format(error,os.path.basename(__file__)),"critical")
def get_Robots (c,t,max):
    http=True
    https=True
    wtp=True
    adress = c
    try:
        rContent = " NULL "
        try:
            rurl = '{0}/robots.txt'.format(adress)
            r = requests.get(rurl)
            rContent = r.text
        except Exception as error:
            wtp=False
            pass

        try:
            rurl = 'http://{0}/robots.txt'.format(adress)
            r = requests.get(rurl)
            rContent = r.text
        except Exception as error:
            http= False
            pass

        try:
            rurl = 'https://{0}/robots.txt'.format(adress)
            r = requests.get(rurl)
            rContent = r.text
        except Exception as error:
            https=False
        
        print(rContent)

    except Exception as error:
        print(error)

    print('''\n
Following with [True] 
You can visualize '/robots.txt' 

Following with [False]
You don't have permission to access /robots.txt on this server.

Robots open with following protocols
http://{site}       → {0}
https://{site}      → {1}
{site}              → {2}
    '''.format(http,https,wtp,site=adress))

def get_Dorks (c,t,max):
    text = str(c)
    print("Searching {m} results for '{0}'.. \nmaybe this take a bit longer to complete".format(text,m=max),"alert")
    links = []
    maxLinks = 0
    try:
        results = search(str(text),stop=int(max))
        for urls in results:
            print(urls)
            # links.append("{0}".format(urls))
            maxLinks = maxLinks+1
    except Exception as error:
        print(error)
    finally:
        for i in links:
            print(i)
        print("done!! {0} links found".format(maxLinks))

def get_Sources (c,t,max):
    print(".HTML FILE IN STRING")

if __name__ == "__main__":

# APP DESCRIP AND EPILOG
    desc = ''' The software provides a number of features for probing computer networks, 
 including host discovery and operating-system detection. These features 
 are extensible by scripts that provide more advanced service detection,
 vulnerability detection, and other features. '''

    epilog = '''Main Functions
  - Ports     Check for open ports in specific site             [-f Ports -in www.site.com -t 1]
  - Links     Craw and return all href links                    [-f Links -in www.site.com ]
  - Robots    Acess site's/robots.txt and return content        [-f Robots -in www.site.com]
  - Dorks     Search for vulnerable dorks with google hacking   [-f Dorks -in inurl='cart.php?id=1' -max 1] [max links]
  - Scrap     Scrap site's SourceCode                           [-f Scrap -in www.site.com]
    '''

# PARSER __init__ PROGRAM
    parser = argparse.ArgumentParser(description=desc,epilog=epilog,formatter_class=RawTextHelpFormatter)
    
    parser._optionals.title = " arguments"
    parser.add_argument('-f',   default='None', nargs='?', help=' use this argument follow by function     [-f function]',      dest='Function')
    parser.add_argument('-in',  default='None', nargs='?', help=' use this argument follow by content      [-in adress]',       dest='Content')
    parser.add_argument('-t',   default=1,      nargs='?', help=' Set function timeout                     [-t 1, default = 1]',dest='Timeout')
    parser.add_argument('-max', default=1,      nargs='?', help=' Set an maximum value                     [-m 1, default = 1]',dest='Max')
    
    args = parser.parse_args()

    arg_func=func_dicts[str(args.Function)]
    c = args.Content
    t = args.Timeout
    max = args.Max

    print("\nAcessing {0} > {1} > {2} > {3}\n".format(arg_func,c,t,max))
    try:
        f = globals()[arg_func](c,t,max)
    except Exception as error:
        print(error,"NULL")