try:
#────────────────────────────────────────────────────────────────────────────────────────────────────────────
    import os,sys
    from datetime import datetime
    from time import time, strftime,gmtime
    
    import argparse
    from argparse import RawTextHelpFormatter
    
    from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, gethostbyname,getaddrinfo,gethostbyaddr,gethostbyaddr
    import requests,lxml
    
    from bs4 import BeautifulSoup
    from googlesearch import search
    
    import urllib3
    import urllib3.request
    import urlparse3

    import base64

    from ipwhois import IPWhois
    import warnings


    func_dicts = {
        'ports':'get_OpenPorts',
        'links':"get_Links",
        'robots':'get_Robots',
        'search':'get_Dorks',
        'scrap':'get_Sources',
        'sitemap':'get_SitemapXML',
        'sql':'check_SQLInjection',
        'admin':'check_AdminLogin',
        'ipLookup':'ip_Lookup'
        }
    d1 = list(func_dicts)
#────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def get_OpenPorts(c,t,m): # -----------------------------[     OPEN PORTS      ]--------------------
        port_dict = {
            20:'FTP (default data channel)',    21:'FTP (control channel)',                         23:'Telnet',
            43:'Whois',                         53:'Domain Name System',                            67:'Bootp server',
            68:'Bootp client',                  69:'Trivial FTP',                                   70:'Gopher',                        
            80:'HYPERTEXT TRANSFER PROTOCOL',   88:'Kerberos',                                      109:'POP-2 (Post Office Protocol)', 
            110:'POP-3',                        119:'NNTP (Network News Transfer Protocol)',        123:'NTP (Network Time Protocol)',  
            135:'NT RPC endpoint mapper',       137:'NetBIOS Name Service',                         138:'NetBIOS Datagram Service',     
            139:'NetBIOS Session Service',      143:'IMAP (Internet Message Access Protocol)',      161:'SNMP',                         
            162:'SNMP Trap',                    179:'BGP (Border Gateway Protocol)',                194:'IRC (Internet Relay Chat)',    
            216:'Computer Associates License',  256:'Checkpoint Firewall Management',               257:'Checkpoint Firewall Log Management',
            258:'CheckP Firewall Management',   259:'Checkpoint VPN-1 FWZ Key Management',          260:'Checkpoint Alternate SNMP',
            261:'CheckP Firewall Management',   264:'Checkpoint Firewall Topology Download',        265:'Checkpoint VPN-1 Public Key Transfer Protocol',
            270:'Microsoft Operations Manager ',389:'LDAP (Lightweight Directory Access Protocol)', 443:'HTTP over SSL',                
            444:'SNPP(Network Paging Protocol)',500:'IKE (IPSEC Internet Key Exchange)',            520:'Routing Information Protocol', 
            524:'Netware Core Protocol',        543:'Kerberos Login',               
            544:'Kerberos Shell',               563:'NNTPS (Secure NNTP)',                          599:'HTTP RPC Endpoint ', 
            1080:'SOCKS Proxy',                 1081:'SOCKS Proxy alternate',                       1214:'Kazaa Network', 
            1241:'Nessus',                      1433:'Microsoft SQL Server',                        1434:'Microsoft SQL MonitorService',
            1494:'Citrix',                      1498:'Sybase',                                      1521:'Oracle TNS Listener', 
            1723:'Point-to-Point Tunneling Protocol (PPTP)',                                        1745:'Winsock-proxy', 
            2000:'Remotely Anywhere',           2001:'Cisco device management, Remotely Anywhere',  2301:'Compaq Insight Manager', 
            2381:'Secure Cpq Insight Manager',  3389:'Terminal Services',                           4001:'Cisco device management', 
            5631:'PC Anywhere'
            }

        port_len = len(port_dict)
        ports_range  = list(port_dict.keys())    

        try:
            _adress = str(c)
            _timeout = int(t)
            _range = ports_range

            ip = gethostbyname(_adress)

            startTime = time()
            print('''[!] Starting Port scan ({1}) \nPort scan report for ({0})'''.format(ip,datetime.now()))

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
            print("[*] done: 1 IP address ({0}) scanned in {1}".format(ip,finalTime))
        except Exception as error:
            print(error,"critical")
    def host_by_name (address):
        try: return gethostbyname(ip.split("www.")[1])
        except:pass
        try: return gethostbyname("https://%s"%address)
        except:pass
        try: return gethostbyname("www.%s"%address)
        except:pass
        try: 
            return gethostbyname("http://www.%s"%address)
        except Exception as error:
            print(error)
    
    def ip_Lookup (c,t,max): # ------------------------------[     IP LOOKUP       ]--------------------
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore",category=UserWarning)
            ip = str(c)
            
            add = host_by_name(ip)

            obj = IPWhois(add,5)
            res = obj.lookup_whois()

            print("\n")
            print("IP Lookup results for '{0}' [{1}]".format(ip,add))
            for els in res:                                                 #GET OBJ RESULT
                val = "{0}".format(els)
                res_els = res[val]
                if res_els is not None:                                     #IF ACTUAL OBJECT HAVE CONTENT
                    if val == 'nets':
                        nets_D = res_els[0]
                        for k in nets_D:                                    #GET KEYS OF DICTS TO VIEW CONTENT
                            content = nets_D.get(k)
                            result = "{0:<20} {1}".format(k,content)
                            print(result)                                   #RESULTS OF NETS INFORMATIONS
                    else:                                                   #GET CONTENT IF IS NOT DICT
                        result = "{0:<20} {1}".format(els,res_els)
                        print(result)                                       #RESULTS OF COMMOM INFORMATIONS
            print("\n")
    def get_Links (c,t,max): # ------------------------------[       LINKS         ]--------------------
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
    def get_Robots (c,t,max): # -----------------------------[       ROBOTS        ]--------------------
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

            print("-"*100)
            print(rContent)
            print("-"*100)

        except Exception as error:
            print(error)

        print('''\nRobots open with following protocols
     http://{site}       → {0}
     https://{site}      → {1}
     {site}              → {2}'''.format(http,https,wtp,site=adress))
    def get_Dorks (c,t,max): # ------------------------------[       DORKS         ]--------------------
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
    def get_Sources (c,t,max): # ----------------------------[ SOURCE CODE (SCRAP) ]--------------------
        print(c)
        _adress = str(c)
        url = str(_adress)
        r = ""

        try:
            try:    r = requests.get(url)
            except: pass
            try:    r = requests.get("http://{0}".format(url))
            except: pass                
            try:    r = requests.get("https://{0}".format(url))
            except: pass
        except Exception as error:
            print("{0}\n\nFile: {1}".format(error,os.path.basename(__file__)),"critical")
        
        data = r.text
        print("\n\n{0}\n\n".format(data))
#────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def getRequests (c):    # ---------- SUB FUNCTION XMLMAP 1 -----------
        try:
            get_url = requests.get(str("http://{0}/sitemap.xml".format(c)))
            return get_url    
        except:pass
        try:
            get_url = requests.get(str("https://{0}/sitemap.xml".format(c)))
            return get_url 
        except:pass
        try:
            get_url = requests.get("{0}/sitemap.xml".format(c))
            return get_url
        except:pass
    def xmlMapString (c):   # ---------- SUB FUNCTION XMLMAP 2 -----------
        try:
            get_url = getRequests(c)

            if get_url.status_code == 200:
                return get_url.text
            else:
                print("Unable to fetch sitemap: %s ." % c)

        except Exception as error:
            print(error)
    def processSitemap (c): # ---------- SUB FUNCTION XMLMAP 3 -----------
        sitemapText = xmlMapString(c)
        soup = BeautifulSoup(sitemapText,'lxml')
        results = []

        for loc in soup.find_all('loc'):
            results.append(loc.text)
        return results
    def get_SitemapXML (c,t,max):#---------------------------[     SITEMAP  XML    ]--------------------
        print("[!] Trying to request '/sitemap.xlm' wait until process complete.")
        sitemapLinks = processSitemap(c)
        lines = 0
        
        for l in range(len(sitemapLinks)):
            print(sitemapLinks[l])
            lines = lines+1
        print("[!] done {0} links found in '{1}/sitemap.xml'".format(lines,c),"\n")
#────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def check_SQLInjection(c,t,max): # ----------------------[    SQL INJECTION    ]--------------------
        url = c
        print("FINISHED SCAN")
    def requestSiteContent (c):
        try:
            get_url = requests.get(str("http://{0}".format(c)))
            return get_url.text
        except:pass
        try:
            get_url = requests.get(str("https://{0}".format(c)))
            return get_url.text
        except:pass
        try:
            get_url = requests.get("{0}".format(c))
            return get_url.text
        except:pass
    def check_AdminLogin (c,t,max):  # ----------------------[    ADMIN BRUTEFORCE ]--------------------
        print("[!] Testing login with 420 words [04m:20s to test all words]")
        link = str(c)
        startTime = time()

        try:
            try:
                urlGit = "raw.githubusercontent.com/zisongbr/Network-Tools/master/admin_wordlist.txt"
                req = str(requestSiteContent(urlGit))
                rcontent = req.split('\n')
                
                for i in range(len(rcontent)):
                    adLink = '{0}/{1}'.format(link,rcontent[i])
                    
                    try:adReq = requests.get('https://'+adLink)
                    except:pass
                    try:adReq = requests.get('http://'+adLink)
                    except:pass
                    try:adReq = requests.get(adLink)
                    except:pass
                    
                    if adReq.status_code == 200:
                        print("[*] login found → [%s] \n" %adLink)
                        break
                    else:
                        print(adLink)

                endTime  = time()
                elapsedTime = endTime-startTime
                finalTime = strftime("%Hh:%Mm:%Ss", gmtime(elapsedTime))
                print("[!] done!!, its take '{0}'".format(finalTime))

            except Exception as error:
                print(error)
        except KeyboardInterrupt:
            print("[!!!] [Ctrl+C] SCAN CANCELED BY spUSER")
#────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def get_all_info(f):
        dorks_url = 'raw.githubusercontent.com/zisongbr/Network-Tools/master/dorks.txt'
        tmp_dorks = requestSiteContent(dorks_url)
        dorkslist = list(tmp_dorks.split('\n'))
    # ------ [DETAILED HELP PANEL '-info'] ---------
        h_dict = {
    #----- ADMIN --------------------
        'admin':'''
        Usage: 
        -f admin -in www.site.com -t 1

        Function Requeriments:
        -in  -> site url to search for login page that is www.site.com to generate www.site.com/login.php
        -t   -> connection timeout
        ''',
    #------ PORTS -----------------
        'ports':'''
        Usage:
        -f ports -in www.site.com -t 1

        Function Requeriments:
        -in  -> site to scan for open ports
        -t   -> timeout betwen ports

        ''',
    #------ SEARCH ---------------
        'search':'''
        Usage: 
        -f search -in inurl:login.php -max 10

        Function Requeriments:
        -in  -> inurl dork or any other search results
        -max -> Number of results to search for

        Real dorks examples:
        -in view_items.asp?id=
        -max 50

        [?] to see all available dorks 
        
        search for dork wordlist                        > '-info dork_list'
        view Advanced Operators of google dork search   > '-info adv_operators'
        
        '''
        }
    
        dork_advOpt = '''    
        Operator:      Purpose:                         Example:
        intitle:       Search page title                ' Admin login'
        allintitle:    Search page title                ' Admin login'
        inurl:         Search URL                       ' addToCart.php?idProduct= / admin.php / users.php'
        allinurl:      Search URL                       ' admin.php / users.php'
        filetype:      Search specific files            ' .php / .txt / .xlcs / .html'
        allintext:     Search text of page only         ' Admin directory / MySQL syntax error'
        site:          Search specific site             ' SpecificSiteDomain'
        link:          Search for links to pages        ' Admin/Login.php'
        inanchor:      Search link anchor text          ' Dorks list / Leaked documents'
        daterange:     Search in date range             ' 1 / 9 / 80'
        numrange:      Locate number                    ' 1944 / 2018 / "29/10/2018"'
        author:        Group author search              ' H.P Lovecraft / Eduardo Sphor'
        group:         Group name search                ' Hacking / Health Care'
        insubject:     Group subject search             ' Best seller '
        msgid:         Group msgid search"              ' 10 / 90 / 99 / 101 / x  '

        [?] To use more than one operator try:
            -f search -in "inurl:users_acess filetype:.php OR filetype:.html intitle:Users informations" 
            -f serach -in="inurl:passwords filetype:.txt or filetype:.php"
        '''
        
        dorks_example = '''
        Inurl Examples:
            addcart.php?
            addItem.php
            add-to-cart.php?ID=
        Usage:
        -f search -in 'OPERATOR':DORK
        -f serach -in
        
        '''

        cmd_info = ["dork_list","adv_operators","dork_examples"]

        if f == cmd_info[0]:
            for line in range(len(dorkslist)):
                print(dorkslist[line])
        if f == cmd_info[1]:
            print(dork_advOpt) 
        if f == cmd_info[2]:
            print()
        if f not in cmd_info:
            print(h_dict[str(f)])
#────────────────────────────────────────────────────────────────────────────────────────────────────────────
    if __name__ == "__main__":
    # APP DESCRIP AND EPILOG
        banner_a = '''
   _   _          _                     _ 
  | \ | |        | |                   | |
  |  \| |   ___  | |_    ___     ___   | |
  | . ` |  / _ \ | __|  / _ \   / _ \  | |
  | |\  | |  __/ | |_  | (_) | | (_) | | |
  |_| \_|  \___|  \__|  \___/   \___/  |_|
  by: Fernando Ferreira Moreira
  '''

        desc = '''
  [?] This software provides a number of features for probing computer networks, 
  including host discovery and operating-system detection. These features are 
  extensible by one simple script that provide more advanced service detection,
  vulnerability detection, and various others features.

  [!] legal disclaimer:
  Usage of this program to cause problems to third parties is not permited by developer, 
  educational purposees only. I do not assume any responsibilities for damages caused by this program

  The source code is provided with this software because we believe that users have the right to
  know exactly what a program will do before you run it.
  This also allows you to audit the software for errors in the code and correct them'''

        epilog = ''' Main Functions:
    - {a:<10} Check for open ports in specific site                    [-f {a:<8} -in www.site.com -t 1]
    - {b:<10} Craw and return all href links                           [-f {b:<8} -in www.site.com ]
    - {c:<10} Acess site's/robots.txt and return content               [-f {c:<8} -in www.site.com]
    - {d:<10} Search for vulnerable dorks with google hacking          [-f {d:<8} -in 'YOU DORK HERE' -max 1]
    - {e:<10} Scrap site's SourceCode                                  [-f {e:<8} -in www.site.com]
    - {f:<10} Scrap sitemap.xml Code and return all links              [-f {f:<8} -in www.site.com]
    - {g:<10} Check if website is classic SQL and if is vulnerable     [-f {g:<8} -in www.site.com/cart.php?id=1]
    - {h:<10} Check connections in wordlist for admin url login        [-f {h:<8} -in www.site.com]
    - {i:<10} Run a IP Lookup and return all host information          [-f {i:<8} -in www.site.com]

    [?] To see all documentation about an function. Use '-info function' or '--get_info=function'
    [?] If you need to put 'SPACES' in function content use -f "function" -in "content"

    example: 
    -f search -in "FOO BAR" or 
    -f search -in="FOO BAR"

        '''.format(a=d1[0],b=d1[1],c=d1[2],d=d1[3],e=d1[4],f=d1[5],g=d1[6],h=d1[7],i=d1[8])
        usage= "netool.py [-h] [-f FUNCTION] [-in ADRESS] [-t TIMEOUT] [-max MAX OPERATIONS]"
        
        parser = argparse.ArgumentParser(description=banner_a + desc,epilog=epilog,usage=usage,formatter_class=RawTextHelpFormatter)
        
        parser._optionals.title = " Arguments usage"

        parser.add_argument('-info','--get_info',default='None', nargs='?', help=' get more info about one specific module  [-info funcion',        dest='Info') 
        parser.add_argument('-f',"--function",   default='None', nargs='?', help=' use this argument follow by function     [-f function]',         dest='Function')
        parser.add_argument('-in',"--target",    default='None', nargs='?', help=' use this argument follow by content      [-in adress]',          dest='Content')
        parser.add_argument('-t',"--timeout",    default=1,      nargs='?', help=' Set function timeout                     [-t 1, default = 1]',   dest='Timeout')
        parser.add_argument('-max',"--maximum",  default=10,     nargs='?', help=' Set an maximum value                     [-max 1, default = 10]',dest='Max')
        
    try:
        line_arg = "="*100
        args = parser.parse_args()

        if args.Info == 'None':        
            arg_func=func_dicts[str(args.Function)]
            
            c = args.Content
            t = args.Timeout
            max = args.Max
            
            h = datetime.now()
            st = strftime("%H:%M:%S")
            print(line_arg,"\n[{0}] [START] Start '{f}' service at '{ctt}'".format(st,f=args.Function,ctt=c))
            
            f = globals()[arg_func](c,t,max)
            
            ct = strftime("%H:%M:%S")
            print("[{0}] [COMPLETED] Completed '{f}' service in '{ctt}'\n".format(ct,f=args.Function,ctt=c),line_arg)

        else:
            sel_help_func = args.Info
            st = strftime("%H:%M:%S")
            print(line_arg,"\n[{0}] [START] Start 'info' in '{f}'".format(st,f=sel_help_func))

            get_all_info(sel_help_func)
            
            ct = strftime("%H:%M:%S")
            print("[{0}] [COMPLETED] Completed 'info' in '{f}' \n".format(ct,f=sel_help_func),line_arg)

    except Exception as error:
        print(error,'[!!] you need a content first . ')

except KeyboardInterrupt:
    print('''\n[!!!]          [Ctrl + C > KEYBOARD INTERRUPT]         [!!!]''')