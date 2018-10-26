# Netool - Network Tool
    
**[?] This software provides a number of features for probing computer networks,
including host discovery and operating-system detection. These features are
extensible by one simple script that provide more advanced service detection,
vulnerability detection, and various others features.**

**_[!] legal disclaimer:_**
**Usage of this program to cause problems to third parties is not permited by developer,
educational purposees only. I do not assume any responsibilities for damages caused by this program**

**The source code is provided with this software because we believe that users have the right to
know exactly what a program will do before you run it.
This also allows you to audit the software for errors in the code and correct them**


**arguments:**  
	-h, 			--help            			show this help message and exit
	-info [INFO], 	--get_info [INFO]         	get more info about one specific module  [-info funcion
	-f [FUNCTION], 	--function [FUNCTION]    	use this argument follow by function     [-f function]
	-in [CONTENT], 	--target [CONTENT]       	use this argument follow by content      [-in adress]
	-t [TIMEOUT], 	--timeout [TIMEOUT]       	Set function timeout                     [-t 1, default = 1]
	-max [MAX], 	--maximum [MAX]             Set an maximum value                     [-max 1, default = 10]

**Main Functions:**  
	- ports      Check for open ports in specific site                    [-f ports    -in www.site.com -t 1]
	- links      Craw and return all href links                           [-f links    -in www.site.com ]
	- robots     Acess site's/robots.txt and return content               [-f robots   -in www.site.com]
	- search     Search for vulnerable dorks with google hacking          [-f search   -in 'YOU DORK HERE' -max 1]
	- scrap      Scrap site's SourceCode                                  [-f scrap    -in www.site.com]
	- sitemap    Scrap sitemap.xml Code and return all links              [-f sitemap  -in www.site.com]
	- sql        Check if website is classic SQL and if is vulnerable     [-f sql      -in www.site.com/cart.php?id=1]
	- admin      Check connections in wordlist for admin url login        [-f admin    -in www.site.com]

**_[?] To see all documentation about an function. Use '-info function' or '--get_info=function'  
[?] If you need to put 'SPACES' in function content use -f "function" -in "content"_**  

**example: **  
-f search -in "FOO BAR" or
-f search -in="FOO BAR"

**_netool.py - 24.10.2018_**  
**_Author : Fernando Moreira - nandoferreira_prof@hotmail.com_**  
**_CC0 - 2018 Creative Commons_**  
