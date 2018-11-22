cd %cd%
cls

@ECHO OFF
@ECHO.
@ECHO    [?] This software provides a number of features for probing computer networks, 
@ECHO    including host discovery and operating-system detection. These features are 
@ECHO    extensible by one simple script that provide more advanced service detection,
@ECHO    vulnerability detection, and various others features.
@ECHO.
@ECHO    [!] legal disclaimer:
@ECHO    Usage of this program to cause problems to third parties is not permited by developer, 
@ECHO    educational purposees only. I do not assume any responsibilities for damages caused by this program
@ECHO.
@ECHO    The source code is provided with this software because we believe that users have the right to
@ECHO    know exactly what a program will do before you run it.
@ECHO    This also allows you to audit the software for errors in the code and correct them
@ECHO.
@ECHO.
@ECHO     arguments:
@ECHO      -h, --help            show this help message and exit
@ECHO      -info [INFO], --get_info [INFO]
@ECHO                             get more info about one specific module  [-info funcion
@ECHO      -f [FUNCTION], --function [FUNCTION]
@ECHO                             use this argument follow by function     [-f function]
@ECHO      -in [CONTENT], --target [CONTENT]
@ECHO                             use this argument follow by content      [-in adress]
@ECHO      -t [TIMEOUT], --timeout [TIMEOUT]
@ECHO                             Set function timeout                     [-t 1, default = 1]
@ECHO      -max [MAX], --maximum [MAX]
@ECHO                             Set an maximum value                     [-max 1, default = 10]
@ECHO.
@ECHO     Main Functions
@ECHO        - ports      Check for open ports in specific site                    [-f ports    -in www.site.com -t 1]
@ECHO        - links      Craw and return all href links                           [-f links    -in www.site.com ]
@ECHO        - robots     Acess site's/robots.txt and return content               [-f robots   -in www.site.com]
@ECHO        - search     Search for vulnerable dorks with google hacking          [-f search   -in 'YOU DORK HERE' -max 1]
@ECHO        - scrap      Scrap site's SourceCode                                  [-f scrap    -in www.site.com]
@ECHO        - sitemap    Scrap sitemap.xml Code and return all links              [-f sitemap  -in www.site.com]
@ECHO        - sql        Check if website is classic SQL and if is vulnerable     [-f sql      -in www.site.com/cart.php?id=1]
@ECHO        - admin      Check connections in wordlist for admin url login        [-f admin    -in www.site.com]
@ECHO        - ipLookup   Run a IP Lookup and return all host information          [-f ipLookup -in www.site.com]
@ECHO.
@ECHO        [?] To see all documentation about an function. Use '-info function' or '--get_info=function'
@ECHO        [?] If you need to put 'SPACES' in function content use -f "function" -in "content"
@ECHO.
@ECHO        example:
@ECHO        -f search -in "FOO BAR" or
@ECHO        -f search -in="FOO BAR"
@ECHO.
@ECHO.

SET /p funct="Select Function :" 
SET /p content="Select Target   :" 

py.exe netool.py -f %funct% -in %content%

pause