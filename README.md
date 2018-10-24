# Netool - Network Tool

This software provides a number of features for probing computer networks, 
including host discovery and operating-system detection. These features are 
extensible by one simple script that provide more advanced service detection,
vulnerability detection, and various others features.

legal disclaimer: 
Use of this program to cause problems to third parties is not permited by developer, 
educational purposees only. I do not assume any responsibilities for damages caused by this program

The source code is provided with this software because we believe that users have the right to
know exactly what a program will do before you run it.
This also allows you to audit the software for errors in the code and correct them

Usage:
netool.py [-h] [-f FUNCTION] [-in ADRESS] [-t TIMEOUT] [-max MAX OPERATIONS]

arguments:
  -h, --help                                - show help message                        [netool.py -h]
  -f    [FUNCTION],   --function [FUNCTION] - use this argument follow by function     [-f function]
  -in   [CONTENT],    --target [CONTENT]    - use this argument follow by content      [-in adress]
  -t    [TIMEOUT],    --timeout [TIMEOUT]   - Set function timeout                     [-t 1, default = 1]
  -max  [MAX]                               - Set an maximum value                     [-m 1, default = 1]

Main Functions
   - Ports     Check for open ports in specific site           
   - Links     Craw and return all href links                   
   - Robots    Acess site's/robots.txt and return content        
   - Dorks     Search for vulnerable dorks with google hacking   
   - Scrap     Scrap site's SourceCode                           
   - Sitemap   Scrap sitemap.xml Code and return all links       
   
 Real Usage examples:
 - netool.py -f Ports   -in  www.site.com -t 1
 - netool.py -f Links   -in  www.site.com
 - netool.py -f Robots  -in  www.site.com
 - netool.py -f Dorks   -in [search text] [inurl='cart.php?id=12'] -max 50
 - netool.py -f Scrap   -in  www.site.com
 - netool.py -f Sitemap -in  www.site.com

 
 
 
 
