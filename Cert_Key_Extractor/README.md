Just dowload the script file and make sure it is executable

Usage: ./ckxp12.sh p12filename

Note: it prompts for p12 file password which you should have in order to extract these files.

Shell script which accepts p12 file and extracts following files        
[p12filename]pub.pem - having just the public cert                      
[p12filename]pubfc.pem - full chain of public cert             
[p12filename]pubx5c.pem - full chain of public cert in x5c format ready to use          
[p12filename]priv.key - unencrypted private RSA key                     
                                                                    
Note: the above files are created in current directory where the script is executed                
                                                                    
Version 1.0                                                             
Developed by: Rajiv Rajani                           
Disclaimer: Please handle private keys with care and securely, author is not responsible in any way for any damage caused.