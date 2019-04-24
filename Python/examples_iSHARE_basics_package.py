import jwt
from datetime import datetime
from datetime import timedelta
import urllib.request
import urllib.parse
import requests
import json
import random
import string
import iSHARE.basics
from pathlib import Path
home = str(Path.home())

#necessary information to run: your EORI, your x5c of certificate,
#and the path to your private key

#iss will be your EORI
iss = "EU.EORI.NL219048113"
#x5c will be the public part of your certificate, formatted as base64 encoded DER
x5c = ["MIIEfzCCAmegAwIBAgIIenjHQA7HkjEwDQYJKoZIhvcNAQELBQAwSDEZMBcGA1UEAwwQaVNIQVJFVGVzdENBX1RMUzENMAsGA1UECwwEVGVzdDEPMA0GA1UECgwGaVNIQVJFMQswCQYDVQQGEwJOTDAeFw0xODExMjYxMDE3MTZaFw0yMDExMjUxMDE3MTZaMEAxEzARBgNVBAMMCktyaWpuIEIuVi4xHDAaBgNVBAUTE0VVLkVPUkkuTkwyMTkwNDgxMTMxCzAJBgNVBAYTAk5MMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1vtTf1bNurdO/VeYMF1Lm33ut1Ze8HXep1MbiJNFc0J0UtRaDHm/CWvf0RARrqkGkhiCaiz+E0qvyIEHhVpNVD9TtIJVStUX3CzNG9ZKrKC9r/Y7Dcy4KHANnT3W0LfuE3w4RXtbNDPrixfdCGqusG+veTCw1CS7Ean+xb25+tAG2EUdJeSdYV+QWOegTsmE7OoMG5FILunr6/Jt2FNLRE3IHkfbaakNYoliUMzH+/8sJw4GrkvghGcNOfvRQJfstFaN8ibL698wYhDU+xAVuxvgSIn/G9C/hW3z4/ufjKkc13cCAUe2rCpb1rvUKpAfZKnT0LQQGO2i1QTANnqr8wIDAQABo3UwczAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFBY85yDp1pTvH+Wi8bj8vurfLDeBMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBRDWdWHFrD5hYhK8LCfWOhhJIEo7DAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAAV2FD5A4fMsB9Axqwcu8DPXyNXsF3npFuNyO7wYBWnghpLv0hC/B3lP9q84/aJcowC+QA3RPeonU1jRrR+gMWpKpOWFYSA39zoMQ8wZVHPHpwZsU8XRPuLQ+Y1S0CEu5dsjf0byL+bXKh9d4xOEiwzaJ6wZd7kLL+Zv78T3OiNDg5cAnk6kiNacs3H7wrSpnf1dSxzSjr835UkuKXxb+W8vjQroXCZQW1JjdIqyx8cYiGIEBnF56j47Qlk+1eeC4cZH+FXTCDdGpWdzuev/3+3upc5S/2TOEyrR92FqZK2ofC1yA1WzzLUELptrKB4LjMipzOlgKPOyPo9z6DIuPMUOZBGcMaEHBQ4R8EiH2bSKt/FkoTjiEe4CeC5ce8GMypfjiDSDBwIiAUJEC4PfvJQlGL5xrmEMfP+gL411tI5wU7joaAhRZNHi/slRKO9FppwVZw54Vc6V9F0RiyeGdRlNPGc7Mjt0GrnvMk0qr0KGQbq32iOp7nYugnnza0EBLjB4nbPNXzdpPqHVk38ytoAbqr0MkT3ScAbFUFS/d0rn30tSyzV45zLLcOpQfJsNZrRxKZw1v+8kT+wCIfT1TC3MEmmYKX1BKSTa1Yxhgc+0L/Lf3fXAPJsOOZFeKcmHQgSLO0XJZomrGRbnQRYQV+fRVBihjKRnj8DbfDgFKXWg"]
#this code works based on private key stored as .pem, security-wise this should be improved 
privkeyfile = home + '/privkey.pem'
with open(privkeyfile, 'r') as myfile:
    priv_key=myfile.read()


#For demo purposes, we will try it out on Warehouse 13
aud = "EU.EORI.NL000000003"
token_url_aud = "https://w13.isharetest.net/connect/token"


#Generates a client_assertion for the aud (EORI of receiver)
#returns the client_assertion as a string
jwt = iSHARE.basics.create_jwt(iss, aud, priv_key, x5c)

#retrieves an access token based on the url of the /token endpoint of aud
#returns the access_token as a Response object, see documentation of .requests
access_token = iSHARE.basics.get_token(token_url_aud, iss, aud, priv_key, x5c)

#retrieves an access token based on ONLY the EORI of the aud, using the information available at Scheme Owner
#this function is vulnerable to small errors in information at Scheme Owner
eori_token = iSHARE.basics.EORI_to_token(iss, aud, priv_key, x5c)

#prints for example the access token status code
print(access_token.status_code)

#nice_print will print the access token in a readable (JSON) format
iSHARE.basics.nice_print(access_token)

    

