import jwt
from datetime import datetime
from datetime import timedelta
import urllib.request
import urllib.parse
import requests
import json
import random
import string
from pathlib import Path
home = str(Path.home())

#basic information on the scheme owner in Test Environment
so_id = "EU.EORI.NL000000000"
base_url = "https://scheme.isharetest.net"

def create_jwt(iss, aud, priv_key, x5c):
    #creating the client_assertion jwt token
    return jwt.encode(
        {
      "iss": iss,
      "sub": iss,
      "aud": aud,
      "jti": ''.join(random.choices(string.ascii_lowercase + string.digits, k=32)),
      "exp": datetime.utcnow() + timedelta(seconds=30),
      "iat": datetime.utcnow(),
      }, priv_key, algorithm='RS256', headers={ 'x5c': x5c})

#gets an access token from the url you feed it, using the parameters and the create_jwt to get a client assertion
def get_token(url, iss, aud, priv_key, x5c):
    return requests.post(url, data =
                  { "grant_type": "client_credentials",
                    "scope": "iSHARE",
                    "client_id": iss,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": create_jwt(iss, aud, priv_key, x5c)
                    })

#returns the /connect/token url from the /capabilities endpoint of a party
def cap_url_to_token_url(cap_url):
    s3 = requests.get(cap_url)

    if s3.status_code != 200:
        print("Could not get capabilities at " + cap_url)

    json_s3 = s3.json()
    cap_token3 = json_s3["capabilities_token"]
    dec_cap_token3 = jwt.decode(cap_token3, verify=False)
    choice_endpoints = dec_cap_token3["capabilities_info"]["supported_versions"][0]["supported_features"][0]["public"]

    nr_endpoints = len(choice_endpoints)
    t = 0

    while t < nr_endpoints:
        endpoint = choice_endpoints[t]
        t += 1
        if endpoint["feature"] == "access token":
            return(endpoint["url"])

#uses the previous three functions to turn any EORI into an access code for that EORI
def EORI_to_token(iss, aud, priv_key, x5c):
    #1) it gets an access token for the Scheme Owner
    so_token = get_token(base_url + "/connect/token", iss, so_id, priv_key, x5c)

        #prints if the access token is received
    if so_token.status_code != 200:
        print("Could not get SO access token.")

        #access token into json object
    json_so_token = so_token.json()
    access_token = "Bearer " + json_so_token["access_token"]

    #2) it uses the access token to get the /capabilities endpoint of the EORI 
    s2 = requests.get(base_url + "/parties" + "?eori=" + aud,
                 headers =
                     {
                        "Authorization": access_token
                      })

    if s2.status_code != 200:
        print("Party does not exist.")
    
    json_s2 = s2.json()
    cap_token2 = json_s2["parties_token"]
    dec_cap_token2 = jwt.decode(cap_token2, verify=False)
    choice_cap_url = dec_cap_token2["parties_info"]["data"][0]["capability_url"]

    #3) it uses the /capabilities endpoint to find the /token endpoint of the party
    choice_token_url = cap_url_to_token_url(choice_cap_url)

    #4) it uses the /token endpoint and the get_token function to get an access token
    return(get_token(choice_token_url, iss, aud, priv_key, x5c))

#nicely prints a Response object (see .requests documentation)
def nice_print(Response):
    formatted = Response.json()
    print(json.dumps(formatted, indent = 4, sort_keys=False))

    

