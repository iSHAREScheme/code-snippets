# -*- coding: utf-8 -*-
import jwt
import uuid
import time
import requests

clientID = "EU.EORI.EMILSP"
arID = "EU.EORI.NL000000004"
arURL = "https://ar.isharetest.net"

# Public key
pub_key = b"-----BEGIN CERTIFICATE-----\nMIIE0DCCA7igAwIBAgIILM/vD4393sEwDQYJKoZIhvcNAQELBQAwPDE6MDgGA1UEAwwxVEVTVCBpU0hBUkUgRVUgSXNzdWluZyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBHNTAeFw0yMzAyMjQwOTU3NDVaFw0yNjAyMjMwOTU3NDRaMFwxGjAYBgNVBAMMEUVtaWwgU2lnbWFubiBFbmdoMRcwFQYDVQQFEw5FVS5FT1JJLkVNSUxTUDEPMA0GA1UECgwGaVNIQVJFMRQwEgYDVQQGEwtOZXRoZXJsYW5kczCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANWFv0Pofjj7wRL4xTiJW+8y3Yyt9cHBhDVnvsB89itS/pt905qo5hbkeLsI1Hl4NFHVxp/TmwO0OFmjhyLETbSjakv981s9Kw2pi9WouWwQmAWs33MpGJXGDcI+pXMwxjKqCYqvqZJPg14Xc72cjV1iLyqDJCKbj8QOdN5Il2Av/KBDg6OuFSyNZyjoBDVG3d/dEgR2T548G1Lc/SONNVrm6mvbIXe40oUiWYmSYkStL8dXRz+gisi4xdhvPOV0GJ76xPGuEmR3NW2VQ165zvl0QWSIAd0EkZOHbg3B+iaWZ3g2dsrMyQcmC7KJnk6o6LNNkUse40FpfH/pb8kHHApWC+pGgv8moHoXfNB1xoPrIHiP3NOz5nzcZ6rdIPp7NkuhWonNNrdWeBqMUyZN4n8NrOyXv/MFiKaDeiEqbBPvhlNwk9zS6Ia2gScxzgKRL2Jb6wKGf4rUtNviqbXMZxgEX5Vys5JWhr77GQut QQI4ndkTU8GkcZpDQspBmECg1dhlepLct6eRwKblbpeQkbDfOP4M79mJCsqr5fRHMrbu+4ihJjM3hWBZ9RW3TzVX9ExjLaUrQrQlnOZQZFTuLM8gJZ1pfkM8tk9mINTf VEp1np6dJXfAN9CMtHIvUO2PbLqy4w1805Laeg+qmPnov1ciBCGqExjH+Of8MutP3ZQ3AgMBAAGjgbUwgbIwHwYDVR0jBBgwFoAUbcVlicvfkVTRazy3AqUuzYpokB0w JwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDATA3BggrBgEFBQcBAwQrMCkwCAYGBACORgEBMAgGBgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGAjAdBgNVHQ4EFgQU8N1erImSF3jjw5cGZwwwhnsNsfwwDgYDVR0PAQH/BAQDAgbAMA0GCSqGSIb3DQEBCwUAA4IBAQBlYiOLvVXNqzD3X7hqAiyiy8qg9/GnCNa+LD0v FfElI3xnv0B+BQq5VvsixNTcO4RistdVxGiaKCwEF+hnh9B5ONqA7/6Q9o4tQMd47wiFtyEECLRkuVyWkxQghH7YB8usHoSs6xeiUBbOzhnXzPpf1M85ybIZ3rk5dXwUhnc9IadHVPHS1sgjoZX1Jdc7gfr5K2wmGQPKmxvaHxK2kVPUoGV2bjvUWjAHlRWULbUZlCGCUKAXVqEX2ggjU9owveocqb2cuHljkvSZlbFknANQxl1URkn4h5cKPpcFrtLYzPt14MdnE910wr2V+vhieLzr4JC10IN2ZX0n0Akwszol\n-----END CERTIFICATE-----"

# Private key
priv_key = b"-----BEGIN PRIVATE KEY-----\n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\n-----END PRIVATE KEY-----"
# Create header
# Specifying additional header values ("x5c" & "typ"), in addition to the standard value "alg"
x5c = ["MIIE0DCCA7igAwIBAgIILM/vD4393sEwDQYJKoZIhvcNAQELBQAwPDE6MDgGA1UEAwwxVEVTVCBpU0hBUkUgRVUgSXNzdWluZyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBHNTAeFw0yMzAyMjQwOTU3NDVaFw0yNjAyMjMwOTU3NDRaMFwxGjAYBgNVBAMMEUVtaWwgU2lnbWFubiBFbmdoMRcwFQYDVQQFEw5FVS5FT1JJLkVNSUxTUDEPMA0GA1UECgwGaVNIQVJFMRQwEgYDVQQGEwtOZXRoZXJsYW5kczCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANWFv0Pofjj7wRL4xTiJW+8y3Yyt9cHBhDVnvsB89itS/pt905qo5hbkeLsI1Hl4NFHVxp/TmwO0OFmjhyLETbSjakv981s9Kw2pi9WouWwQmAWs33MpGJXGDcI+pXMwxjKqCYqvqZJPg14Xc72cjV1iLyqDJCKbj8QOdN5Il2Av/KBDg6OuFSyNZyjoBDVG3d/dEgR2T548G1Lc/SONNVrm6mvbIXe40oUiWYmSYkStL8dXRz+gisi4xdhvPOV0GJ76xPGuEmR3NW2VQ165zvl0QWSIAd0EkZOHbg3B+iaWZ3g2dsrMyQcmC7KJnk6o6LNNkUse40FpfH/pb8kHHApWC+pGgv8moHoXfNB1xoPrIHiP3NOz5nzcZ6rdIPp7NkuhWonNNrdWeBqMUyZN4n8NrOyXv/MFiKaDeiEqbBPvhlNwk9zS6Ia2gScxzgKRL2Jb6wKGf4rUtNviqbXMZxgEX5Vys5JWhr77GQutQQI4ndkTU8GkcZpDQspBmECg1dhlepLct6eRwKblbpeQkbDfOP4M79mJCsqr5fRHMrbu+4ihJjM3hWBZ9RW3TzVX9ExjLaUrQrQlnOZQZFTuLM8gJZ1pfkM8tk9mINTfVEp1np6dJXfAN9CMtHIvUO2PbLqy4w1805Laeg+qmPnov1ciBCGqExjH+Of8MutP3ZQ3AgMBAAGjgbUwgbIwHwYDVR0jBBgwFoAUbcVlicvfkVTRazy3AqUuzYpokB0wJwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDATA3BggrBgEFBQcBAwQrMCkwCAYGBACORgEBMAgGBgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGAjAdBgNVHQ4EFgQU8N1erImSF3jjw5cGZwwwhnsNsfwwDgYDVR0PAQH/BAQDAgbAMA0GCSqGSIb3DQEBCwUAA4IBAQBlYiOLvVXNqzD3X7hqAiyiy8qg9/GnCNa+LD0vFfElI3xnv0B+BQq5VvsixNTcO4RistdVxGiaKCwEF+hnh9B5ONqA7/6Q9o4tQMd47wiFtyEECLRkuVyWkxQghH7YB8usHoSs6xeiUBbOzhnXzPpf1M85ybIZ3rk5dXwUhnc9IadHVPHS1sgjoZX1Jdc7gfr5K2wmGQPKmxvaHxK2kVPUoGV2bjvUWjAHlRWULbUZlCGCUKAXVqEX2ggjU9owveocqb2cuHljkvSZlbFknANQxl1URkn4h5cKPpcFrtLYzPt14MdnE910wr2V+vhieLzr4JC10IN2ZX0n0Akwszol"]
             
       #"MIIDSDCCAjCgAwIBAgIISxR3ImzG1BcwDQYJKoZIhvcNAQELBQAwJzElMCMGA1UEAwwcVEVTVCBpU0hBUkUgRm91bmRhdGlvbiBlSURBUzAeFw0xOTAyMjIxMDA0MzFaFw0zOTAyMTcxMDAyNDlaMDwxOjA4BgNVBAMMMVRFU1QgaVNIQVJFIEVVIElzc3VpbmcgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHB2ABQL7zwmi1xIkO0a2q6jIJdn3QAm0s1lSeQev9F2F3M5Z8qiqQJaurMZywZfdNvg9+IqGHOjDe6hIhuRzzoAo0AbO4N9Odf2RDDU95N7toJmAyCiYGgZfZt7BsKFIeQ6p6CsgKcRXPi0fdXdVSHp4bZfQOQdclMbtITirnFtU06NPAhoY676Yz96xFAE0zom6eMVPPOIm0G8gd44XlnbL0w0mccCi2VUZjvCIL59O61O8vlVyLsBqNNTCvf9C2CMYaEatXZyz/lwgH6JYHtD0usXt/+M0qKYe1oeoLk0ZicFZXck1iS09kFdggK5BlNodoWJaDBRro51WhY2WnAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUlZMkybyhCzK5HOBFHKRO+MLSR/4wHQYDVR0OBBYEFG3FZYnL35FU0Ws8twKlLs2KaJAdMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAZH5Qjuq+O9Fpv637g0cF6n1ILYBLz1eNZjEB3doAexvi5CzSw3oswJCSedGW3hh0qHOTK2gI83jh0W2EAn2isFgwhMoG2jd2YSFSkm8Q/2eOfc6MgGSC5sOTL75J7byLCordqd/N4eaj3EqKLaWq7r7ustP81P8EIlz0D8a7lff1FSo23HWXTWX2+m2voLAE5l97aGTGRS1UbxhP2jFKYJ9XziKe9MQJSZElTQ8jqg2kPFkEx/XqAWqlG1dl1ywLJq5iePvK1R4AYNI/YbZQk9slj8v+P/6M7EtErsf2uISgewLTcWl24x3nG5xbQZxrP8l2jSGYmOTIngKOQSnbfg==",
       #"MIIDMzCCAhugAwIBAgIIBLU2cZAZqLEwDQYJKoZIhvcNAQELBQAwJzElMCMGA1UEAwwcVEVTVCBpU0hBUkUgRm91bmRhdGlvbiBlSURBUzAeFw0xOTAyMjIxMDAyNDlaFw0zOTAyMTcxMDAyNDlaMCcxJTAjBgNVBAMMHFRFU1QgaVNIQVJFIEZvdW5kYXRpb24gZUlEQVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrDP2DWX3/b8uMapzEBATSa6iZfvggzIBUExkWEbG9e1nVy/jQk20nfSFMUmRT6NhYcdkSYO/Wrki9Y4EpCy1xvZHqL+4Y6S9JLZwJ760LpYle+NaVu7minMUQcuoj5nKzClvazb00Ax5gkJUfR3v3X5GXqQrkWazMt+k5TNM6TWuJ30qOfwrHx5vTLmTUUih+BsGL3f5GOs1VTYICNhiTjN74n2Wqp2kULWIe+/X6RZ/hKspaHGZnKDVTwI+8ZmWFejuxA6DOX7RsYLKvQO21FmbIBoSs9Azv59/RxWUJVMO0WhDhKpQgCGjwgV32ofNdkFgmdVulzNPID2RNbTTLAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUlZMkybyhCzK5HOBFHKRO+MLSR/4wHQYDVR0OBBYEFJWTJMm8oQsyuRzgRRykTvjC0kf+MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAlzaBVaFhZmH9uxsLSv3FkkxWVwBR1GhAxwcJlV4x+kqX8tchJ4SDLEuWRrF4DNtvSR3r69Kz8eYI5XuW1eG12YjGGVlYijdxrG1ANzGn2vdo9vL7dEFUEMK1AKxRstbTdE7ywzIV/C61w8JrxwLtt9OjdUEUPHuGTjuv5nFBPdFzOcvu+DTMl73CJP2zeZUFguj55MsXY45MrXrbgt+LJqUu4pkB2bLu9FbeRLWZJuknYSrW4fyQBZ2i+MsGdiBKQcf3fLXjpch48/p7SiTk4ufloBaqTClt/EtWXDSmFcv4QjBk1mUPu9vxikcHDkAvJrOXGg0b+3eI4a7OTfAb1g=="]
header = {}
header["typ"] = "JWT"
header["x5c"] = x5c

# Create payload 
iss = clientID
sub = clientID
aud = arID
jti = str(uuid.uuid1())
iat = int(time.time())
exp = int(time.time()) + 30
payload = {}
payload["iss"] = iss
payload["sub"] = sub
payload["aud"] = aud
payload["jti"] = jti
payload["iat"] = iat
payload["exp"] = exp 

# Generate client assertion
client_assertion= jwt.encode(payload, priv_key, headers=header, algorithm="RS256") 

# HTTP POST request header
POST_header = {"Content-type":"application/x-www-form-urlencoded"}

# HTTP POST request body
POST_parameters = {
        "grant_type": "client_credentials",
        "scope":"iSHARE", 
        "client_id":clientID, 
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer", 
        "client_assertion":client_assertion
        }

# Making a post request
POST_req = requests.post(arURL + "/connect/token", headers=POST_header, data=POST_parameters)
print(POST_req)

# Retrieving the access token 
access_token = POST_req.json()["access_token"]

# HTTP POST request header for delegation 
POST_header_dele = {"Authorization":"Bearer " + access_token, 
                    "Content-Type":"application/json"}

# HTTP POST request parameters for delegation 
POST_parameters_dele = {
    "delegationRequest": {
        "policyIssuer":"EU.EORI.EMILEP", 
        "target":{
            "accessSubject":"EU.EORI.EMILSC"
        }, 
        "policySets":[
        {
            "target":{
                "environment":{
                    "licenses":["ISHARE.0001"]
                }
            },
            "policies": [
            {
                "target":{
                    "resource":{
                        "type": "cars",
                        "identifiers": ["urn:cars"],
                        "attributes": ["liscence_plate"]
                    }, 
                    "actions":["GET"]
                },
                "rules":[{"effect":"Permit"}]
            }
            ]    
        }
        ]
    }
}

# Making a POST request to obtain the delegation evidence
POST_req_dele = requests.post(arURL + "/delegation", headers=POST_header_dele, json=POST_parameters_dele)
print(POST_req_dele)

# Filtering to only retreive the encoded jwt delegation
delegation_encoded = POST_req_dele.json()["delegation_token"]

# Decoding the jwt delegation 
delegation_token = jwt.decode(delegation_encoded, options={"verify_signature":False})

# Showing the delegation policy 
print(delegation_token)