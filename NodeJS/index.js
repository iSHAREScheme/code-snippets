'use strict';
const fs = require('fs');
const forge = require('node-forge');
const querystring = require('querystring');
const express = require('express')
const request = require('request-promise');
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken');
const parse = require('urlencoded-body-parser')
const csv = require('csv-parser')
const port = process.env.PORT || 1337;

//your information
const base_url = ''
const eori_sp = 'EU.EORI.NLXXXXXXXXX'
const x5c_value_sp = ''

//this works for test environment, but should compare to the trusted_list of iSHARE CAs
const iSHARETestCA  = fs.readFileSync('./linktocert.pem', 'utf8');
const iSHARETestCA_TLS  = fs.readFileSync('./linktocert.pem', 'utf8').toString();;
const caStore = forge.pki.createCaStore([ iSHARETestCA_TLS ]);

//to get key 
const NodeRSA = require('node-rsa');
const privateKey  = fs.readFileSync('./linkto.key.decr.pem', 'utf8');


const results = [];

fs.createReadStream('data.csv')
  .pipe(csv({ separator: ';' }))
  .on('data', (data) => results.push(data))
  .on('end', () => {
    //console.log(results);
    // [
    //   { NAME: 'Daffy Duck', AGE: '24' },
    //   { NAME: 'Bugs Bunny', AGE: '22' }
    // ]
  });

function getCertificatePublicKeyBitLength(pemFile) {
    const certificate = forge.pki.certificateFromPem(pemFile);
    return certificate.publicKey.n.bitLength();
}

function verifyAccessToken(accessToken) {
    //console.log(accessToken);
    
    var epoch = Math.floor(new Date() / 1000)

    var begin_cert = '-----BEGIN CERTIFICATE-----\n'
    var end_cert = '\n-----END CERTIFICATE-----'
    var inn_pem_cert = begin_cert.concat(x5c_value_sp, end_cert);
    
    try{
        var decoded_token = jwt.verify(accessToken, inn_pem_cert, {
            algorithms: 'RS256'
        });
    } catch(err){
        console.log('signature not ours');
        console.log(err);
        return false
    }
    
    //console.log(decoded_token);
    
    if(decoded_token.iss != eori_sp){
        console.log('token not ours');
		return false
	} else{
        return true
    }  
}

const jwtService = require('./jwtService.js')
const generateAccessTokenForClient = require('./generateAccessTokenForClient.js')
const jwtCapabilitiesService = require('./jwtCapabilitiesService.js')
const jwtCapabilitiesServiceAuth = require('./jwtCapabilitiesServiceAuth.js')

const app = express();
//app.use(bodyParser.json()); // support json encoded bodies  
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies

var reqBody = ' ';
var contentLength = ' ';
var authorizationHeader;
var client_id

app.post('/check_ca', async function(req, res) {
	var epoch = Math.floor(new Date() / 1000)
	var body = await req.body
	var ca = body.client_assertion
	//console.log(ca)
    //console.log(body.client_id)
	client_id = body.client_id
	if(!body.client_assertion){
		console.log('Request has no client_assertion.')
		res.status(400).json({
                success: false,
                description: 'Request has no client_assertion.'
        });
		return
	}
	const client_assertion = ca.replace(/\s/g,'')
	
	if(!body.grant_type){
		console.log('Request has no grant type')
		res.status(400).json({
                success: false,
                description: 'Request has no grant type.'
        });
		return
	}
	if(body.grant_type!='client_credentials'){
		console.log('Request has other value than client_credentials.')
		res.status(400).json({
                success: false,
                description: 'Request has other value than client_credentials.'
        });
		return
	}
	if(!body.scope){
		console.log('Request has no scope.')
		res.status(400).json({
                success: false,
                description: 'Request has no scope.'
        });
		return
	}
	if(body.scope!='iSHARE'){
		console.log('Request scope has other value than iSHARE.')
		res.status(400).json({
                success: false,
                description: 'Request has other value than iSHARE.'
        });
		return
	}
	if(!body.client_assertion_type){
		console.log('Request scope has no client_assertion_type.')
		res.status(400).json({
                success: false,
                description: 'Request has no client_assertion_type.'
        });
		return
	}
	if(body.client_assertion_type!='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'){
		console.log('Request has other value than urn:ietf:params:oauth:client-assertion-type:jwt-bearer.')
		res.status(400).json({
                success: false,
                description: 'Request has other value than urn:ietf:params:oauth:client-assertion-type:jwt-bearer.'
        });
		return
	}
	
	if(!body.client_id){
		console.log('Request has no client_id.')
		res.status(400).json({
                success: false,
                description: 'Request has no client_id.'
        });
		return
	}

	
	var decodedClientAssertion = jwt.decode(client_assertion, {
        complete: true
   });
	
	try{
	var x5c = decodedClientAssertion.header.x5c
	}catch(e){
		console.log('wrong ca')
		res.status(400).json({
                success: false,
                description: 'Request has non-valid client_assertion.'
        });
		return
	}
	var alg = decodedClientAssertion.header.alg
	var typ = decodedClientAssertion.header.typ
	
	if(!alg){
		console.log('Client assertion JWT header '+ 'alg'+ ' field missing.')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT header '+ 'alg'+ ' field missing.'
        });
		return
	}
	if(alg.substring(0,2)!='RS'){
		console.log('Client assertion JWT header '+ 'alg'+ ' field is different algorithm than RS.')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT header '+ 'alg'+ ' field is different algorithm than RS.'
        });
		return
	}
	if(alg.substring(2,5)<256){
		console.log('Client assertion JWT header '+ 'alg'+ ' field has lower value than RS256 (i.e. 128, 64 etc)')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT header '+ 'alg'+ ' field has lower value than RS256 (i.e. 128, 64 etc)'
        });
		return
	}
	if(!typ){
		console.log('Client assertion JWT header '+ 'typ'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT header "typ" field missing'
        });
		return
	}
	if(typ!='JWT'){
		console.log('Client assertion JWT header '+ 'typ'+ ' field is other value than '+ 'jwt'+ '')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT header '+ 'typ'+ ' field is other value than '+ 'jwt'+ ''
        });
		return
	}
	if(!x5c){
		console.log('Client assertion JWT header contains no '+ 'x5c'+ ' array')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT header contains no '+ 'x5c'+ ' array'
        });
		return
	}
	var iss = decodedClientAssertion.payload.iss
    var sub = decodedClientAssertion.payload.sub
    var aud = decodedClientAssertion.payload.aud
    var exp = decodedClientAssertion.payload.exp
    var iat = decodedClientAssertion.payload.iat
	var jti = decodedClientAssertion.payload.jti

	if(!iss){
		console.log('Client assertion JWT payload '+ 'iss'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'iss'+ ' field missing'
        });
		return
	}
	if(iss!=client_id){
		console.log('Client assertion JWT payload '+ 'iss'+ ' field is different value from Client_id request parameter')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'iss'+ ' field is different value from Client_id request parameter'
        });
		return
	}
	if(!sub){
		console.log('Client assertion JWT payload '+ 'sub'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'sub'+ ' field missing'
        });
		return
	}
	if(iss!=sub){
		console.log('Client assertion JWT payload '+ 'sub'+ ' field is different value than '+ 'iss'+ ' field')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload "sub" field is different value than '+ 'iss'+ ' field'
        });
		return
	}
	if(!aud){
		console.log('Client assertion JWT payload '+ 'aud'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'aud'+ ' field missing'
        });
		return
	}
	if(aud!=inn_eori){
		console.log('Client assertion JWT payload '+ 'aud'+ ' field is different value than the server iSHARE client id')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'aud'+ ' field is different value than the server iSHARE client id'
        });
		return
	}
	if(!jti){
		console.log('Client assertion JWT payload '+ 'jti'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'jti'+ ' field missing'
        });
		return
	}
	if(!exp){
		console.log('Client assertion JWT payload '+ 'exp'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'exp'+ ' field missing'
        });
		return
	}
	if(exp!=iat+30){
		console.log('Client assertion JWT payload '+ 'exp'+ ' field is different value than '+ 'iat'+ ' field + 30 seconds')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'exp'+ ' field is different value than '+ 'iat'+ ' field + 30 seconds'
        });
		return
	}
	if(!iat){
		console.log('Client assertion JWT payload '+ 'iat'+ ' field missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload "iat" field missing'
        });
		return
	}
	if(iat>epoch+5){
		console.log('Client assertion JWT payload '+ 'iat'+ ' field is after current time')
        console.log(epoch)
        console.log(iat)
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT payload '+ 'iat' + 'field is after current time'
        });
		return
	}
	if(!client_assertion.split('.').slice(2).join('.')){
		console.log('Client assertion JWT signature missing')
		res.status(400).json({
                success: false,
                description: 'Client assertion JWT signature missing'
        });
		return
	}
  
	var x5cStrigified = JSON.stringify(x5c)
	var result = x5cStrigified.substring(2, x5cStrigified.length - 2);
    var begin_cert = '-----BEGIN CERTIFICATE-----\n'
    var end_cert = '\n-----END CERTIFICATE-----'
    var pem_cert = begin_cert.concat(result, end_cert);
    
	try {  
        var decoded = jwt.verify(client_assertion, pem_cert, {
            algorithms: 'RS256'
        });
		var derKey = forge.util.decode64(x5c[0]);
		var asnObj = forge.asn1.fromDer(derKey);
		var asn1Cert = forge.pki.certificateFromAsn1(asnObj);
	
        console.log("Bit length: ", getCertificatePublicKeyBitLength(pem_cert));
        
        if(getCertificatePublicKeyBitLength(pem_cert) < 2048){
		  console.log('key length < 2048')
		  res.status(400).json({
                success: false,
                description: 'invalid client'
            });
		  return
	   }
        
        try {
			forge.pki.verifyCertificateChain(caStore, [asn1Cert]);
			res.status(200).json({
                success: true,
                description: 'verified client_assertion'
            });
		} catch (e) {
			res.status(401).json({
                success: false,
                description: 'Failed to verify certificate'
            });
			//console.log('Failed to verify certificate (' + e.message || e + ')');
		}
		
    } catch (err) {
        //console.log('ERR decoded client_assertion: ' + err)
        console.log(' ')
        if (err == 'TokenExpiredError: jwt expired') {
            res.status(401).json({
                success: false,
                description: 'Client is not authorized by Simply Deliver: JWT is expired.'
            });
            return;
        } else {
			console.log('Client assertion JWT header "x5c" contains invalid certificate')
            res.status(401).json({
                success: false,
                description: 'Client assertion JWT header "x5c" contains invalid certificate'
            });
            return;
        }
    }
})

app.get('/token', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})
app.put('/token', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})
app.patch('/token', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})
app.delete('/token', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})

app.post('/token', async function(req, res) {
    console.log('token request')
    var reqBody = await req.body
    var client_id = reqBody.client_id
    var contentLength = reqBody.length;
    console.log('checking client assertion...');
    
    request({
        headers: {
            'Content-Length': contentLength,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        url: base_url + "/check_ca",
        method: "POST",
        body: querystring.stringify(reqBody)
    }).then(function(response) {
        const responseParsed = JSON.parse(response);
        const status = responseParsed.description
        
        if (status == 'verified client_assertion') {
            console.log('client_assertion checked')   
        } else {
            res.status(400).json({
                status: "Not Active"
            });
        }
        
        console.log('checking iSHARE status...')
        
                    var reqBody = querystring.stringify({
                    'grant_type': 'client_credentials',
                    'scope': 'iSHARE',
                    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion': jwtService.sign(),
                    'client_id': inn_eori
                    });
                var contentLength = reqBody.length;
                request.post({
                    headers: {
                        'Content-Length': contentLength,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    url: "https://scheme.isharetest.net/connect/token",
                    body: reqBody,
                }, async function(error, response, body) {
                    var res_body = await response.body;
                    var parsedData = JSON.parse(res_body);
                    var access_token = parsedData.access_token;
                    //console.log("token => " + access_token);
                    var authorizationHeader = 'Bearer ' + access_token;                        
                                request({
                                    headers: {
                                        'Authorization': authorizationHeader,
                                        'Do-Not-Sign': true
                                    },
                                    url: "https://scheme.isharetest.net/parties?eori=" + client_id,
                                    method: "GET",
                                }).then(function(response) {
                                    
                                    const responseParsed = JSON.parse(response);
                                    console.log(responseParsed)
                                    console.log(client_id)
                                    const status = responseParsed.data[0].adherence.status;
                                    if (status == 'Active') {
                                        const access_token = generateAccessTokenForClient.sign(client_id);
                                        console.log('')
                                        console.log('Access Token for client: ' + access_token)
                                        res.status(200).json({
                                            access_token: access_token,
                                            expires_in: 3600,
                                            token_type: 'Bearer'
                                        });	
                                    } else {
                                        res.status(400).json({
                                            message: 'invalid client'
                                        });	
                                        console.log('status is not active')
                                    }
                                }).catch(function(err) {
                                    console.log('there is an error')
                                    console.log(err)
                                });  
                    })
    }).catch(function(err) {
        res.status(400).json({
            status: "Not Found"
        });
        console.log(err)
    });
})

app.get('/capabilities', async function(req, res) {
    console.log('capabilities')
    var headers = await req.headers;
    
    //return without 'restricted' APIs if no token is given
    if (!headers.authorization){
        console.log('without access token')
        res.status(200).json({
            capabilities_token: jwtCapabilitiesService.sign()
        })
        //res.status(200).send(jwtCapabilitiesService.sign());
    } else if (headers.authorization.substring(0,6) != 'Bearer'){
        
            console.log(headers.authorization.substring(1,6))
            res.status(400).json({
            status: "token invalid"
            });
        
    } else { //if access token is included, check validity and send back 'restricted' APIs as well
        console.log('with access token, verifying access token...')
        
        var token = req.headers.authorization.substring(7);
        
        //here verify that the access token is valid)
        if ( verifyAccessToken(token) == true ){
            
        console.log('access token valid')
        res.status(200).json({
            capabilities_token: jwtCapabilitiesServiceAuth.sign()
            
        }) } else {            
            console.log('access token invalid')
            res.status(401).json({
            status: "token invalid"
            });
            
        }
    }
 })

app.post('/capabilities', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})
app.put('/capabilities', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})
app.patch('/capabilities', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})
app.delete('/capabilities', async function(req, res) { res.status(405).json({ message: 'http wrong method'})})

app.get('/test', async function(req, res) {
    console.log('test API')
    
    try{ 
        var headers = await req.headers;
        var token = req.headers.authorization.substring(7);
    } catch(err){
        console.log(err);
        res.status(400).json({
            status: "token invalid"
            });
    }
        //here verifies that the access token is valid)
        if ( verifyAccessToken(token) == true ){
            
        console.log('access token valid')
	    res.status(200).json({
            
        message: "TEST succesfull"
            
        }) } else {
            
            console.log('access token invalid')
            res.status(401).json({
            status: "token invalid"
            });
            
        }
 });

try {
    const server = app.listen(port, function() {
        console.log('Server is listening on port ' + port);
    });
    //getAccessToken()
} catch (error) {
    console.log('intern server eror: ' + error);
}