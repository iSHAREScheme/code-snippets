'use strict';
const fs = require('fs');
const forge = require('node-forge');
const querystring = require('querystring');
const express = require('express')
const request = require('request-promise');
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken');
const parse = require('urlencoded-body-parser')

const iSHARETestCA  = fs.readFileSync('./iSHARETestCA.cacert.pem', 'utf8');
const iSHARETestCA_TLS  = fs.readFileSync('./iSHARETestCA_TLS.cacert.pem', 'utf8').toString();;
const caStore = forge.pki.createCaStore([ iSHARETestCA_TLS ]);



const jwtService = require('./jwtService.js')
const generateAccessTokenForClient = require('./generateAccessTokenForClient.js')
const jwtCapabilitiesService = require('./jwtCapabilitiesService.js')

const app = express();
//app.use(bodyParser.json()); // support json encoded bodies  
app.use(bodyParser.urlencoded({ extended: false })); // support encoded bodies

var reqBody = ' ';
var contentLength = ' ';
var authorizationHeader;
var client_id

app.post('/checkclientassertion', async function(req, res) {
    console.log('checkclientassertion');
	console.log('')
	var epoch = Math.floor(new Date() / 1000)
	const body = await parse(req)
	var ca = body.client_assertion
	//console.log(ca)
	//console.log(body)
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
	if(aud!='xxxxxxx'){
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
	if(iat>epoch){
		console.log('Client assertion JWT payload '+ 'iat'+ ' field is after current time')
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
    var reas = begin_cert.concat(result, end_cert);
	//console.log('reas: '+ reas)
	try {      
        var decoded = jwt.verify(client_assertion, reas, {
            algorithms: 'RS256'
        });
        console.log('verified client_assertion: ' + JSON.stringify(decoded))
        console.log(' ')
		var derKey = forge.util.decode64(x5c[0]);
		var asnObj = forge.asn1.fromDer(derKey);
		var asn1Cert = forge.pki.certificateFromAsn1(asnObj);
		try {
			forge.pki.verifyCertificateChain(caStore, [asn1Cert]);
			res.status(401).json({
                success: true,
                description: 'Verified client_assertion:'
            });
			console.log('verified')
		} catch (e) {
			res.status(401).json({
                success: false,
                description: 'Failed to verify certificate'
            });
			console.log('Failed to verify certificate (' + e.message || e + ')');
		}
		
    } catch (err) {
        console.log('ERR decoded client_assertion: ' + err)
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
    console.log(' ')
})

app.get('/gotoishareforaccesstoken', async function(req, res) {
    console.log('gotoishareforaccesstoken')
    var reqBody = querystring.stringify({
        'grant_type': 'client_credentials',
        'scope': 'iSHARE',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': jwtService.sign(),
        'client_id': 'xxxxxx'
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
        console.log('')
		console.log('Access Token for us : ' + res_body);
        var parsedData = JSON.parse(res_body);
        var access_token = parsedData.access_token;
        //console.log("token => " + access_token);
        authorizationHeader = 'Bearer ' + access_token;
        //getTrustedList(authorizationHeader);
        if (access_token) {
            res.status(200).json({
                success: true
            });
        } else {
            res.status(400).json({
                success: false,
                description: res_body
            });
        }
    })
})

app.get('/getparties', async function(req, res) {
	console.log('')
    console.log('getparties')
    
    request({
        headers: {
            'Authorization': authorizationHeader,
            'Do-Not-Sign': true
        },
        url: "https://scheme.isharetest.net/parties/" + client_id,
        method: "GET",
    }).then(function(response) {
		console.log('')
        const responseParsed = JSON.parse(response);
        const status = responseParsed.adherence.status
        console.log('GetParties: ' + response)
        console.log('adherence.status: ' + status)
        console.log()
        console.log('Party name: ' + responseParsed.party_name)
        if (status == 'Active') {
			const access_token = generateAccessTokenForClient.sign(client_id);
			console.log('')
			console.log('Access Token for client: ' + access_token)
            res.status(200).json({
                status: "Active",
				access_token: access_token
            });	
        } else {
            res.status(200).json({
                status: "Not Active"
            });
        }
    }).catch(function(err) {
        res.status(200).json({
            status: "Not Found"
        });
        console.log(err)
    });
   
});

app.get('/capabilities',  function(req, res) {
    console.log('capabilities')
	res.status(200).send(jwtCapabilitiesService.sign());
 })

try {
    const server = app.listen(4010, function() {
        console.log('Server is listening on port 4010...');
    });
    //getAccessToken()
} catch (error) {
    console.log('intern server eror: ' + error);
}
