const fs    = require('fs');
const jwt   = require('jsonwebtoken');
const service = require('./index.js')
const privateKey  = fs.readFileSync('./RSA_PRIVATE_KEY.key', 'utf8');


module.exports = {
	
 sign: (client_id, $Options) => {
	var iat     = Math.floor(new Date() / 1000)
	var payload = {
		"iss": 'xxxxxxxx',
		"aud": "xxxxxxxx",
		"client_id":client_id,
		"exp": iat+3600,
		"nbf": iat,
		"scope":["iSHARE"]
	};
   return jwt.sign(payload,  privateKey,
    { algorithm: 'RS256', noTimestamp : true })
 }
}
