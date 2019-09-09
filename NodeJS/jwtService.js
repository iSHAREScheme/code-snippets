const fs    = require('fs');
const jwt   = require('jsonwebtoken');
const crypto = require('crypto');
const service = require('./index.js')
const privateKey  = fs.readFileSync('./RSA_PRIVATE_KEY.key', 'utf8');

module.exports = {
 sign: ( $Options) => {
	var iat     = Math.floor(new Date() / 1000)
	var header  = {"x5c":[""]};
	var payload = {
		"iss": 'xxxxxx',
		"sub": 'xxxxxx',
		"aud": "TBD",
		"jti": crypto.randomBytes(16).toString('hex'),
		"exp": iat+30,
		"iat": iat
	};
    return jwt.sign(payload, privateKey,
    { algorithm: 'RS256', header: header })
 }
}
