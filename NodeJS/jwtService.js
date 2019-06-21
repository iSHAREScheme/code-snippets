const fs    = require('fs');
const jwt   = require('jsonwebtoken');
const service = require('./iShareService.js')
const privateKey  = fs.readFileSync('./RSA_PRIVATE_KEY.key', 'utf8');

module.exports = {
 sign: ( $Options) => {
	var iat     = Math.floor(new Date() / 1000)
	var header  = {"x5c":[""]};
	var payload = {
		"iss": 'xxxxxx',
		"sub": 'xxxxxx',
		"aud": "EU.EORI.NL000000000",
		"jti": "rtnre6rht234-y4n4656-wvrhbw82-sadvbjch",
		"exp": iat+30,
		"iat": iat
	};
    return jwt.sign(payload, privateKey,
    { algorithm: 'RS256', header: header })
 }
}
