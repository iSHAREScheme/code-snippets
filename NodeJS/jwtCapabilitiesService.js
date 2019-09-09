const fs    = require('fs');
const jwt   = require('jsonwebtoken');
const service = require('./iShareService.js')
const privateKey  = fs.readFileSync('./RSA_PRIVATE_KEY.key', 'utf8');

const base_url = 'https://innopaytest.azurewebsites.net'

const capabilities = {
		"party_id": "EU.EORI.NL812458837",
		"supported_versions": [
			{
				"version": "0.1",
				"supported_features": [
					{
						"public": [
							{
								"id": "DFE2392-FMEKLL555",
								"feature": "capabilities",
								"description": "Retrieves API capabilities",
								"url": base_url + "/capabilities",
								"token_endpoint": base_url + "/token"
							},
							{
								"id": "3V45VH3589-KLW920SN",
								"feature": "access token",
								"description": "Obtains access token",
								"url": base_url + "/token"
							}
						]
					}
				]
			}
		]
	 };
module.exports = {
 sign: ( $Options) => {
	var iat     = Math.floor(new Date() / 1000)
	var header  = {"x5c":[""]};
	var payload = {
		"iss": 'xxxxxx',
		"sub": 'xxxxxx',
		"jti": "ergth5445-rthy545-dfgdfh-4545",
		"exp": iat+30,
		"iat": iat,
		"capabilities_info": capabilities
	};
    return jwt.sign(payload, privateKey,
    { algorithm: 'RS256', header: header, noTimestamp: true  })
 }
}
