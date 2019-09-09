const fs    = require('fs');
const crypto = require('crypto');
const jwt   = require('jsonwebtoken');
const service = require('./index.js')
const privateKey  = fs.readFileSync('./linkto.key.decr.pem', 'utf8');
const x5c_value = ''

const base_url = ''


const capabilities = {
		"party_id": "EU.EORI.XXXXXXXXX",
		"supported_versions": [
			{
				"version": "1.9",
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
						],
                        "restricted": [
                            {
								"id": "3HGRU3894-JFWOEDDI388",
								"feature": "test",
								"description": "Obtains test result",
								"url": base_url + "/test"
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
	var header  = {"x5c":[ x5c_value ]};
	var payload = {
		"iss": 'EU.EORI.XXXXXXXXX',
		"sub": 'EU.EORI.XXXXXXXXX',
		"jti": crypto.randomBytes(16).toString('hex'),
		"iat": iat,
		"exp": iat+30,
		"capabilities_info": capabilities
	};
    return jwt.sign(payload, privateKey,
    { algorithm: 'RS256', header: header, noTimestamp: false  })
 }
}
