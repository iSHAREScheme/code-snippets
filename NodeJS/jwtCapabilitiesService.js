const fs    = require('fs');
const jwt   = require('jsonwebtoken');
const service = require('./iShareService.js')
const privateKey  = fs.readFileSync('./RSA_PRIVATE_KEY.key', 'utf8');

const capabilities = {
		"party_id": "xxxxxx",
		"supported_versions": [
			{
				"version": "1.0",
				"supported_features": [
					{
						"public": [
							{
								"id": "DFE2392-FMEKLL555-FGR4545-DF353-JKDJKDE3434",
								"feature": "capabilities",
								"description": "Retrieves JORR-IT capabilities",
								"url": "https://dev.jorr-itsolutions.nl/ords/wms/ishare/capabilities",
								"token_endpoint": "https://dev.jorr-itsolutions.nl/ords/wms/ishare/token"
							},
							{
								"id": "3V45VH3589-KLW920SN-CKS028JC-OSNCO2U8K-CLKW927KV083CO",
								"feature": "access token",
								"description": "Obtains access token",
								"url": "https://dev.jorr-itsolutions.nl/ords/wms/ishare/token"
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
		"jti": "dwqeyug43lb-werfbiyqwr0-wvrhbw82-sadvbjch",
		"exp": iat+30,
		"iat": iat,
		"capabilities_info": capabilities
	};
    return jwt.sign(payload, privateKey,
    { algorithm: 'RS256', header: header, noTimestamp: true  })
 }
}