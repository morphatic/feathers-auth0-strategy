// const fs = require('fs')
// const jwt = require('jsonwebtoken')

// const privateKey = fs.readFileSync('test.priv.pem')
// const user = {
//   'sub': 'auth0|currentValidTokenMember',
//   'aud': [
//     'https://example.auth0.com/api/v2/',
//     'https://example.auth0.com/userinfo'
//   ],
//   'iss': 'https://example.auth0.com/'
// }
// const token = jwt.sign(user, privateKey, { algorithm: 'RS256', keyid: 'goodKid', noTimestamp: true })
// console.log(token)

// const cert = fs.readFileSync('test.cert.pem')
// const valid = (token, cert)