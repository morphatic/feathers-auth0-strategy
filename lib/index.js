const Auth0Service = require('./service')
const Auth0Strategy = require('./strategy')
const authenticate = require('./hooks/authenticate')
const fromAuth0 = require('./hooks/from-auth0')

module.exports = {
  Auth0Service,
  Auth0Strategy,
  hooks: {
    authenticate,
    fromAuth0
  }
}
