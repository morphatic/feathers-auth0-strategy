const Auth0Service = require('./service')
const Auth0Strategy = require('./strategy')
const { fromAuth0, usIPAddresses, euIPAddresses, auIPAddresses } = require('./hooks/from-auth0')
const addIP = require('./middleware/add-ip')

module.exports = {
  Auth0Service,
  Auth0Strategy,
  fromAuth0,
  addIP,
  usIPAddresses,
  euIPAddresses,
  auIPAddresses
}
