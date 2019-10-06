const { AuthenticationService, authenticate } = require('@feathersjs/authentication')
const { isProvider, some, unless } = require('feathers-hooks-common')
const { fromAuth0 } = require('./hooks/from-auth0')

class Auth0Service extends AuthenticationService {
  setup() {
    // get the authStrategies and secret (if any) from the configuration
    const { auth0: { autoregister = false, services }, authStrategies, secret } = this.configuration

    // if secret is NOT set and auth0 is the ONLY strategy
    if (typeof secret !== 'string' && authStrategies.length === 1 && authStrategies[0] === 'auth0') {
      // we need to set a dummy secret to prevent super.setup() from throwing an error
      this.app.set('authentication', { ...this.configuration, secret: 'I_am_not_used' })
    }

    // then call the parent setup method
    super.setup()

    // if autoregister is true
    if (autoregister) {
      // get the list of services which will be registered to use Auth0 authentication
      // defaults to ALL services registered on the app
      const svcs = Array.isArray(services) ? services : Object.keys(this.app.services)

      // register the authenticate hook on teh requested services
      for (let svc of svcs) {
        if (svc !== 'authentication') {
          this.app.service(svc).hooks({
            before: {
              all: [
                unless(some(isProvider('server'), fromAuth0()), authenticate('auth0'))
              ]
            }
          })
        }
      }
    }
  }
}

module.exports = Auth0Service
