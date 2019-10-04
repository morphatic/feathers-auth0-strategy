const { AuthenticationService } = require('@feathersjs/authentication')

class Auth0Service extends AuthenticationService {
  setup() {
    // get the authStrategies and secret (if any) from the configuration
    const { authStrategies, secret } = this.configuration

    // if secret is NOT set and auth0 is the ONLY strategy
    if (typeof secret !== 'string' && authStrategies.length === 1 && authStrategies[0] === 'auth0') {
      // we need to set a dummy secret to prevent super.setup() from throwing an error
      this.app.set('authentication', { ...this.configuration, secret: 'I_am_not_used' })
    }

    // then call the parent setup method
    super.setup()
  }
}

module.exports = Auth0Service
