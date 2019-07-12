const { AuthenticationService, authenticate, hooks } = require('@feathersjs/authentication')
const { GeneralError } = require('@feathersjs/errors')
const { isProvider, some, unless } = require('feathers-hooks-common')
// const Auth0Strategy = require('./strategy')
const fromAuth0 = require('./hooks/from-auth0')

class Auth0Service extends AuthenticationService {

  /**
   * Overrides `AuthenticationService.setup()`. Duplicates the functionality
   * of the `connection()` and `events()` hooks so this won't be lost. It
   * automatically registers `Auth0Strategy`.
   */
  setup() {
    const { entity, entityId, service, services = 'all' } = this.configuration
    
    if (entity !== null) {
      if (service === undefined) {
        throw new GeneralError(`Since the 'entity' option is set to '${entity}', the 'service' option must also be set`)
      }

      if (this.app.service(service) === undefined) {
        throw new GeneralError(`The '${service}' entity service does not exist. Set to 'null' if it is not required.`)
      }

      if (this.app.service(service).id === undefined && entityId === undefined) {
        throw new GeneralError(`The '${service}' service does not have an 'id' property and no 'entityId' option is set`)
      }
    }

    // make sure that the IP address of incoming requests is passed along
    const addIP = (req, res, next) => {
      // `x-real-ip` is for when is behind an nginx reverse proxy
      req.feathers.ip = req.headers['x-real-ip'] || req.ip
      // carry on...
      next()
    }
    this.app.use(addIP)

    // get the list of services that should be authenticated
    const svcs = Array.isArray(services) ? services : Object.keys(this.app.services)

    // register the authenticate hook on the requested services
    for (let svc of svcs) {
      if (svc !== '/authentication') {
        this.app.service(svc).hooks({
          before: {
            all: [
              unless(some(isProvider('server'), fromAuth0()), authenticate('auth0'))
            ]
          }
        })
      }
    }

    // register the connection and events hooks
    this.hooks({ after: [hooks.connection(), hooks.events()] })

    // register the Auth0Strategy
    // this.register('auth0', new Auth0Strategy())
  }
}

module.exports = Auth0Service
