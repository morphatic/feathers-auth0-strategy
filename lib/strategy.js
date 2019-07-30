const { JWTStrategy } = require('@feathersjs/authentication')
const { GeneralError, NotAuthenticated } = require('@feathersjs/errors')
const memory = require('feathers-memory')
const rp = require('request-promise')
const jwt = require('jsonwebtoken')
const { omit } = require('lodash')

class Auth0Strategy extends JWTStrategy {

  get configuration () {
    const authConfig = this.authentication.configuration
    const config = super.configuration

    return {
      create: authConfig.createIfNotExists || false,
      domain: authConfig.auth0.domain,
      entity: authConfig.entity,
      entityId: authConfig.entityId,
      header: 'Authorization',
      keysService: authConfig.auth0.keysService,
      service: authConfig.service,
      schemes: [ 'Bearer', 'JWT' ],
      ...config
    }
  }

  get keysService () {
    const { keysService } = this.configuration

    let service = this.app.service(keysService)
    if (!service) {
      const paginate = this.app.get('paginate')
      service = this.app.use(keysService, memory({ paginate }))
      this.app.service(keysService).hooks({
        before: {
          all: [
            // disallow all external requests
            context => {
              const { provider } = context.params
              if (provider) {
                throw new NotAuthenticated('No external requests permitted for the `keys` service')
              }
              return context
            }
          ]
        }
      })
    }

    return service
  }
  /**
   * Make sure that required options (i.e. Auth0 domain) are set, and that only
   * allowable options have been set. Overrides `JWTStrategy.verifyConfiguration()`.
   * Throws an error if required options are not set, or if "extra" options have been set.
   */
  verifyConfiguration () {
    const requiredKeys = ['domain']
    const allowedKeys = ['create', 'domain', 'entity', 'entityId', 'header', 'keysService', 'schemes', 'service'];

    // make sure required keys are set
    for (const key of requiredKeys) {
      if (!this.configuration[key]) {
        throw new GeneralError(`The 'authentication.${this.name}.${key}' option must be set.`)
      }
    }

    // make sure allowed keys are set in the appropriate place
    for (const key of Object.keys(this.configuration)) {
      if (!allowedKeys.includes(key)) {
        throw new GeneralError(`Invalid Auth0Strategy option 'authentication.${this.name}.${key}'`);
      }
    }
  }

  /**
   * Return the entity for a given user_id. Overrides the
   * `JWTStrategy.getEntity()` method.
   *
   * @param   {String} user_id The Auth0 user_id to use
   * @param   {Object} params  Service call parameters
   * @returns {entity}         An object of the `entity` class
   */
  async getEntity (user_id, params) {
    // get the createIfNotExists setting, "users" entity, and entity ID field from config
    const { create, entity, entityId } = this.configuration
    const entityService = this.entityService

    // make sure we have a reference to the entity service
    if (entityService === null) {
      throw new NotAuthenticated(`Could not find the "${entity}" service`)
    }

    // make sure we have at least the basic params set
    params = {
      ...omit(params, 'provider'),
      paginate: false,
      query: {
        $limit: 1,
        [entityId]: user_id
      }
    }

    // search for a user with the given user_id
    let result = await entityService.find(params)

    // if there is no result...
    if (!result[0]) {
      // should we create a new entity?
      if (create) {
        // get rid of unnecessary params
        delete params.paginate
        delete params.query
        // try to create the entity
        try {
          result = await entityService.create({ [entityId]: user_id }, params)
        } catch (error) {
          throw new NotAuthenticated(`Could not create an ${entity} with this user_id in the database`);
        }
      } else {
        throw new NotAuthenticated(`Could not find ${entity} with this user_id in the database`);
      }
    } else {
      // set the result to the retrieved user
      result = result[0]
    }
    // finally return the entity
    return result
  }

  /**
   * Verifies an Auth0 access token using the RS256 algorithm, i.e.
   * it retrieves the public signing key associated with a token from Auth0
   * and uses it (instead of a clientSecret, used with HS256 algorithm) to
   * make sure the access token is valid. Overrides `JWTStrategy.authenticate()`.
   * This function is the core of this strategy.
   *
   * @param   {object} authentication Contains the accessToken to be verified
   * @param   {object} params         Contains params for finding the user
   * @returns {object}                Contains the token, decoded token, and user info
   */
  async authenticate(authentication, params) {
    // get the accessToken passed in with the authentication request
    const { accessToken } = authentication
    // get the "users" entity and domain for verifying JWTs
    const { entity, domain } = this.configuration

    // if no accessToken was received, throw an error
    if (!accessToken) throw new NotAuthenticated('No access token was received')

    // decode the access token (this does not throw an error)
    let token = jwt.decode(accessToken, { complete: true })

    // throw an error if the token was malformed or missing
    if (!token) throw new NotAuthenticated('The access token was malformed')

    // get the kid from the token header
    const kid = token.header.kid

    // create a JWKS retrieval client
    const client = this.getJWKS(`https://${domain}.auth0.com/.well-known/jwks.json`)

    // get the signing key from the JWKS endpoint at Auth0
    const key = await this.getKey(kid, client)

    // configure necessary jwtOptions based on the provided domain
    const jwtOptions = {
      algorithms: ['RS256'],
      audience: [
        `https://${domain}.auth0.com/api/v2/`,
        `https://${domain}.auth0.com/userinfo`
      ],
      ignoreExpiration: false,
      issuer: `https://${domain}.auth0.com/`
    }

    // verify the raw JWT
    try {
      token = jwt.verify(accessToken, key, jwtOptions)
    } catch (err) {
      throw new NotAuthenticated('Token could not be verified', err.message)
    }

    // get the user ID from the token payload
    const user_id = token.sub

    // check to see if we have a user with this ID in the database
    // this throws an error if the user is not found
    const user = await this.getEntity(user_id, params)

    // If we made it this far, we're all good!
    // Returns the same structure as JWTStrategy
    return {
      accessToken,
      authentication: {
        strategy: this.name,
        payload: token
      },
      [entity]: user
    }
  }

  /**
   * Takes a JWKS endpoint URI and returns a function that can retrieve an
   * array of JWKs, i.e. a JWKS. The resulting function may throw any of
   * [the errors described here]{@link https://github.com/request/promise-core/blob/master/lib/errors.js}
   * 
   * @param   {string}   uri The URI of the JWKS endpoint
   * @returns {function}     A function that can retrieve a JWKS from the endpoint
   */
  getJWKS (uri) { return () => rp({ uri, json: true }) }

  /**
   * Takes a JWK object and returns a valid key in PEM format. Throws
   * a GeneralError if there are no x5c items stored on the JWK.
   * 
   * @param   {string}       jwk The JWK to be parsed
   * @returns {string}           The key in PEM format from the first x5c entry
   * @throws  {GeneralError}     Throws a GeneralError if there are no x5c items
   */
  x5cToPEM (jwk) {
    if (!jwk.x5c.length > 0) throw new GeneralError('Stored JWK has no x5c property.')
    const lines = jwk.x5c[0].match(/.{1,64}/g).join('\n')
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`
  }

  /**
   * Takes a `kid`, a reference to an in-memory Feathers service (`svc`)
   * for storing JWKs, and a `client` for retrieving signing keys from a
   * JWKS endpoint. Returns a valid signing key in PEM format or throws
   * a `SigningKeyNotFoundError`. If a key is successfully retrieved from
   * the endpoint, it tries to store this value using the `svc`.
   * 
   * @async
   * @param   {string}       kid        The `kid` for the JWK to be retrieved
   * @param   {function}     jwksClient A function that takes a `kid` and returns a key
   * @returns {string}                  The retrieved signing key in PEM format
   * @throws  {GeneralError}            Thrown by the `client` if `kid` is not found
   */
  async getKey (kid, jwksClient) {
    // get the service for retrieving JWKs
    const keysService = this.keysService

    try {
      // get the signing key from the in-memory service, if it exists
      const storedKey = await keysService.find({ query: { kid } }).then(keys => keys[0])

      // if the storedKey exists, return it
      if (storedKey) return this.x5cToPEM(storedKey)
    } catch (err) {
      // nothing to see here. please move along...
    }

    // otherwise, we need to get it from our JWKS endpoint
    let jwk
    try {
      // get an array of JWKs from the endpoint
      const jwks = await jwksClient()
      // try to find one that matches the given kid
      jwk = jwks.keys.find(k => k.kid === kid)
    } catch (err) {
      // throw an error if we still don't have a signing key
      throw new NotAuthenticated('Could not retrieve JWKS', err)
    }

    // throw an error if there were no JWKs that contained our kid
    if (!jwk) throw new NotAuthenticated('Could not find a JWK matching given kid')

    // get the signing key from the retrieved JWK
    const key = this.x5cToPEM(jwk)

    // try to store the jwk in our in-memory service
    try { keysService.create(jwk) } catch (e) { /* no problem if this fails */ }

    // and return the key
    return key
  }
}

module.exports = Auth0Strategy
