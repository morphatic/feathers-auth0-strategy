const { AuthenticationBaseStrategy } = require('@feathersjs/authentication')
const { GeneralError, NotAuthenticated } = require('@feathersjs/errors')
const axios = require('axios')
const jwt = require('jsonwebtoken')
const { omit } = require('lodash')
const lt = require('long-timeout')

class Auth0Strategy extends AuthenticationBaseStrategy {
  /**
   * Mainly calling this so that we have an opportunity to
   * initialize the `expirationTimers` property. This is
   * used to maintain long-running login information. Also,
   * the `jwks` property keeps a list of already-retrieved
   * JWKs.
   *
   * @param {Object} app The Feathers app
   * @param {String} configKey The configuration key
   * @param {Object} options Custom options override the config file
   */
  constructor (app, configKey = 'authentication', options = {}) {
    super(app, configKey, options)
    this.expirationTimers = new WeakMap()
    this.jwks = new Map()
  }

  /**
   * Returns the configuration settings for the Auth0 strategy.
   * This strategy maintains its own _separate_ set of JWT options.
   * The reason is that we are using the RS256 verification
   * algorithm instead of the HS256 used by the JWT, OAuth, and
   * other strategies.
   */
  get configuration () {
    const { auth0, domain, entity, entityId, header, schemes, service } = this.authentication.configuration
    const { create = false, jwtOptions, whitelist } = auth0
    return {
      create,
      entity: auth0.entity || entity || 'user',
      entityId: auth0.entityId || entityId || 'user_id',
      header: auth0.header || header || 'Authorization',
      jwksUri: `https://${auth0.domain || domain}/.well-known/jwks.json`,
      jwtOptions: {
        algorithms: ['RS256'],
        audiences: [
          `https://${auth0.domain || domain}/api/v2`,
          `https://${auth0.domain || domain}/userinfo`
        ],
        ignoreExpiration: false,
        issuer: `https://${auth0.domain || domain}/`,
        ...jwtOptions
      },
      schemes: auth0.schemes || schemes || ['Bearer', 'JWT'],
      service: auth0.service || service || 'users',
      whitelist: whitelist || []
    }
  }

  /**
   * Makes sure that required options (i.e. Auth0 domain) are set,
   * and that only allowable options have been set. Overrides
   * `JWTStrategy.verifyConfiguration()`. Throws an error if required
   * options are not set, or if "extra" options have been set.
   */
  verifyConfiguration () {
    // the domain is the only required setting
    const { auth0, domain } = this.authentication.configuration
    if (!auth0.domain && !domain) {
      throw new GeneralError('You must set `authentication.auth0.domain` in your app configuration.')
    }
  }

  /**
   * Takes a JWK object and returns a valid key in PEM format. Throws
   * a GeneralError if there are no x5c items stored on the JWK.
   *
   * @param   {String}       jwk The JWK to be parsed
   * @returns {String}           The key in PEM format from the first x5c entry
   * @throws  {GeneralError}     Throws a GeneralError if there are no x5c items
   */
  x5cToPEM (jwk) {
    if (!jwk.x5c.length > 0) throw new GeneralError('JWK has no x5c property.')
    const lines = jwk.x5c[0].match(/.{1,64}/g).join('\n')
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`
  }

  /**
   * Takes a JWKS endpoint URI and returns a Promise that resolves to an
   * array of JWKs, i.e. a JWKS. The resulting function may throw any of
   * [the errors described here]{@link https://github.com/request/promise-core/blob/master/lib/errors.js}
   *
   * @param   {String}   url The URI of the JWKS endpoint
   * @returns {Promise}      A Promise that resolves to JWKS retrieved
   */
  getJWKS (url) { return axios({ url }).then(res => res.data) }

  /**
   * Auth0Strategy uses the RS256 algorithm to verify access tokens.
   * This requires the use of a public JavaScript Web Key (JWK) in
   * place of what would normally be the app's authentication secret
   * key. Since there could potentially be more than one of these
   * and/or they can change over time they must be retrieved from
   * the web for each login instead of stored on the server. In order
   * for Auth0Strategy to be able to use the built-in token verifier,
   * we have to set the `secret` prop in the config before either the
   * `authenticate()` or `handleConnection()` methods are called.
   *
   * @param  {String}       accessToken The access token for which a JWK must be set
   * @throws {GeneralError}             Throws a GeneralError if no JWK can be set
   */
  async getJWK (accessToken) {
    // decode the access token (this does not throw an error)
    const token = jwt.decode(accessToken, { complete: true })

    // throw an error if the token was malformed or missing
    if (!token) throw new NotAuthenticated('The access token was malformed or missing')

    // get the kid from the token header
    const kid = token.header.kid

    // have we already retrieved this JWK?
    let jwk
    if (this.jwks.has(kid)) {
      // yes, so get it
      return this.jwks.get(kid)
    } else {
      // no, so let's retrieve it
      try {
        // get an array of JWKs from the endpoint
        const jwks = await this.getJWKS(this.configuration.jwksUri)
        // try to find one that matches the given kid
        jwk = jwks.keys.find(k => k.kid === kid)
        // parse it
        jwk = this.x5cToPEM(jwk)
        // store it
        this.jwks.set(kid, jwk)
        // then return it
        return jwk
      } catch (err) {
        // throw an error if we still don't have a signing key
        throw new NotAuthenticated('Could not retrieve JWKS', err)
      }
    }
  }

  /**
   * This function makes sure that real time connections are closed
   * and removed from the authenticated channel if the JWT has expired
   * or if the user explicitly logs out. It is almost identical to
   * the `handleConnection()` function in JWTStrategy except that it
   * uses different parameters to verify the JWT, i.e. those required
   * for the RS256 algorithm, which is the primary purpose of
   * this library
   *
   * @param {String} event      Event type (login/logout/disconnect)
   * @param {Object} connection A Socket.io/Primus connection
   * @param {Object} authResult A Feathers (Crow) authentication result
   */
  async handleConnection (event, connection, authResult) {
    const isValidLogout =
      event === 'logout' &&
      connection.authentication &&
      authResult &&
      connection.authentication.accessToken === authResult.accessToken

    const { accessToken } = authResult || {}

    if (accessToken && event === 'login') {
      // make sure the JWK has been added to the strategy configuration
      const jwk = await this.getJWK(accessToken)
      // verify the token and extract the expiration time
      const { exp } = await jwt.verify(accessToken, jwk, this.configuration.jwtOptions)
      const duration = (exp * 1000) - new Date().getTime()
      // set a timer that will disconnect the client when the token expires
      const timer = lt.setTimeout(() => this.app.emit('disconnect', connection), duration)
      this.expirationTimers.set(connection, timer)
      // eslint-disable-next-line require-atomic-updates
      connection.authentication = { strategy: this.name, accessToken }
    } else if (event === 'disconnect' || isValidLogout) {
      delete connection.authentication
      lt.clearTimeout(this.expirationTimers.get(connection))
    }
  }

  /**
   * Return the entity for a given `user_id`. Overrides the
   * `JWTStrategy.getEntity()` method. We're overriding because
   * the `entityId` is frequently NOT the same as the `id`
   * field, hence we have to use `find()` instead of `get()`
   * to retrieve the entity (usually a user). We also support
   * creating a new entity (user) in the database if the
   * authentication is successful.
   *
   * @param   {String} user_id The Auth0 user_id to use
   * @param   {Object} params  Service call parameters
   * @returns {Entity}         An object of the `entity` class
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
          throw new NotAuthenticated(`Could not create an ${entity} with this user_id in the database`)
        }
      } else {
        throw new NotAuthenticated(`Could not find ${entity} with this user_id in the database`)
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
   * @param   {Object} authentication Contains the accessToken to be verified
   * @param   {Object} params         Contains params for finding the user
   * @returns {Object}                Contains the token, decoded token, and user info
   */
  async authenticate (authentication, params) {
    // get the accessToken passed in with the authentication request
    const { accessToken } = authentication

    // get the "users" entity and domain for verifying JWTs
    const { entity } = this.configuration

    // verify the access token
    let token
    try {
      // make sure we've set a secret
      const jwk = await this.getJWK(accessToken)
      // console.log(jwk)
      token = await jwt.verify(accessToken, jwk, this.configuration.jwtOptions)
    } catch (err) {
      throw new NotAuthenticated('Token could not be verified', err)
    }

    // get the user ID from the token payload
    const user_id = token.sub

    // check to see if we have a user with this ID in the database
    // this throws an error if the user is not found
    let user
    try {
      user = await this.getEntity(user_id, params)
    } catch (err) {
      throw new NotAuthenticated(err.message, err)
    }

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
   * Extracts the accessToken from a HTTP request object's Authorization header.
   *
   * @param   {Object} req            Express request object
   * @returns {Object}                Contains the token and strategy name
   */
  parse (req) {
    if (req.headers.authorization) {
      return {
        strategy: this.name,
        accessToken: req.headers.authorization.split(' ').pop()
      }
    }
    return null
  }
}

module.exports = Auth0Strategy
