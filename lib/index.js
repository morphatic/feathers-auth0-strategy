const { GeneralError, NotAuthenticated } = require('@feathersjs/errors')
const createService = require('feathers-memory')
const { disallow, isProvider, some, unless } = require('feathers-hooks-common')
const jwt = require('jsonwebtoken')
const rp = require('request-promise')
const UnauthorizedError = require('./unauthorized-error')

module.exports = ({
  /**
   * Default options
   */
  algorithm = 'RS256',
  authTimeout = 5000,
  currentTokenField = 'currentToken',
  keysService = 'keys',
  prefix = 'Bearer',
  userIdField = 'user_id',
  usersService = 'users',
  whitelist = [
    '138.91.154.99',
    '54.183.64.135',
    '54.67.77.38',
    '54.67.15.170',
    '54.183.204.205',
    '54.173.21.107',
    '54.85.173.28',
    '35.167.74.121',
    '35.160.3.103',
    '35.166.202.113',
    '52.14.40.253',
    '52.14.38.78',
    '52.14.17.114',
    '52.71.209.77',
    '34.195.142.251',
    '52.200.94.42'
  ],
  /**
   * Takes a JWKS endpoint URI and returns a function that can retrieve an
   * array of JWKs, i.e. a JWKS. The resulting function may throw any of
   * [the errors described here]{@link https://github.com/request/promise-core/blob/master/lib/errors.js}
   * 
   * @param   {string}   uri The URI of the JWKS endpoint
   * @returns {function}     A function that can retrieve a JWKS from the endpoint
   */
  getJWKS = uri => () => rp({ uri, json: true }),
  /**
   * Takes a JWK object and returns a valid key in PEM format. Throws
   * a GeneralError if there are no x5c items stored on the JWK.
   * 
   * @param   {string}       jwk The JWK to be parsed
   * @returns {string}           The key in PEM format from the first x5c entry
   * @throws  {GeneralError}     Throws a GeneralError if there are no x5c items
   */
  x5cToPEM = jwk => {
    if (!jwk.x5c.length > 0) throw new GeneralError('Stored JWK has no x5c property.')
    const lines = jwk.x5c[0].match(/.{1,64}/g).join('\n')
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`
  },
  /**
   * Takes a `kid`, a reference to an in-memory Feathers service (`svc`)
   * for storing JWKs, and a `client` for retrieving signing keys from a
   * JWKS endpoint. Returns a valid signing key in PEM format or throws
   * a `SigningKeyNotFoundError`. If a key is successfully retrieved from
   * the endpoint, it tries to store this value using the `svc`.
   * 
   * @async
   * @param   {string}       kid        The `kid` for the JWK to be retrieved
   * @param   {object}       svc        The Feathers service used to store JWKs in memory
   * @param   {function}     jwksClient A function that takes a `kid` and returns a key
   * @returns {string}                  The retrieved signing key in PEM format
   * @throws  {GeneralError}            Thrown by the `client` if `kid` is not found
   */
  getKey = async (kid, svc, jwksClient) => {
    try {
      // get the signing key from the in-memory service, if it exists
      const storedKey = await svc.find({ query: { kid } }).then(keys => keys[0])

      // if the storedKey exists, return it
      if (storedKey) return x5cToPEM(storedKey)
    } catch (err) {
      // nothing to see here. please move along...
    }

    // otherwise, we need to get it from our JWKS endpoint
    let jwk
    try {
      const jwks = await jwksClient()
      jwk = jwks.keys.find(k => k.kid === kid)
    } catch (err) {
      // throw an error if we still don't have a signing key
      throw new GeneralError('Could not retrieve JWKS', err)
    }

    // throw an error if there were no JWKs that contained our kid
    if (!jwk) throw new GeneralError('Could not find a JWK matching given kid')

    // get the signing key from the retrieved JWK
    const key = x5cToPEM(jwk)

    // store the jwk in our in-memory service
    try { svc.create(jwk) } catch (e) { /* no problem if this fails */ }

    // and return the key
    return key
  },
  /**
   * A hook to authorize REST requests
   *
   * @param   {HookContext} context See: https://crow.docs.feathersjs.com/api/hooks.html#hook-context
   * @returns {HookContext}         The modified hook context
   */
  authorizeRest = async (context) => {
    // Throw if the hook is being called from an unexpected location.
    if (context.type !== 'before')
      throw new NotAuthenticated('`authorizeRest()` can only be used as a `before` hook.', context)

    // get the Authorization header
    const header = (context.params.headers || {}).authorization || null

    // throw an error if the Authorization header is not set
    if (!header) throw new NotAuthenticated('`Authorization` header not set.', context)

    // extract the raw token from the header
    const currentToken = header.replace(`${prefix} `, '').trim()

    // decode it (this does not throw an error)
    let token = jwt.decode(currentToken, { complete: true })

    // throw an error if the token was malformed or missing
    if (!token) throw new NotAuthenticated('The token was malformed or missing.')

    // get the user ID from the token payload
    const user_id = token.payload.sub

    // check to see if we have a user with this ID in the database
    let user
    try {
      const query = { $limit: 1 }
      query[userIdField] = user_id
      user = await context.app.service(usersService).find({
        paginate: false,
        query
      }).then(results => {
        if (results[0]) return results[0]
        throw 'User was not found in the database'
      })
    } catch (err) {
      // throw an error if no such user exists
      throw new NotAuthenticated('No user with this ID exists.', err)
    }

    // if the user already has a valid, current token, stop here
    if (user[currentTokenField] && user[currentTokenField] === currentToken) return context

    // otherwise, get the kid from the token header
    const kid = token.header.kid

    // create a JWKS retrieval client
    const client = getJWKS(context.app.get('jwksUri'))

    // get the signing key from the JWKS endpoint at Auth0
    const key = await getKey(kid, context.app.service(keysService), client)

    // verify the raw JWT
    try {
      jwt.verify(currentToken, key, context.app.get('jwtOptions'))
    } catch (err) {
      throw new NotAuthenticated('Token could not be verified.', err.message)
    }

    // OK! The JWT is valid, store it in the user profile
    // (It's okay if this fails)
    context.app.service(usersService).patch(
      null,
      { currentToken },
      { query: { user_id: user.user_id } }
    )

    // If we made it this far, we're all good!
    return context
  },
  /**
   * A hook to determine if a given request originated from an
   * IP address belonging to Auth0. Defaults to US IP addresses.
   * see: https://auth0.com/docs/guides/ip-whitelist
   *
   * @param {HookContext} context The context for the hook call
   */
  fromAuth0 = async (context) => whitelist.includes(context.params.ip),
  /**
   * Sets the domain, jwksUri, jwtOptions, and creates a
   * service for storing signing keys.
   *
   * @param {Feathers} app The feathers app being setup
   */
  auth0Setup = app => {
    // get the domain from the auth0 config
    const domain = app.get('auth0domain')
  
    // throw an error if the domain has not been set
    if (!domain) throw new Error('[feathers-auth0-authorize] Auth0 domain must be set')
  
    // set the jwtOptions for the app
    app.set('jwksUri', `https://${domain}.auth0.com/.well-known/jwks.json`)
    app.set('jwtOptions', {
      algorithms: [algorithm],
      audience: [
        `https://${domain}.auth0.com/api/v2/`,
        `https://${domain}.auth0.com/userinfo`
      ],
      ignoreExpiration: false,
      issuer: `https://${domain}.auth0.com/`
    })
  
    // get the default pagination options for the app
    const paginate = app.get('paginate')
  
    // create the keys in-memory service
    app.use(`/${keysService.replace(/^\//, '')}`, createService({ paginate }))
  
    // restrict access to the keys service to internal calls
    app.service(keysService).hooks({
      before: {
        all: [
          disallow('external')
        ]
      }
    })
  },
  addHeadersAndIP = req => {
    // add headers to the request
    req.feathers = { ...req.feathers, headers: req.headers }
    // pass the requesting IP address, as well
    // `x-real-ip` is for when is behind an nginx reverse proxy
    req.feathers.ip = req.headers['x-real-ip'] || req.ip
    // carry on...
    return req
  },
  /**
   * Register the authorizeREST() hook. The hook will run for all
   * external requests that do NOT use the socket.io transport and
   * do not originate from an Auth0 IP address. This function also
   * registers middleware necessary for the hooks to work.
   *
   * @param {Feathers} app The FeathersJS for which hooks are being registered
   */
  auth0Hooks = app => {
    // set up middleware to pass headers and IP to the requests
    app.use((req, res, next) => {
      req = addHeadersAndIP(req)
      next()
    })
    // register the REST hooks
    app.hooks({
      before: {
        all: [
          unless(some(isProvider('server'), isProvider('socketio'), fromAuth0), authorizeRest)
        ]
      }
    })
  },
  /**
   * Utility function for sending errors to clients
   *
   * @param {Socket}       socket The socket experiencing the error
   * @param {Error|string} err    The error or error message
   * @param {string}       code   A short error code
   */
  disconnectWithError = (socket, err, code) => {
    code = code || 'unknown'
    const error = new UnauthorizedError(code, {
      message: (Object.prototype.toString.call(err) === '[object Object]' && err.message) ? err.message : err
    })
    socket.emit('unauthorized', error, () => {
      socket.disconnect('unauthorized')
    })
  },
  /**
   * Register the authorizeREST() hook. This method will run every
   * time a client attempts to connect to the server using socket.io.
   *
   * @param {Feathers} app The FeathersJS for which hooks are being registered
   */
  auth0SocketIO = app => {
    // when we receive an incoming connection
    app.io.sockets.on('connection', socket => {
      // close the connection if timely `authenticate` not received
      const auth_timer = setTimeout(() => {
        disconnectWithError(socket, 'Authentication timeout.', 'auth_timeout')
      }, authTimeout)

      // wait for the authenticate message
      socket.on('authenticate', async (payload) => {
        // clear the auth_timer
        clearTimeout(auth_timer)

        // disconnect if there's no token in the payload
        if (!payload.token) disconnectWithError(socket, 'The token was missing.', 'missing_token')

        // assign currentToken
        const currentToken = payload.token

        // otherwise decode the token (this does not throw an error)
        const token = jwt.decode(currentToken, { complete: true })

        // disconnect if the token was malformed or missing
        if (!token) disconnectWithError(socket, 'The token was malformed.', 'invalid_token')

        // get the user ID from the token payload
        const user_id = token.payload.sub

        // check to see if we have a user with this ID in the database
        let user
        try {
          const query = { $limit: 1 }
          query[userIdField] = user_id
          user = await app.service(usersService).find({
            paginate: false,
            query
          }).then(results => {
            if (results[0]) return results[0]
            disconnectWithError(socket, 'The user_id was not found.', 'unknown_user')
          })
        } catch (err) {
          // disconnect if no such user exists
          disconnectWithError(socket, err, 'unknown_user')
        }

        // if the user already has a valid, current token, stop here
        if (user[currentTokenField] && user[currentTokenField] === currentToken) return

        // otherwise, get the kid from the token header
        const kid = token.header.kid

        // create a JWKS retrieval client
        const client = getJWKS(app.get('jwksUri'))

        // get the signing key from the JWKS endpoint at Auth0
        const key = await getKey(kid, app.service(keysService), client)

        // verify the raw JWT
        try {
          jwt.verify(currentToken, key, app.get('jwtOptions'))
        } catch (err) {
          disconnectWithError(socket, err, 'invalid_token')
        }

        // OK! The JWT is valid, store it in the user profile
        // (It's okay if this fails)
        app.service(usersService).patch(
          null,
          { currentToken },
          { query: { user_id: user.user_id } }
        )

        // allow the connection to remain open
        socket.emit('authenticated')
      })
    })
  },
  auth0Transports = app => {
    auth0Setup(app)
    auth0Hooks(app)
    auth0SocketIO(app)
  }
} = {}) => ({
  getJWKS,
  x5cToPEM,
  getKey,
  authorizeRest,
  fromAuth0,
  auth0Setup,
  addHeadersAndIP,
  auth0Hooks,
  disconnectWithError,
  auth0SocketIO,
  auth0Transports
})
