const assert = require('assert')
/* eslint-disable no-unused-vars */
const {
  app,
  testApp,
  appWithoutDomain,
  appUri,
  fakeJWKS,
  signingKey,
  mockKeyService,
  mockJWKSClient,
  jwts,
  contexts
} = require('./test-vars')

// import the hook subbing in mocks for the helper functions
const {
  getJWKS,
  x5cToPEM,
  getKey,
  authorizeRest,
  fromAuth0,
  auth0Setup,
  addHeadersAndIP,
  auth0Hooks,
  auth0SocketIO,
  auth0Transports
} = require('../lib')({
  getJWKS: mockJWKSClient
})
/* eslint-enable no-unused-vars */

const clone = obj => JSON.parse(JSON.stringify(obj))

describe('An authorization hook has', () => {
  describe('a getJWKS() helper that', () => {
    it('is a function', () => {
      assert(typeof getJWKS === 'function', 'getJWKS() is not a function')
    })

    it('returns a function when passed a uri (string)', () => {
      assert(
        typeof getJWKS(appUri) === 'function',
        'Calling getJWKS() with a valid URI parameter did not return a function'
      )
    })

    it('returns a JWKS asynchronously', async () => {
      const client = getJWKS(appUri)
      const jwks = await client()
      assert.deepEqual(jwks, fakeJWKS, 'getJWKS() client did not return the expected JWKS')
    })
  })

  describe('a x5cToPEM() helper that', () => {
    it('is a function', () => {
      assert(typeof x5cToPEM === 'function', 'x5cToPEM() is not a function.')
    })

    it('extracts a key in PEM format from a JWK', () => {
      const pem = x5cToPEM(fakeJWKS.keys[0])
      assert.strictEqual(pem, signingKey, 'x5cToPEM() did not extract the expected key from the JWK')
    })

    it('throws an error if the JWK has no x5c elements', () => {
      try {
        const jwkWithNoX5C = JSON.parse(JSON.stringify(fakeJWKS.keys[0]))
        jwkWithNoX5C.x5c = []
        x5cToPEM(jwkWithNoX5C)
      } catch (err) {
        assert.strictEqual(err.name, 'GeneralError', 'should throw a GeneralError')
        assert.strictEqual(err.message, 'Stored JWK has no x5c property.', 'message should be \'Stored JWK has no x5c property.\'')
      }
    })
  })

  describe('a getKey() helper that', () => {
    it('is a function', () => {
      assert(typeof getKey === 'function', 'getKey() is not a function.')
    })

    it('returns a signing key in PEM format', async () => {
      const key = await getKey('goodKid', mockKeyService, getJWKS(appUri))
      assert(key === signingKey, 'getKey() did not return the key expected')
    })

    it('throws an error if key is not already in memory and the jwksClient gets a bad URI', async () => {
      try {
        await getKey('badKid', mockKeyService, getJWKS('badURI'))
      } catch (err) {
        assert.strictEqual(err.name, 'GeneralError', 'should throw a GeneralError')
        assert.strictEqual(err.data, 'The URI for the JWKS was incorrect', 'should let us know the JWKS URI was wrong')
        assert.strictEqual(err.message, 'Could not retrieve JWKS', 'message should be\'Could not retrieve JWKS\'')
      }
    })

    it('throws an error if key is not already in memory and the retrieved JWKS does not contain `kid`', async () => {
      try {
        await getKey('badKid', mockKeyService, getJWKS('noMatchingKeysURI'))
      } catch (err) {
        assert.strictEqual(err.name, 'GeneralError', 'should throw a GeneralError')
        assert.strictEqual(err.message, 'Could not find a JWK matching given kid', 'message should be \'Could not find a JWK matching given kid\'')
      }
    })

    it('will return a stored key if found in the database', async () => {
      await app.service('keys').create(fakeJWKS.keys[0])
      const key = await getKey('goodKid', mockKeyService, getJWKS(appUri))
      assert(key === signingKey, 'getKey() did not return the key expected')
    })
  })

  describe('an authorizeRest() function that', () => {
    before(async () => {
      // add a Member with a valid currentToken
      await app.service('users').create({
        user_id: 'auth0|currentValidTokenMember',
        currentToken: jwts.currentMemberJWT
      })
    })

    after(async () => {
      // remove the Member added in before()
      await app.service('users').remove(null, {
        query: {
          user_id: 'auth0|currentValidTokenMember'
        }
      })
    })

    it('is a function', () => {
      assert(typeof authorizeRest === 'function', 'authorizeRest() is not a function.')
    })

    it('throws an error if called from an after context', async () => {
      try { await authorizeRest(contexts.afterContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', '\'name\' should be \'NotAuthenticated\'')
        assert.strictEqual(
          err.message,
          '`authorizeRest()` can only be used as a `before` hook.',
          'wrong message'
        )
      }
    })

    it('throws an error if called from an error context', async () => {
      try { await authorizeRest(contexts.errorContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', '\'name\' should be \'NotAuthenticated\'')
        assert.strictEqual(
          err.message,
          '`authorizeRest()` can only be used as a `before` hook.',
          'wrong message'
        )
      }
    })

    it('throws an error if the Authorization header is not set', async () => {
      try { await authorizeRest(contexts.noAuthorizationHeaderContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenticated\'')
        assert.strictEqual(err.message, '`Authorization` header not set.', 'wrong message')
      }
    })

    it('throws an error if the token is malformed or missing', async () => {
      try { await authorizeRest(contexts.malformedTokenContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenticated\'')
        assert.strictEqual(err.message, 'The token was malformed or missing.', 'wrong message')
      }
    })

    it('throws an error if the user does not exist', async () => {
      try { await authorizeRest(contexts.unknownMemberContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenticated\'')
        assert.strictEqual(err.message, 'No user with this ID exists.', 'wrong message')
        assert.strictEqual(err.data, 'User was not found in the database', 'Error data not passed')
      }
    })

    it('returns the context if the JWT is already associated with the user', async () => {
      const context = await authorizeRest(contexts.currentValidTokenMemberContext)
      assert.deepEqual(context, contexts.currentValidTokenMemberContext, 'the contexts were not the same')
    })

    it('throws an error if the token cannot be verified', async () => {
      // remove the currentToken for our test user
      await app.service('users').patch(null,
        { currentToken: null },
        { query: { user_id: 'auth0|currentValidTokenMember' } }
      )
      try { await authorizeRest(contexts.invalidIssuerMemberContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenticated\'')
        assert.strictEqual(err.message, 'Token could not be verified.', 'wrong message')
        assert.strictEqual(err.data, 'jwt issuer invalid. expected: https://example.auth0.com/', 'wrong data')
      }
    })

    it('returns the context if the JWT is successfully verified', async () => {
      // remove the currentToken for our test user
      await app.service('users').patch(null,
        { currentToken: null },
        { query: { user_id: 'auth0|currentValidTokenMember' } }
      )
      const context = await authorizeRest(contexts.currentValidTokenMemberContext)
      assert.deepEqual(context, contexts.currentValidTokenMemberContext, 'the contexts were not the same')
    })
  })

  describe('a fromAuth0() hook', () => {
    it('is a function', () => {
      assert(typeof fromAuth0 === 'function', 'fromAuth0() is not a function.')
    })

    it('returns true if the request context comes from a whitelisted IP address', async () => {
      const isWhitelisted = await fromAuth0(contexts.fromAuth0Context)
      assert(isWhitelisted, 'an IP address on the whitelist was rejected')
    })

    it('returns false if the request context comes from a non-whitelisted IP address', async () => {
      const isWhitelisted = await fromAuth0(contexts.notFromAuth0Context)
      assert(!isWhitelisted, 'an IP address not on the whitelist was accepted')
    })
  })

  describe('an auth0Setup() function', () => {
    it('is a function', () => {
      assert(typeof auth0Setup === 'function', 'auth0Setup() is not a function.')
    })

    it('throws an error if the Auth0 domain has not been set', () => {
      try { appWithoutDomain.configure(auth0Setup) }
      catch (err) {
        assert.strictEqual(err.name, 'Error', '\'name\' should be \'Error\'')
        assert.strictEqual(
          err.message,
          '[feathers-auth0-authorize] Auth0 domain must be set',
          'wrong message'
        )
      }
    })

    it('sets the jwksUri', () => {
      testApp.configure(auth0Setup)
      assert.strictEqual(
        testApp.get('jwksUri'), appUri, '`jwksUri` was not set correctly'
      )
    })
      
    it('sets the jwtOptions', () => {
      testApp.configure(auth0Setup)
      const algorithm = 'RS256'
      const domain = testApp.get('auth0domain')
      assert.deepEqual(
        testApp.get('jwtOptions'), {
          algorithms: [algorithm],
          audience: [
            `https://${domain}.auth0.com/api/v2/`,
            `https://${domain}.auth0.com/userinfo`
          ],
          ignoreExpiration: false,
          issuer: `https://${domain}.auth0.com/`
        }, '`jwtOptions` were not set correctly'
      )
    })

    it('creates the `keys` service and sets default pagination', async () => {
      testApp.configure(auth0Setup)
      const keyService = testApp.service('keys')
      const keys = await keyService.find()
      const maxKeys = await keyService.find({ query: { $limit: 100 } })
      assert(keyService, 'The `keys` service was not created')
      assert.strictEqual(keys.limit, 10, 'Pagination for `keys` was not setup correctly')
      assert.strictEqual(maxKeys.limit, 50, 'Pagination for `keys` was not setup correctly')
    })
    
    it('prevents external requests from accessing the `keys` service', async () => {
      testApp.configure(auth0Setup)
      const keysHooks = testApp.service('keys').__hooks.before;
      ['find', 'get', 'create', 'update', 'patch', 'remove'].forEach(
        hook => {
          assert(Array.isArray(keysHooks[hook]), `No "${hook}" hooks are defined`)
          assert(keysHooks[hook].length, 1, `Wrong number of "${hook}" hooks defined`)
          const disallow = keysHooks[hook][0]
          const externalContext = clone(contexts.externalContext)
          const serverContext = clone(contexts.serverContext)
          externalContext.method = hook
          serverContext.method = hook
          assert.throws(() => { disallow(externalContext) }, `"${hook}" hook doesn't throw for external context`)
          assert.strictEqual(disallow(serverContext), undefined, `Disallow "${hook}" returned the wrong result`)
        }
      )
    })
  })

  describe('an addHeadersAndIP() function', () => {
    const requestWithIP = {
      feathers: {
        provider: 'external'
      },
      headers: {
        authorization: 'Bearer 12345'
      },
      ip: '66.66.66.66'
    }
    const requestWithXRealIP = {
      feathers: {
        provider: 'external'
      },
      headers: {
        authorization: 'Bearer 12345',
        'x-real-ip': '66.66.66.66'
      }
    }
    const feathersAfter = {
      provider: 'external',
      headers: {
        authorization: 'Bearer 12345'
      },
      ip: '66.66.66.66'
    }
    const feathersAfterXRealIP = {
      provider: 'external',
      headers: {
        authorization: 'Bearer 12345',
        'x-real-ip': '66.66.66.66'
      },
      ip: '66.66.66.66'
    }

    it('is a function', () => {
      assert(typeof addHeadersAndIP === 'function', 'addHeadersAndIP() is not a function.')
    })

    it('adds headers to the feathers object in the request', () => {
      const after = addHeadersAndIP(requestWithIP)
      assert.deepEqual(after.feathers, feathersAfter, 'The headers and IP address were not added to the feathers object')
    })

    it('adds headers to the feathers object in the request', () => {
      const after = addHeadersAndIP(requestWithXRealIP)
      assert.deepEqual(after.feathers, feathersAfterXRealIP, 'The headers and IP address were not added to the feathers object')
    })
  })

  /* TODO: 1 */
  describe('an auth0Hooks() function', () => {
    before(async () => {
      testApp.configure(auth0Setup)
      // add a Member with a valid currentToken
      await app.service('users').create({
        user_id: 'auth0|currentValidTokenMember',
        currentToken: jwts.currentMemberJWT
      })
    })

    after(async () => {
      // remove the Member added in before()
      await app.service('users').remove(null, {
        query: {
          user_id: 'auth0|currentValidTokenMember'
        }
      })
    })

    it('is a function', () => {
      assert(typeof auth0Hooks === 'function', 'auth0Hooks() is not a function.')
    })

    xit('registers middleware that passes the IP address and HTTP headers to the context', () => {
      testApp.configure(auth0Hooks)
    })

    it('registers authorizeRest to run before all non-Auth0, external REST requests', () => {
      testApp.configure(auth0Hooks);
      ['find', 'get', 'create', 'update', 'patch', 'remove'].forEach(
        async hook => {
          const hooks = testApp.__hooks.before[hook]
          // console.log(testApp.__hooks) // eslint-disable-line
          assert(Array.isArray(hooks), `No "${hook}" hooks are defined for the app`)
          assert(hooks.length > 0, `Wrong number of "${hook}" hooks defined for the app`)
          const authorizeRest = hooks.pop()
          // console.log(authorizeRest.toString()) // eslint-disable-line
          // const externalContext = clone(contexts.externalContext)
          // const serverContext = clone(contexts.serverContext)
          // externalContext.method = hook
          // serverContext.method = hook
          try {
            await authorizeRest(contexts.invalidIssuerMemberContext)
          } catch (err) {
            assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenticated\'')
          }
          try {
            const context = await authorizeRest(contexts.currentValidTokenMemberContext)
            assert.deepEqual(
              context,
              contexts.currentValidTokenMemberContext,
              `authorizeRest() "${hook}" returned the wrong result`
            )
          } catch (err) {
            // noop
          }
        }
      )          
    })
  })

  describe('an auth0SocketIO() function', () => {
    it('is a function', () => {
      assert(typeof auth0SocketIO === 'function', 'auth0SocketIO() is not a function.')
    })

  })
})
