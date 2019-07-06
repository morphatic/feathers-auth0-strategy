const assert = require('assert')
const {
  app,
  appUri,
  fakeJWKS,
  signingKey,
  mockKeyService,
  mockJWKSClient,
  jwts,
  contexts
} = require('./test-vars')

// import the hook subbing in mocks for the helper functions
const { authorize, getJWKS, x5cToPEM, getKey } = require('../lib')({
  getJWKS: mockJWKSClient
})

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
  })

  describe('an authorize() function that', () => {
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
      assert(typeof authorize === 'function', 'authorize() is not a function.')
    })

    it('throws an error if called from an after context', async () => {
      try { await authorize(contexts.afterContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', '\'name\' should be \'NotAuthenticated\'')
        assert.strictEqual(
          err.message,
          '`authorize()` can only be used as a `before` hook.',
          'wrong message'
        )
      }
    })

    it('throws an error if called from an error context', async () => {
      try { await authorize(contexts.errorContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', '\'name\' should be \'NotAuthenticated\'')
        assert.strictEqual(
          err.message,
          '`authorize()` can only be used as a `before` hook.',
          'wrong message'
        )
      }
    })

    it('throws an error if the Authorization header is not set', async () => {
      try { await authorize(contexts.noAuthorizationHeaderContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenicated\'')
        assert.strictEqual(err.message, '`Authorization` header not set.', 'wrong message')
      }
    })

    it('throws an error if the token is malformed or missing', async () => {
      try { await authorize(contexts.malformedTokenContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenicated\'')
        assert.strictEqual(err.message, 'The token was malformed or missing.', 'wrong message')
      }
    })

    it('throws an error if the user does not exist', async () => {
      try { await authorize(contexts.unknownMemberContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenicated\'')
        assert.strictEqual(err.message, 'No member with this ID exists.', 'wrong message')
      }
    })

    it('returns the context if the JWT is already associated with the member', async () => {
      const context = await authorize(contexts.currentValidTokenMemberContext)
      assert.deepEqual(context, contexts.currentValidTokenMemberContext, 'the contexts were not the same')
    })

    it('throws an error if the token cannot be verified', async () => {
      // remove the currentToken for our test member
      await app.service('users').patch(null,
        { currentToken: null },
        { query: { user_id: 'auth0|currentValidTokenMember' } }
      )
      try { await authorize(contexts.invalidIssuerMemberContext) }
      catch (err) {
        assert.strictEqual(err.name, 'NotAuthenticated', 'should be \'NotAuthenicated\'')
        assert.strictEqual(err.message, 'Token could not be verified.', 'wrong message')
        assert.strictEqual(err.data, 'jwt issuer invalid. expected: https://example.auth0.com/', 'wrong data')
      }
    })

    it('returns the context if the JWT is successfully verified', async () => {
      // remove the currentToken for our test member
      await app.service('users').patch(null,
        { currentToken: null },
        { query: { user_id: 'auth0|currentValidTokenMember' } }
      )
      const context = await authorize(contexts.currentValidTokenMemberContext)
      assert.deepEqual(context, contexts.currentValidTokenMemberContext, 'the contexts were not the same')
    })
  })
})
