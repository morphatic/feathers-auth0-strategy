const app = require('./test-app')
const appUri = app.get('jwksUri')

const fakeJWKS = {
  'keys': [
    {
      'alg': 'RS256',
      'kty': 'RSA',
      'use': 'sig',
      'x5c': [
        'MIIC/zCCAeegAwIBAgIJAL/wBpdsjTFBMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTE5MDQxNDA0MjkzOFoXDTI5MDQxMTA0MjkzOFowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx3//jquVOqKWfNFAsXXUQSH/7lzKS0EXZabfEu6x2m9iesU57j+nbkRbUFLm6mhuTy9MSXKcoOHlFe8vVd6IrAI+6P6JIGGl2bjYwHbkLdlAjUHg/R3cCn4Es7Af5whtRX4WcNOyJQaBJNwAeVOKm+uDmmBlWoer9CNFee8SPdt/Sf360P00kzvE3MIJnFa6ME+jUOVNNYV7QmfDz/EM2C6G7uYEBeO3QI4gmbfi0AeRdLQroFiGhWF+Ag+uH5TsEJwaooc72+ua+bqok1Ixfu1aZXny4ea6TZNbDso50FmVqvNA6E/rhBzWss5rCjaBoDhpiU6uhacYO0DE5bWXhAgMBAAGjUDBOMB0GA1UdDgQWBBS3I6CR+jLB/E5O1Mebvzg4G+1j7TAfBgNVHSMEGDAWgBS3I6CR+jLB/E5O1Mebvzg4G+1j7TAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQChQsSKnkWzQzbEfn1bxzT5Lw6gOmTPefn+6eLrorGSsQpWUIMhjPWCzbmHXK+H0CbUTjB4DYyArD/G0MKM5EnfZV9q+q8imqXnnjocdjKUtE5e3mEjGniemjQGhZQbDaD9gH5U7+NEFxaOHXmc9kUhFboDuQDm/oPVxaPudxb04n3HN+Yu9cBKoIoDLsk6iqF40/dHYsCpWGdnNrwndx+fkDWaA4gJrkbjTnxj7/EqRcpkic22fEZ41gtBtZ0FwygohyxTI7PywMfzMn6ZEjHN3irxSdfm6Ij8jLsiiJVZW0CE2/a3RiZSXBRYVrLKYeZx0a/iUgVlXckr9twyjtxp'
      ],
      'n': 'zg4LsfOZ4MMmvO0b9T4WUb600UYb_Q8xonCmnEnLEKQqbU',
      'e': 'AQAB',
      'kid': 'goodKid',
      'x5t': 'N0ZBNjUzRTMyNzkwQTJCMjMwOEMyR'
    }
  ]
}
const signingKey = '-----BEGIN CERTIFICATE-----\nMIIC/zCCAeegAwIBAgIJAL/wBpdsjTFBMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV\nBAMMC2V4YW1wbGUuY29tMB4XDTE5MDQxNDA0MjkzOFoXDTI5MDQxMTA0MjkzOFow\nFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQCx3//jquVOqKWfNFAsXXUQSH/7lzKS0EXZabfEu6x2m9iesU57j+nb\nkRbUFLm6mhuTy9MSXKcoOHlFe8vVd6IrAI+6P6JIGGl2bjYwHbkLdlAjUHg/R3cC\nn4Es7Af5whtRX4WcNOyJQaBJNwAeVOKm+uDmmBlWoer9CNFee8SPdt/Sf360P00k\nzvE3MIJnFa6ME+jUOVNNYV7QmfDz/EM2C6G7uYEBeO3QI4gmbfi0AeRdLQroFiGh\nWF+Ag+uH5TsEJwaooc72+ua+bqok1Ixfu1aZXny4ea6TZNbDso50FmVqvNA6E/rh\nBzWss5rCjaBoDhpiU6uhacYO0DE5bWXhAgMBAAGjUDBOMB0GA1UdDgQWBBS3I6CR\n+jLB/E5O1Mebvzg4G+1j7TAfBgNVHSMEGDAWgBS3I6CR+jLB/E5O1Mebvzg4G+1j\n7TAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQChQsSKnkWzQzbEfn1b\nxzT5Lw6gOmTPefn+6eLrorGSsQpWUIMhjPWCzbmHXK+H0CbUTjB4DYyArD/G0MKM\n5EnfZV9q+q8imqXnnjocdjKUtE5e3mEjGniemjQGhZQbDaD9gH5U7+NEFxaOHXmc\n9kUhFboDuQDm/oPVxaPudxb04n3HN+Yu9cBKoIoDLsk6iqF40/dHYsCpWGdnNrwn\ndx+fkDWaA4gJrkbjTnxj7/EqRcpkic22fEZ41gtBtZ0FwygohyxTI7PywMfzMn6Z\nEjHN3irxSdfm6Ij8jLsiiJVZW0CE2/a3RiZSXBRYVrLKYeZx0a/iUgVlXckr9twy\njtxp\n-----END CERTIFICATE-----\n'
const unknownMemberJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhdXRoMHxpYW1ub3RpbnRoZWRhdGFiYXNlIn0.eO6k3CMM5HhqJco-o7DHQ6qlgpCEmCMYhOPFN3-0emUL5amLvZh0ETni-cG_uFtt2Nd9hoeS9XcSRVR6Adlvla6e9pRI2Ns0JQiTuhUPy_DduRbYkYHi_ED4-Jfvcaz_6vdC_KKg8rwHTmGWE66bH2tvU_TfG6kAC90M5F_tYt4'
const invalidIssuerJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imdvb2RLaWQifQ.eyJzdWIiOiJhdXRoMHxjdXJyZW50VmFsaWRUb2tlbk1lbWJlciIsImF1ZCI6WyJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20ifQ.p5BUlFfpyASaGgxSVoQkwMng97a64EvuvTyS7GafEkHchpWF8LIYvSc6q8gDDydFsfqPhXd1TNL-AfgctaYDVGamNQH3YvTW1Uock7741OaECcoQSJ4NDF_Qai6XpXN6Sl-wysK3kcDtYdOgDJwiHS9Y_k3sD_5YK0djawIRi-37yHmYhJkc__fqCDGawEfDl2FNq45iiEWh_y8dYnfpTsvMMaygQ8wNi--MukM5f3NPTvP5p4wH_gC-hNnTLgb6KBLbCgsqvA6-kPOXdVYqWIHNvJjR_SmYhAk6sNgj00Vg_Hw17rxRH05jQ95CAo2fIFwjtZIU16s9nKsYn13n6A'
const currentMemberJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imdvb2RLaWQifQ.eyJzdWIiOiJhdXRoMHxjdXJyZW50VmFsaWRUb2tlbk1lbWJlciIsImF1ZCI6WyJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20vIn0.Gcb-DG_z5K91CdwxBeJda7bBypXdNH7Uyg5kPT4fWDhOgLB1kxycJYJPCmrAPy1sbqaaQ2IG_94q622RaKn1FKskiurne1x89ZFu-39ivQUPNww6NHft2jdVnr4fxFqaEw51ErVgxaQDHXOQfiX9tsJhB6unSIJQixQFYBjJfMPDLKzhg6ZXp28TGIlDkUjFSLUkLIfZ1pg4yki9rk1kwxLZ_Uq7vaDFVKDxwPOpvX14S3_nAFje9cKZHdL9-R216nNXiaYdl4HvPSFsuH-DzxssCGiQ3tgWMCqLeEUcIn5cPQoY_Hlz00kg4GlGGPhgSHn7i0StcasIyBF3G8IWIA'

// various contexts
const afterContext = {
  app,
  type: 'after',
  params: {
    provider: ''
  }
}
const errorContext = {
  app,
  type: 'error',
  params: {
    provider: ''
  }
}
const externalContext = { app, type: 'before', params: { provider: 'external' } }
const serverContext = { app, type: 'before', params: { provider: '' } }
const fromAuth0Context = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    headers: {
      authorization: null
    },
    ip: '34.195.142.251'
  }
}
const fromEuropeanAuth0Context = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    headers: {
      authorization: null
    },
    ip: '52.28.56.226'
  }
}
const notFromAuth0Context = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    headers: {
      authorization: null
    },
    ip: '66.66.66.66'
  }
}
const noAuthenticationContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: null
  }
}
const noAuthorizationHeaderContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: {
      accessToken: null,
      strategy: 'auth0'
    }
  }
}
const malformedTokenContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: {
      accessToken: 'iamnotwellformed',
      strategy: 'auth0'
    }
  }
}
const unknownMemberContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: {
      accessToken: unknownMemberJWT,
      strategy: 'auth0'
    }
  }
}
const alreadyAuthenticatedContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: {
      accessToken: currentMemberJWT,
      strategy: 'auth0',
      authenticated: true
    }
  }
}
const invalidIssuerMemberContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: {
      accessToken: invalidIssuerJWT,
      strategy: 'auth0'
    }
  }
}
const currentValidTokenMemberContext = {
  app,
  type: 'before',
  params: {
    provider: 'external',
    authentication: {
      accessToken: currentMemberJWT,
      strategy: 'auth0'
    }
  }
}
const createValidTokenConnectionContext = {
  app,
  type: 'after',
  method: 'create',
  params: {
    connection: {
      authentication: {
        accessToken: currentMemberJWT,
        strategy: 'auth0'
      }
    },
    provider: 'socketio',
  },
  result: {
    accessToken: currentMemberJWT,
    strategy: 'auth0'
  }
}
const removeValidTokenConnectionContext = {
  app,
  type: 'after',
  method: 'remove',
  params: {
    connection: {
      authentication: {
        accessToken: currentMemberJWT,
        strategy: 'auth0'
      }
    },
    provider: 'socketio',
  },
  result: {
    accessToken: currentMemberJWT,
    strategy: 'auth0'
  }
}
const noConnectionContext = {
  app,
  type: 'after',
  method: 'create',
  params: {
    provider: 'socketio',
  },
  result: {
    accessToken: currentMemberJWT,
    strategy: 'auth0'
  }
}

module.exports = {
  app,
  appUri,
  fakeJWKS,
  signingKey,
  jwts: {
    unknownMemberJWT,
    invalidIssuerJWT,
    currentMemberJWT
  },
  contexts: {
    afterContext,
    errorContext,
    externalContext,
    serverContext,
    fromAuth0Context,
    fromEuropeanAuth0Context,
    notFromAuth0Context,
    noAuthenticationContext,
    noAuthorizationHeaderContext,
    malformedTokenContext,
    unknownMemberContext,
    alreadyAuthenticatedContext,
    invalidIssuerMemberContext,
    currentValidTokenMemberContext,
    createValidTokenConnectionContext,
    removeValidTokenConnectionContext,
    noConnectionContext
  }
}