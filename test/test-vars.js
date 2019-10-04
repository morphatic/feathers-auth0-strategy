const app = require('./test-app')

const fakeJWKS = {
  'keys': [
    {
      'alg': 'RS256',
      'kty': 'RSA',
      'use': 'sig',
      'x5c': [
        'MIIDqjCCApICCQCUq6mF2Up/mDANBgkqhkiG9w0BAQsFADCBljELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhSaWNobW9uZDEQMA4GA1UECgwHRXhhbXBsZTEUMBIGA1UECwwLRW5naW5lZXJpbmcxFDASBgNVBAMMC2V4YW1wbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRzb21lYm9keUBleGFtcGxlLmNvbTAeFw0xOTA3MzAyMTA5NDBaFw0yOTA3MjcyMTA5NDBaMIGWMQswCQYDVQQGEwJVUzERMA8GA1UECAwIVmlyZ2luaWExETAPBgNVBAcMCFJpY2htb25kMRAwDgYDVQQKDAdFeGFtcGxlMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIzAhBgkqhkiG9w0BCQEWFHNvbWVib2R5QGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwSVCjAs6xFDnRQHI0ppjpZ3tDgpXarUXmQFabVhjTJ/lan358SoBKF5ZZ+XnCIC/PvLk/QAWorBw+nAlLg7CFA9dysG9MUIU4rAlhrUoIWkcCuadHh8+GTKV0cIb+hdqOCiWc9CEyInIVk3rxNAQb37io43gPYI0+skDDLZiN2ZEYZ7L33T+4CLGNzGoqcptNUHMcuiKYdFwfWbk2BGhpaHHZYQjKLEOaCHFSySZngvXPWEJiUxX+VMF6NxqpKJzFmfh/mAwtTC1N3tHUkt04H1g8K9q/qb/JZzvThyywvSyy0Zo/DBpYNrKFjBPrwTC1yEE01EcPIZqI8N1CaAApwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBzpRHw4NbD1LkA1zd8xNtQOhKDYs+VtqXi06D5YuHPF+YKTq33uvvDsy5BwTo25m0rAERoLdSotP+5HC/v4kfYsr/7JouGD6toLQkXHX8OfKH4O4QUY+zRLEIVPn5pPXmYdbQUE8yhUH1pz4TXkuo6Ct1Vgi/XxFCdXkpSVrgGk0/FGXp3/vu/zBxkPA9XcwHmuQyeT1qTGj1fheuKSQnbJ9ZBIPNQdfGhQH7OOVuzjyXNG/+Rlk3d2xzAcecUGvdmkw5zYAdhWELpxhr9/XGIqekAKUW8AyGwvWMRNMrGeSQh/e1XTUijH8TJ0/8emnKipf30O5eghHN/ppmahHQx'
      ],
      'n': 'wSVCjAs6xFDnRQHI0ppjpZ3tDgpXarUXmQFabVhjTJ_lan358SoBKF5ZZ-XnCIC_PvLk_QAWorBw-nAlLg7CFA9dysG9MUIU4rAlhrUoIWkcCuadHh8-GTKV0cIb-hdqOCiWc9CEyInIVk3rxNAQb37io43gPYI0-skDDLZiN2ZEYZ7L33T-4CLGNzGoqcptNUHMcuiKYdFwfWbk2BGhpaHHZYQjKLEOaCHFSySZngvXPWEJiUxX-VMF6NxqpKJzFmfh_mAwtTC1N3tHUkt04H1g8K9q_qb_JZzvThyywvSyy0Zo_DBpYNrKFjBPrwTC1yEE01EcPIZqI8N1CaAApw',
      'e': 'AQAB',
      'kid': 'goodKid',
      'x5t': 'ubQTcREssEE0m2LV46gck3oc+N8='
    }
  ]
}

// although either the **certificate** OR the **public key** can be used to verify a JWT,
// the key stored in Auth0's JWKS is a **certificate** so that is what needs to be used here.
const signingCertificate = '-----BEGIN CERTIFICATE-----\nMIIDqjCCApICCQCUq6mF2Up/mDANBgkqhkiG9w0BAQsFADCBljELMAkGA1UEBhMC\nVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhSaWNobW9uZDEQMA4GA1UE\nCgwHRXhhbXBsZTEUMBIGA1UECwwLRW5naW5lZXJpbmcxFDASBgNVBAMMC2V4YW1w\nbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRzb21lYm9keUBleGFtcGxlLmNvbTAeFw0x\nOTA3MzAyMTA5NDBaFw0yOTA3MjcyMTA5NDBaMIGWMQswCQYDVQQGEwJVUzERMA8G\nA1UECAwIVmlyZ2luaWExETAPBgNVBAcMCFJpY2htb25kMRAwDgYDVQQKDAdFeGFt\ncGxlMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEUMBIGA1UEAwwLZXhhbXBsZS5jb20x\nIzAhBgkqhkiG9w0BCQEWFHNvbWVib2R5QGV4YW1wbGUuY29tMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwSVCjAs6xFDnRQHI0ppjpZ3tDgpXarUXmQFa\nbVhjTJ/lan358SoBKF5ZZ+XnCIC/PvLk/QAWorBw+nAlLg7CFA9dysG9MUIU4rAl\nhrUoIWkcCuadHh8+GTKV0cIb+hdqOCiWc9CEyInIVk3rxNAQb37io43gPYI0+skD\nDLZiN2ZEYZ7L33T+4CLGNzGoqcptNUHMcuiKYdFwfWbk2BGhpaHHZYQjKLEOaCHF\nSySZngvXPWEJiUxX+VMF6NxqpKJzFmfh/mAwtTC1N3tHUkt04H1g8K9q/qb/JZzv\nThyywvSyy0Zo/DBpYNrKFjBPrwTC1yEE01EcPIZqI8N1CaAApwIDAQABMA0GCSqG\nSIb3DQEBCwUAA4IBAQBzpRHw4NbD1LkA1zd8xNtQOhKDYs+VtqXi06D5YuHPF+YK\nTq33uvvDsy5BwTo25m0rAERoLdSotP+5HC/v4kfYsr/7JouGD6toLQkXHX8OfKH4\nO4QUY+zRLEIVPn5pPXmYdbQUE8yhUH1pz4TXkuo6Ct1Vgi/XxFCdXkpSVrgGk0/F\nGXp3/vu/zBxkPA9XcwHmuQyeT1qTGj1fheuKSQnbJ9ZBIPNQdfGhQH7OOVuzjyXN\nG/+Rlk3d2xzAcecUGvdmkw5zYAdhWELpxhr9/XGIqekAKUW8AyGwvWMRNMrGeSQh\n/e1XTUijH8TJ0/8emnKipf30O5eghHN/ppmahHQx\n-----END CERTIFICATE-----\n'

// this JWT represents an otherwise valid user/request, but there is no record in the database for them
const unknownMemberJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imdvb2RLaWQifQ.eyJzdWIiOiJhdXRoMHxpYW1ub3RpbnRoZWRhdGFiYXNlIiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20vYXBpL3YyLyIsImh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20vdXNlcmluZm8iXSwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmF1dGgwLmNvbS8ifQ.NgstVIZfonSpbjPL6VHTVZ-Z_vp6kIBtXmPquBN2ltvwUPNQ638qtrzN4Hl7HEnQ8_Iu0k3U-1Gab54EKsANIlUDkzuPjiae2py3WFyQ2jSjahS1tl-4QgPEzny_2SLzGDEe4UVswYDvZFB2JUN0pf7YUMw_nyCN8IN_X-ZIgkdPhbVWVnQMhnJLp03pedDF7pZ6DnLSg4HKLC4_i4MZoboyjBMcpnE7plqgyFzOF166xzdzk6YHS0PKNpyKO6Sym8rvKJx619tBm7qcHLNyHJbao88b9sHSwwkzkY1B-9q1iFSSsTUjJi80UW2YzPej-yBTkC6VaMCSVEyrzAe_MA'

/**
 * The `iss` claim on the JWT payload is _very_ sensitive. This JWT is missing the
 * final trailing slash from the URL of the JWT issuer.
 */
const invalidIssuerJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imdvb2RLaWQifQ.eyJzdWIiOiJhdXRoMHxjdXJyZW50VmFsaWRUb2tlbk1lbWJlciIsImF1ZCI6WyJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20ifQ.WAQppWHg3c9rppqzr9glTLSkvPThJM3FUCWTos-kIcEZBI9WQZNNYk04DAzqiWlyEYeXfWjkeqPOvV11JSby3RHYPbpwFdGRtfc5NqlnI9VT1HDJeqrLhLvp5VcaEzVoYoWgeO2Cv4e14f0Uqek6H17l7N140mC_z87TRd1fJ7I_Ztvq051rqeNqydm7ArC7ZZPnN2HJbPQO0AT6qFhiKKc5MmrkJnmBKyd8LfH6XDIYo9dDfVGTEBcOkH4JX1oLsvmSh_Us8-Iwww_UyaI6OOuNWU_qegk4EZbyMiKZIMRWqtKOWj3bikZKhIiYapOuFHBJrhdDp38fEnKAMXIirA'

const currentMemberJWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imdvb2RLaWQifQ.eyJzdWIiOiJhdXRoMHxjdXJyZW50VmFsaWRUb2tlbk1lbWJlciIsImF1ZCI6WyJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20vIn0.rmQ_3u1cCCrYuSZsfqVXASPJ8168_fZZhu_AcxH8QP3t-nxYh0LJXhz9awv2A1aE8fehH7MiqEKGo3tYGg1cq05Ry6Esyu92IKKePKhMEsKiFs1D_NAhVbwyx1MGKh4l1McWJvWb6z_-iurdJLGhs9n0C4vFlT9ANejuPkQJv-SkXITixqJqqY_cWpkQGX011L8N1ijAmYwUnfkDwqV8-ts5NJMVZ56gVEVmsmVJVURN4jNmjl1qyXUfveANlXLryTvWFsov9yRinS8K4K5PSoyJoBsUsQj8QM9C8o2DrbQYjE1JgatN5qizbcC_w5wKxwaiKZrIgb42hNOk-FIVGw'


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
  fakeJWKS,
  signingCertificate,
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