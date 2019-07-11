
const connection = (strategy = 'auth0') => context => {
  // extract key values from the context
  const { method, result, params: { connection } } = context
  // get the access token from context.result
  const { accessToken, ...rest } = result

  // if there is no connection object; carry on...
  if (!connection) return context

  const { authentication = {} } = connection

  // unset authentication info from the connection if we're leaving the channel, i.e. logout
  if (method === 'remove' && accessToken === authentication.accessToken) {
    delete connection.authentication
  } else if (method === 'create' && accessToken) {
    // otherwise, add authentication info to the connection, i.e. login
    Object.assign(connection, rest, { authentication: { strategy, accessToken } })
  }

  // return the mutated context
  return context
}

module.exports = connection
