const { flatten, merge, omit } = require('lodash')
const { NotAuthenticated } = require('@feathersjs/errors')

const authenticate = (originalSettings, ...originalStrategies) => {
  const settings = typeof originalSettings === 'string'
    ? { strategies: flatten([ originalSettings, ...originalStrategies])}
    : originalSettings

  if (!originalSettings || settings.strategies.length === 0) {
    throw new Error('The authenticate hook needs at least one allowed strategy')
  }

  // return the hook function
  return async context => {
    // extract key values from the context
    const { app, params, type, service } = context
    // get the authentication service and strategies from the settings
    // const authPath = settings.service || app.get('defaultAuthentication')
    // const strategies = settings.strategies
    const {
      service: authPath = app.get('defaultAuthentication'),
      strategies
    } = settings
    // get the provider and authentication details from the params
    const { provider, authentication } = params
    const authService = app.service(authPath)
    
    // make sure it is a 'before' hook
    if (type && type !== 'before') {
      throw new NotAuthenticated('The `authenticate` hook must be used as a `before` hook')
    }

    // make sure we're not trying to authenticate an authentication request
    if (service === authService) {
      throw new NotAuthenticated('The authenticate hook should not be used for the authenticate service')
    }

    // if we've already authenticated previously...carry on
    if (params.authenticated === true) return context

    if (authentication) {
      // get the params we care about, omit: provider, authentication, query
      const authParams = omit(params, 'provider', 'authentication', 'query')

      // execute the authentication request
      const authResult = await authService.authenticate(authentication, authParams, ...strategies)

      // merge the result back into the context; set authenticated to true
      context.params = merge({}, params, omit(authResult, 'accessToken'), { authenticated: true })

      // carry on...
      return context
    } else if (!authentication && provider) {
      // for internal calls provider === '', otherwise provider === rest, socketio, or primus
      // in other words, you hit this branch if an external request is being made but
      // no authentication has been set up for this service (I think...)
      throw new NotAuthenticated('Not authenticated.')
    }

    // otherwise, just return the context and move on...
    return context
  }
}

module.exports = authenticate
