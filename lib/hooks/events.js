// map methods to event names
const EVENTS = {
  create: 'login',
  remove: 'logout'
}

const events = () => context => {
  // extract key values from the context
  const { method, app, result, params } = context
  // set the event name to be emitted
  const event = EVENTS[method]

  // if this is one of the events we care about,
  // this is an external request (params.provider !== ''),
  // and result has a value
  if (event && params.provider && result) {
    // emit an event
    app.emit(event, result, params, context)
  }
  // carry on...
  return context
}

module.exports = events
