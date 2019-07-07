/**
 * Defines a minimal feathers app to use for running tests
 */
const feathers = require('@feathersjs/feathers')
const express = require('@feathersjs/express')
const socketio = require('@feathersjs/socketio')
const socketClient = require('@feathersjs/socketio-client')
const io = require('socket.io-client')
const config = require('@feathersjs/configuration')
const nedb = require('nedb')
const createNeDBService = require('feathers-nedb')
const createMemoryService = require('feathers-memory')

// initialize a test app for testing utility functions
// that acts like auth0Setup() has already been run
const appWithKeysAndConfig = feathers()

// load the config
appWithKeysAndConfig.configure(config())

// create the schema for users
// add users and keys services
appWithKeysAndConfig.use('/users', createNeDBService({ Model: new nedb(), multi: true }))
appWithKeysAndConfig.use('/keys', createMemoryService())

// initialize a test app that is closer to mimicking an
// actual app scenario
const testApp = express(feathers())
testApp.configure(socketio())

// set the auth0domain in the config
testApp.set('auth0domain', 'example')
testApp.set('paginate', { default: 10, max: 50 })
testApp.set('host', 'localhost')

// add the users service
testApp.use('/users', createNeDBService({ Model: new nedb(), multi: true }))

// setup test client generator
const makeClient = options => {
  const app = feathers()
  const socket = io('http://localhost:3030')
  socket.on('connect', () => {
    console.log('hi') // eslint-disable-line
    socket.emit('authenticate', options.token)
  })
    .on('unauthorized', err => {
      console.log('Ruh-roh!', err) // eslint-disable-line
    })
    .on('disconnect', () => {
      console.log('bye') // eslint-disable-line
    })
  app.configure(socketClient(socket))
  return app
}

// initialize a test app for which domain has not been set
const appWithoutDomain = feathers()

module.exports = {
  app: appWithKeysAndConfig,
  testApp,
  appWithoutDomain,
  makeClient
}