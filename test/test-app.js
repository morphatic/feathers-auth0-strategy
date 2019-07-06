/**
 * Defines a minimal feathers app to use for running tests
 */
const feathers = require('@feathersjs/feathers')
const express = require('@feathersjs/express')
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

// set the auth0domain in the config
testApp.set('auth0domain', 'example')
testApp.set('paginate', { default: 10, max: 50 })

// add the users service
testApp.use('/users', createNeDBService({ Model: new nedb(), multi: true }))

// initialize a test app for which domain has not been set
const appWithoutDomain = feathers()

module.exports = {
  app: appWithKeysAndConfig,
  testApp,
  appWithoutDomain
}