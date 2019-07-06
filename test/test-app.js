/**
 * Defines a minimal feathers app to use for running tests
 */
const feathers = require('@feathersjs/feathers')
const config = require('@feathersjs/configuration')
const nedb = require('nedb')
const createNeDBService = require('feathers-nedb')
const createMemoryService = require('feathers-memory')

// initialize the test app
const app = feathers()

// load the config
app.configure(config())

// create the schema for users
// add users and keys services
app.use('/users', createNeDBService({ Model: new nedb(), multi: true }))
app.use('/keys', createMemoryService())

module.exports = app