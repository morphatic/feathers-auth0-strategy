# FeathersJS Auth0 Authorization Strategy

[![Build Status](https://travis-ci.org/morphatic/feathers-auth0-strategy.svg?branch=master)](https://travis-ci.org/morphatic/feathers-auth0-strategy)
[![Coverage Status](https://coveralls.io/repos/github/morphatic/feathers-auth0-strategy/badge.svg?branch=master)](https://coveralls.io/github/morphatic/feathers-auth0-strategy?branch=master)
[![npm version](https://badge.fury.io/js/%40morphatic%2Ffeathers-auth0-strategy.svg)](https://www.npmjs.com/package/@morphatic/feathers-auth0-strategy)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/morphatic/feathers-auth0-strategy/master/LICENSE)

:warning: **This package is designed to work with the [FeatherJS v4.0 (Crow)](https://crow.docs.feathersjs.com/), currently (2019-07-30) in pre-release.** :warning:

## What this package does

This package does two things:

1. It implements a [custom `auth0` authentication strategy for FeathersJS](https://crow.docs.feathersjs.com/api/authentication/strategy.html). The `Auth0Strategy` verifies JWTs ([JSON Web Tokens](https://jwt.io/)) using the asymmetric `RS256` algorithm ([the recommended practice](https://auth0.com/blog/navigating-rs256-and-jwks/)), rather than the `HS256` algorithm that is built into the FeathersJS [`JwtStrategy`](https://crow.docs.feathersjs.com/api/authentication/jwt.html#jwtstrategy).
2. It implements a [custom FeathersJS authentication service](https://crow.docs.feathersjs.com/api/authentication/service.html#customization). The `Auth0Service` extends, and is designed to be used in place of the default [`AuthenticationService`](https://crow.docs.feathersjs.com/api/authentication/service.html). The primary benefits of the `Auth0Service` are that it:
   1. Removes the necessity for developers to specify the `authentication.secret` configuration property in their apps. The client secret is not used by `RS256` token verification scenarios, but the default `AuthenticationService` will throw an error if the `secret` is not specified.
   2. Automatically configures the hooks necessary to force all clients to be authenticated when accessing API services. By default, all services will require authentication **_except_** the `/authentication` service itself.
   3. Implements an IP address whitelist that will allow requests coming directly from Auth0 to access the API without authentication. The IP whitelist can be configured by implementers.

This package has been designed and tested for use with the latest version of FeathersJS (v4.0, aka "Crow"). Otherwise, this package is designed to be completely compatible with FeathersJS authentication, and should integrate seamlessly with other FeathersJS packages or plugins that use authentication. Note, the `Auth0Strategy` may be used on its own without also using the `Auth0Service` but this will require developers to explicitly add authentication hooks to services (which is the standard practice already). The `Auth0Service` should only be used if developers are sure that they want to require authentication for ALL non-authentication services.

## Who should use this package

This package is designed specifically for the following scenario:

* [FeathersJS](https://feathersjs.com/) is being used solely as a backend API server
* [Auth0](https://auth0.com/) is being used for authentication from a frontend client written with, e.g. Vue, React, or Angular
* Auth0 is configured to sign access tokens using the **`RS256`** algorithm ([the recommended practice](https://auth0.com/blog/navigating-rs256-and-jwks/))

For a fuller discussion of this scenario and why I chose to write this package, [check out this blog post](https://morphatic.com/2019/04/14/authorizing-feathers-api-requests-for-vue-react-angular-apps-using-auth0/).

## Who should NOT use this package

If any of the following scenarios apply to your app, there are likely better options than this package:

* If you are using FeathersJS as **BOTH** frontend and backend, you're probably much better off simply using the [`@feathersjs/authentication`](https://docs.feathersjs.com/api/authentication/server.html) that's already part of the framework.
* If your access tokens are signed with the `HS256` algorithm (see: [How can I check the signature algorithm?](https://auth0.com/docs/api-auth/tutorials/verify-access-token#check-the-signature-algorithm)), there are easier ways to configure Feathers to verify them, namely to use the built-in `JwtStrategy`.

## Installation and Configuration

To install this package, from the root of your FeathersJS app:

```console
npm install --save @morphatic/feathers-auth0-strategy
```

After installation, you need to make sure that you have a `users` service. Customization of the `users` service will be discussed below.

### Update the app configuration

In your server config file (usually `config/default.json`), at a minimum, you'll need to add the following:

```json
{
  "authentication": {
    "auth0": {
      "domain": "example"
    },
    "authStrategies": [
      "auth0"
    ],
    "createIfNotExists": false,
    "entity": "users",
    "entityId": "user_id",
    "service": "users"
  }
}
```

The package assumes that your full Auth0 domain name is something like `https://example.auth0.com/`. You should only add the "example" part to your config. Note that you do **NOT** need to specify a `secret` since the `RS256` algorithm doesn't use them. You also do not need to specify `jwtOptions` as these are handled automatically by this package.

### Set up the `users` service

It's likely that you already have a `users` service in your app. If you don't, you'll need to create one. Assuming you already have a `users` service, you'll need to ensure that your model has a `user_id` property. The `user_id` field will hold the `user_id` generated by Auth0 when the user's account was created. For reference, [a JSON Schema representation of a minimal `users` service](https://github.com/morphatic/feathers-auth0-strategy/blob/master/test/user-schema.json) is included in this repo.

If you'd like to use a different service for storing user information or the `user_id` key, this is configurable using the `options` described below.

### Decide how to handle non-existent users

By default, this package will **NOT** add users to your API database. This is primarily an issue that affects authentication when users first create an account with your app. Since the signup and authentication process is handled by Auth0, you have to have some way to get the Auth0 `user_id` stored in a new `user` record in your API's database.

#### Option #1: Direct Auth0 <==> API `user` creation

One way to get your Auth0 users into your API is to have Auth0 make an API request directly. From the [Auth0 management dashboard](https://manage.auth0.com/dashboard), you can go to the "Rules" menu and create a new rule that will attempt to make an API request whenever someone logs in. I have something like this:

```js
/**
 * A RULE created from the Auth0 Dashboard
 * Add user to the API users table
 */
function (user, context, callback) {
  // check to see if they've already been added
  if (user.app_metadata && !user.app_metadata.api_id) {
    // no, they haven't, so...
    // load the library we'll need to make an API request
    const axios = require('axios');

    // construct our URL and POST body
    // NOTE: You MUST send an additional `api_url` param with the
    // authentication request so Auth0 knows how to find your API!!!
    const url = `${context.request.query.api_url}/users`;
    const body = { ...user };
    delete body._id;

    // try to create/update a new user via the API
    // NOTE: I'm using an "upsert" query here. Setting this up
    // requires additional configuration on the API server side
    axios.patch(url, body, {
      headers: { 'content-type': 'application/json' },
      params: { user_id: user.user_id }
    }).then(
      api_user => {
        // it worked! set the API _id for the created user in app_metadata
        if (Array.isArray(api_user.data) && api_user.data[0] && api_user.data[0]._id) {
          user.app_metadata.api_id = api_user.data[0]._id;
        } else if (Array.isArray(api_user.data.upserted) && api_user.data.upserted[0]._id) {
          user.app_metadata.api_id = api_user.data.upserted[0]._id;
        } else {
          user.app_metadata.api_id = '';
        }
        return auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
      })
      .then(() => {
        callback(null, user, context);
      })
      .catch((err) => {
        console.log('error',err);
        // it didn't work.
        callback(null, user, context);
      });
  } else {
    // yes, they've already been added to the API
    // carry on...
    callback(null, user, context);
  }
}
```

As will be explained below, [this package sets up an IP address whitelist to allow requests from Auth0 to be accepted by your API](#the-fromauth0-ip-address-whitelist) without the normal authentication. (You'll still need some mechanism to make sure that the requests actually came from Auth0 and not another agent spoofing an Auth0 IP address.)

#### Option #2: Allow `Auth0Strategy` to create new `users`

A second method for creating users in your API database is to configure `Auth0Strategy` to allow a new `user` to be created if one doesn't already exist with the given Auth0 `user_id`. To do this, the default configuration needs to be updated to:

```json
{
  "authentication": {
    "auth0": {
      "domain": "example"
    },
    "authStrategies": [
      "auth0"
    ],
    "createIfNotExists": true, // <-- SET THIS TO `TRUE`
    "entity": "users",
    "entityId": "user_id",
    "service": "users"
  }
}
```

In this case, the very first time a new user attempts to authenticate, a new `user` record will be created that contains ONLY the Auth0 `user_id`. This happens AFTER the `access_token` has been verified to be valid.

This is easier to set up than the previous option, but it also means you'll have to figure out another way to transfer the user's profile from Auth0 to the API.

### :warning: This package does NOT check permissions

This package is designed to verify that access tokens sent from your client are:

1. Valid
2. Current (i.e. not expired)
3. Associated with an **existing** user account (although it is possible to create a **minimal** user record automatically)

That said, this package does **NOT** check to see if the users making API requests actually have permission to access the requested resources. You'll need to address permissions in some other way. Also, since Auth0 allows you to store user-related information in `user_metadata`, and since app developers will make different decisions about where to store user info (API vs Auth0), how much (if any) info to duplicate across these stores, I chose not to address this in this package. Likewise, permissions scenarios are also likely to vary widely across apps, and are hence unaddressed here.

## Basic usage

You'll need to do some configuration on both the server and in your clients.

### Server setup when using `Auth0Service`

If you choose to use **BOTH** `Auth0Strategy` and `Auth0Service`, in your main server configuration (usually `src/app.js`):

```js
// src/app.js

// import the service and strategy classes
const { addIP, Auth0Service, Auth0Strategy } = require('@morphatic/feathers-auth0-strategy')

// configure middleware for adding the IP address to the context for incoming requests
// this MUST be added to your `app.js` file BEFORE any services have been registered
app.configure(addIP)

// instantiate the service
const auth0Service = new Auth0Service(app)

// register the strategy
auth0Service.register('auth0', new Auth0Strategy())

// register the `/authentication` service with feathers
app.use('/authentication', auth0Service)
```

### Server setup when using `AuthenticationService`

Using the FeathersJS default `AuthenticationService` gives you more control, but requires more configuration. If you choose to use **ONLY** `Auth0Strategy`, your app config (`config/default.json`) will need to look like this (note the addition of a `secret` prop that must be set, but is not used):

```json
{
  "authentication": {
    "auth0": {
      "domain": "example"
    },
    "authStrategies": [
      "auth0"
    ],
    "createIfNotExists": false,
    "entity": "users",
    "entityId": "user_id",
    "secret": "i_am_not_used_but_must_be_set",
    "service": "users"
  }
}
```

And then in your app setup (usually `src/app.js`):

```js
// src/app.js

// import the service, strategy, and hooks
const { AuthenticationService, authenticate } = require('@feathersjs/authentication')
const { Auth0Strategy, fromAuth0 } = require('@morphatic/feathers-auth0-strategy')
const { isProvider, some, unless } = require('feathers-hooks-common')

// instantiate the service
const authService = new AuthenticationService(app)

// register the strategy
authService.register('auth0', new Auth0Strategy())

// register the `/authentication` service with feathers
app.use('/authentication', authService)

// middleware to configure the app to pass IP addresses into the hook
// context (for use with the `fromAuth0()` hook)
const passIPAddress = (req, res, next) => {
  // `x-real-ip` is for when is behind an nginx reverse proxy
  req.feathers.ip = req.headers['x-real-ip'] || req.ip
  // carry on...
  next()
}

// register a "todos" service that uses the middleware
app.use('/todos', passIPAddress)

// configure other services to use it, e.g. the following config
// will require authentication for all external requests that don't
// originate from Auth0 servers
app.service('todos').hooks({
  before: [
    unless(some(isProvider('server'), fromAuth0()), authenticate('auth0'))
  ]
})
```

Additional configuration options are explained below.

### Client setup

From your frontend app, you'll need to configure the standard [`@feathersjs/authentication-client`](https://crow.docs.feathersjs.com/api/authentication/client.html) as follows:

```js
// NOTE: this is almost exactly the same as standard client setup described in the official docs
const feathers = require('@feathersjs/feathers')
const socketio = require('@feathersjs/socketio-client')
const io = require('socket.io-client')
const auth = require('@feathersjs/authentication-client')
const localforage = require('localforage)

const socket = io('http://api.feathersjs.com')
const api = feathers()

// Setup the transport (Rest, Socket, etc.) here
api.configure(socketio(socket))

// Make sure the authentication client is configured to use the `auth0` strategy
api.configure(auth({
  jwtStrategy: 'auth0', // <-- IMPORTANT!!!
  storage: localforage,
  storageKey: 'auth0_token'
}))
```

Depending on your client setup, you'll want to make sure that the authentication client is able to find the access tokens that have been acquired from Auth0. The above example assumes that the tokens are stored in the browser using [`LocalForage`](https://github.com/localForage/localForage) under the `auth0_token` key, but this is entirely dependent upon the specific setup of your app.

#### Client usage example

The key thing to remember here, is that FeathersJS is **NOT** being used to authenticate users in your client app. The authentication process is being handled by Auth0, and will result in an access token being stored in the client app, usually in some place like local storage, a cookie, or using a package like `LocalForage`. FeathersJS does NOT create or issue a JWT (access token) for you, but rather just **verifies that the access token being sent from your app (i.e. the one acquired from Auth0) is valid and unexpired**.

As such, setting up authentication in your client is beyond the scope of this documentation. Refer to [the Auth0 docs](https://auth0.com/docs) for more information on this topic. You just need to make sure that the access tokens that you receive from Auth0 are stored in a place that `@feathersjs/authentication-client` expects to find them (see the config example above).

So, assuming your user has successfully logged in, and a valid access token is stored in the browser somewhere, the following should "just work"™:

```js
// using async/await
const getTodos = async () => {
  let todos = []
  try {
    // if configured correctly, your feathers client should get
    // the access token from where it is stored and automatically
    // send it in the `Authorization` header for the request
    const result = await app.service('todos').find({})
    todos = result.data
  } catch (err) {
    // if the access token was missing or invalid (e.g. expired)
    // an error will be thrown and you need to handle (re)authenticating
    // your client app
  }
  return todos
}

// using promises
app.service('todos').find({})
  .then(
    result => {
      // if configured correctly, your feathers client should get
      // the access token from where it is stored and automatically
      // send it in the `Authorization` header for the request
      const todos = result.data
    }
  )
  .catch(
    err => {
      // if the access token was missing or invalid (e.g. expired)
      // an error will be thrown and you need to handle (re)authenticating
      // your client app
    }
  )
```

## Custom configuration

`Auth0Strategy` and `Auth0Service` allow for a number of additional configuration settings that will be described here. Here is an example of configuration with all options specified:

```json
{
  "authentication": {
    "auth0": {
      "domain": "example",
      "keysService": "keys",
      "whitelist": []
    },
    "authStrategies": ["auth0"],
    "createIfNotExists": false,
    "entity": "user",
    "entityId": "user_id",
    "jwtOptions": {},
    "service": "users"
  }
}
```

First, currently `jwtOptions` is **NOT** configurable in `Auth0Strategy`. The `jwtOptions` are currently hard-coded into the strategy and resolve to:

```js
const jwtOptions = {
  algorithms: ['RS256'],
  audience: [
    `https://${domain}.auth0.com/api/v2/`,
    `https://${domain}.auth0.com/userinfo`
  ],
  ignoreExpiration: false,
  issuer: `https://${domain}.auth0.com/`
}
```

Where `domain` is the `authentication.auth0.domain` property in the config. `domain` is a **REQUIRED** option and an error will be thrown if it is not set. Likewise the JWKS URL (where the package will go to retrieve the signing key) is set to: `https://${domain}.auth0.com/.well-known/jwks.json`. If you use a custom domain with your Auth0 account, you'll have to fork this repo and update these values accordingly. (I may make these options configurable in a future release if this becomes a highly-requested feature.)

### The `keys` service

Under the hood, the `Auth0Strategy` generates an in-memory `keys` service in your app. This is used to store JSON web keys (JWKs) retrieved from [Auth0's JWKS endpoint](https://auth0.com/docs/jwks). This service does not need to be persistent as it is mainly used to cache already-retrieved JWKs and improve performance. Also, although not strictly necessary, since the `keys` service does not contain any non-public information, the `Auth0Strategy` sets up a hook to prevent the `keys` service from being called by external clients. For reference, please see [the JSON Schema version of the `keys` service](https://github.com/morphatic/feathers-auth0-strategy/blob/master/test/key-schema.json) contained in this repo.

In the unlikely event that you already have another service called `keys` in your app, if you'd like to use a different service for storing the keys, replace "keys" in the above `authentication.auth0.keysService` setting for the name you'd like to use for this service.

### The `users` service

`Auth0Strategy` gets the Auth0 `user_id` from the `sub` claim of the decoded JWT access token. By default, when looking up the associated user or entity in your FeathersJS API, it tries to retrieve a `user` from the `users` service using `app.service('users').find({ query: { user_id } })` and returning the first matching result (since the `user_id` should be unique, there should be only a single result).

If you'd like to store your user information in a different service, and/or use a different field for `user_id`, this can be accomplished by updating the `authentication` config. For example, say you call your users "members" and store them in a service with a matching name, you could have a config like:

```json
{
  "authentication": {
    "auth0": {
      "domain": "example",
      "keysService": "keys"
    },
    "authStrategies": ["auth0"],
    "entity": "member",
    "entityId": "member_id",
    "service": "members"
  }
}
```

### The `fromAuth0()` IP address whitelist

This package includes a `fromAuth0()` hook which is designed to allow requests to your API that come from one of [Auth0's published IP addresses](https://auth0.com/docs/guides/ip-whitelist). By default, the list of whitelisted IP addresses is set to the US region. There are several ways to customize the whitelist. From the app config:

```json
{
  "authentication": {
    "auth0": {
      "domain": "example",
      "whitelist": [
        "111.111.111.111",
        "222.222.222.222"
      ]
    },
    "authStrategies": ["auth0"],
    "entity": "member",
    "entityId": "member_id",
    "service": "members"
  }
}
```

You can also update the app config on the fly, e.g.:

```js
// get the current authentication config
const config = app.get('authentication')
// update the auth0.whitelist property
config.auth0.whitelist = ['123.45.67.89']
// update the config with the new values
app.set('authentication', config)
```

And, if you are using the `fromAuth0()` hook directly, you can pass an object with a single `whitelist` property, e.g.:

```js
app.service('todos').hooks({
  before: {
    all: [
      unless(fromAuth0({ whitelist: ['123.45.67.89']}), authenticate('auth0'))
    ]
  }
})
```

To disable the whitelist entirely, just set the value of the `whitelist` property to an empty array, i.e. `[]`.

## FAQ

I don't know if these are technically "frequently-asked", but they are questions...

### Do you provide TypeScript typings

No, not yet. The package is currently written in plain JavaScript. I do plan at some point to update it to use TypeScript, but I can't say for sure when that will be. I know this is not a ton of work. I used to use TypeScript with some frequency, but it's been a while and frankly, the cognitive overhead of brushing up on TypeScript to get this out the door was more than I had bandwidth for at the time I wrote it. :sweat_smile:

### Does `Auth0Strategy` work in conjunction with other strategies

Is it possible for the `Auth0Strategy` to be one of several, e.g. setting `"authStrategies": ["auth0", "jwt", "local"]` in the `authentication` config? To be honest, I haven't tried it, so I don't know. I'd love to get reports from others as to whether it works or not. I _think_ it should work fine, though.

### Why not just store the signing certificate on the server

The signing certificate used with the `RS256` algorithm is a "public key" and as such, is not terribly sensitive. As an alternative to using this package, one could theoretically (i.e. I haven't actually tried this) download the signing key from Auth0 (it's in `Auth0 Website > Dashboard > Applications > Your App > Advanced Settings > Certificates`) and store it on the API (FeathersJS) server, and then use the built-in `JwtStrategy` with the following configuration (or something similar? like I said, I haven't tested this method):

```json
{
  "authentication": {
    "secret": "your signing key",
    "authStrategies": ["jwt"],
    "jwtOptions": {
      "audience": [
        "https://example.auth0.com/api/v2/",
        "https://example.auth0.com/userinfo"
      ],
      "header": {
        "typ": "JWT"
      },
      "issuer": "https://example.auth0.com/",
      "algorithm": "RS256"
    }
  }
}
```

This is probably a perfectly satisfactory way to use `RS256` authentication with your FeathersJS app. However, there are a couple of potential "gotchas" to consider:

1. As [discussed in this Auth0 blog post](https://auth0.com/blog/navigating-rs256-and-jwks/), one of the key goals of using an asymmetric signing algorithm like `RS256` is that you can avoid storing a secret key on multiple servers
2. Signing keys can change over time. Although this is probably a rare event, a not-so-unlikely scenario involves an app maintainer deciding to rotate the signing key. This would, in effect, force all of the users of your app to be logged out, and require them to re-authenticate. In this scenario, the app maintainer would have to remember to download and replace the signing key on the API server whenever it was rotated. This additional step introduces additional points of potential failure, e.g. forgetting to update the server, the signing key is corrupted in transit, etc.
3. The JWKS architecture allows there to be _multiple_ valid signing keys. The `JwtStrategy` only allows you to have a _single_ secret associated with your authentication strategy.

The `Auth0Strategy` addresses and handles each of these points, and is designed to operate according to the standard.

### Why does `Auth0Service` override the `setup()` function

The [FeathersJS docs say explicitly](https://crow.docs.feathersjs.com/api/authentication/service.html#customization):

> When extending `setup`, `super.setup(path, app)` should always be called, otherwise events and real-time connection authentication will no longer work.

If you're the kind of person to dig into source code, you'd find that the `Auth0Service` overrides `setup()` but it does **NOT** call `super.setup(path, app)`. The problem is that the `setup()` function in the default `AuthenticationService` throws an error if the `authentication.secret` property is not set in the app config. Since one of the primary goals of extending the `AuthenticationService` was to avoid having to set `authentication.secret`, it was necessary to override the `setup()` function. However, care has been taken to apply the `connection()` and `events()` hooks that were in the original `setup()` function so that real-time connection authentication will _still_ work as expected. In addition, the `connection()` hook actually has to be initialized `connection('auth0')` so that the correct strategy will be used when authenticating real-time requests.

## Comments, Questions, Issues, etc

I welcome feedback, bug reports, enhancement requests, or reports on your experiences with the plugin. Undoubtedly, there's a better way to do this than what I've come up with, and I'd love to hear about it. That being said, I hope some people will find this useful!!!
