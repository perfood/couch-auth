# CouchAuth

![Known Vulnerabilities](https://dev.snyk.io/test/github/sl-nx/superlogin/badge.svg)
![Build Status](https://github.com/perfood/couch-auth/workflows/Build/badge.svg?branch=master)

This is a heavily modified [SuperLogin](https://github.com/colinskow/superlogin), re-written in TypeScript and developed with Node 14/16 & CouchDB 3. It is compatible with Cloudant when using the CouchDB-style authentication, adapted for current OWASP best practises and can be used on [CloudFoundry](https://www.ibm.com/cloud/cloud-foundry).

Important breaking changes, see the [Changelog](https://github.com/perfood/couch-auth/blob/master/CHANGELOG.md) for details:
- `0.17.0`: Replaced `ejs` with `nunjucks`, new templating logic, Node >= 14
- `0.14.0`: Moved db and `sl-users` - structure to UUIDs

Important notes from the maintainer:
- I assume that the express server using `couch-auth` runs behind a load balancer which handles _rate limiting_. Use something like HAProxy which is also [recommended by CouchDB](https://docs.couchdb.org/en/stable/best-practices/reverse-proxies.html#reverse-proxying-with-haproxy) and configure it to prevent brute force attacks.
- I'm only actively working on / testing the `local` email/PW authentication strategy, not for the OAuth part. Feel free to use it and to contribute, but you're on your own.


If you encounter a bug, [open an issue](https://github.com/perfood/couch-auth/issues).
If you have trouble setting things up or any other question about the package, [join the discussion](https://github.com/perfood/couch-auth/discussions) instead.

Check the [Project board](https://github.com/perfood/couch-auth/projects/1) for upcoming changes or if you want to contribute.

## Below is the (partially adjusted) original README:

## Overview

CouchAuth is a full-featured NodeJS/Express user authentication solution for APIs and Single Page Apps (SPA) using
CouchDB or Cloudant.

User authentication is often the hardest part of building any web app, especially if you want to integrate multiple providers. Now all the tough work has been done for you so you can relax and create with less boilerplate!

## Contents

- [Features](#features)
- [Client Tools and Demo](#client-tools-and-demo)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Securing Your Routes](#securing-your-routes)
- [Database Security](#database-security)
- [Email Templates](#email-templates)
- [CouchDB Document Update Validation](#couchdb-document-update-validation)
- [Adding Providers](#adding-providers)
- [Adding additional fields](#adding-additional-fields)
- [Advanced Configuration](#advanced-configuration)
- [Routes](#routes)
- [Event Emitter](#event-emitter)
- [Main API](#main-api)

## Features

- Authentication solution for APIs, sPAs and Offline-First CouchDB powered Apps
- Supports local login with username/email and password using best security practices
- Sends system emails for account confirmation, password reset, or anything else you want to configure
- Add any [Passport](http://passportjs.org) OAuth2 strategy with literally just a couple lines of code
- Link multiple authentication strategies to the same account for user convenience
- Provides seamless token access to both your CouchDB server (or Cloudant) and your private API
- Manages permissions on an unlimited number of private or shared user databases and seeds them with the correct design documents
- Enable slowing down requests to /login on errors to [prevent brute force attacks](#brute-force-protection)

## How It Works

Simply authenticate yourself with CouchAuth using any supported strategy and you will be issued a temporary access token and password. Then include the access token and password in an Authorization Bearer header on every request to access protected endpoints. The same credentials (using Basic rather than Bearer Authorization) will authenticate you on any CouchDB or Cloudant database you have been authorized to use.

## Quick Start

Here's a simple minimalist configuration that will get you up and running right away:

First:

```
npm install @perfood/couch-auth express body-parser morgan
```

You'll need an email service that is supported by [nodemailer](https://nodemailer.com/smtp/). Then start a server with the following content:

```javascript
var express = require('express');
var bodyParser = require('body-parser');
var logger = require('morgan');
var { CouchAuth } = require('@perfood/couch-auth');

var app = express();
app.set('port', process.env.PORT || 3000);
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

var config = {
  dbServer: {
    protocol: 'http://',
    host: 'localhost:5984',
    user: 'admin',
    password: 'password',
    userDB: 'sl-users',
    couchAuthDB: '_users'
  },
  // uncomment this if you want your users to select their own username an login with the username
  // local: {
  //   emailUsername: false, // store the username in the database instead of an auto-generated key
  //   usernameLogin: true, // allow login with username
  // },
  mailer: {
    fromEmail: 'gmail.user@gmail.com',
    options: {
      service: 'Gmail', // N.B.: Gmail won't work out of the box, see https://nodemailer.com/usage/using-gmail/
      auth: {
        user: 'gmail.user@gmail.com',
        pass: 'userpass'
      }
    }
  },
  userDBs: {
    defaultDBs: {
      private: ['supertest']
    }
  }
};

// Initialize CouchAuth
var couchAuth = new CouchAuth(config);

// Mount CouchAuth's routes to our app
app.use('/auth', couchAuth.router);
app.listen(app.get("port"));
```

Enabling login via username instead of via email is only recommended if the usernames are public anyways. 
Otherwise, using email only is more secure and prevents account guessing. Read the [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) for more information.

Now let's create our first user by sending a POST request with the following JSON content to `http://localhost:3000/auth/register`. 
Replace the example E-Mail with one that you can access:

```json
{
  "name": "Joe Smith",
  "email": "joesmith@example.com",
  "password": "bigsecret",
  "confirmPassword": "bigsecret"
}
```

e.g. via `curl`:

```bash
curl --request POST \
  --url http://localhost:3000/auth/register \
  --header 'Content-Type: application/json' \                 
  --data '{"name": "Joe Smith", "email": "joesmith@example.com", "password": "bigsecret", "confirmPassword": "bigsecret"}'
```

Using `x-www-form-urlencoded` is also supported:

```bash
curl --request POST \
  --url http://localhost:3000/auth/register \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'name=Joe Smith' \
  --data-urlencode 'email=joesmith@example.com' \
  --data-urlencode 'password=bigsecret' \
  --data-urlencode 'confirmPassword=bigsecret'
```

You should get the response `{"success": "Request processed."}` and an confirmation E-Mail should have been sent out. 
Click on the confirmation link to activate your account. 
You can also manually confirm the user's email by removing the `unverifiedEmail` - property in his doc in `sl-users` and adding `"email": "joesmith@example.com"` instead.


Now to login, simply post your username and password to `http://localhost:3000/auth/login`. You should get a response similar to this:

```json
{
  "issued": 1440232999594,
  "expires": 1440319399594,
  "provider": "local",
  "token": "aViSVnaDRFKFfdepdXtiEg",
  "password": "p7l9VCNbTbOVeuvEBhYW_A",
  "user_id": "joesmith",
  "roles": ["user"],
  "userDBs": {
    "supertest": "http://aViSVnaDRFKFfdepdXtiEg:p7l9VCNbTbOVeuvEBhYW_A@localhost:5984/supertest$joesmith"
  }
}
```

You have now been issued an access token. Let's use it to access a protected endpoint. 
Make a request to `http://localhost:3000/auth/refresh` and you'll see it was unauthorized. 
Now add a header to your request: `"Authorization": "Bearer {token}:{password}"` and you should see that your session was refreshed. That was easy!

If your user document contains a field called `profile`, this will automatically be included with the session information.

You can also use the same token and password combination to access your personal database. 
But as soon as you log out your session, that access will be revoked.

**Note:** Session tokens for your API will be unusable as soon as they expire. 
However, there is no mechanism to automatically revoke expired credentials with CouchDB. 
Whenever a user logs in, logs out, or refreshes the session, CouchAuth will automatically clean up any expired credentials for that user. 
But you **have to** periodically run `couchAuth.removeExpiredKeys()`, e.g. with `setInterval` or a cron job. This will deauthorize every single expired credential.

## Securing Your Routes

Securing your routes is very simple:

```js
app.get(
  '/admin',
  couchAuth.requireAuth,
  couchAuth.requireRole('admin'),
  function (req, res) {
    res.send('Welcome Admin');
  }
);
```

Note that you must use `requireAuth` prior to checking any roles or an error will be thrown.

##### `couchAuth.requireAuth`

Middleware that authenticates a user with a token and password in the request header. (`"Authorization": "Bearer {token}:{password}"`)

##### `couchAuth.requireRole(role)`

Middleware that makes sure the authenticated user possesses the specified `role` (string).

##### `couchAuth.requireAnyRole(possibleRoles)`

Middleware that makes sure the user possesses at least one of the specified `possibleRoles` (array).

##### `couchAuth.requireAllRoles(requiredRoles)`

Middleware that makes sure the user possesses ALL of the specified `requiredRoles` (array).

## Database Security

When using CouchDB, you should block anonymous reads across all databases by setting `require_valid_user` to `true` under `[couch_httpd_auth]` in your CouchDB config.

For CouchDB versions `< 3`, Admin Party is default and all your databases are readable and writable by the public until you implement the correct security measures. 

CouchAuth also allows you to specify default `_security` roles for members and admins in the `userDBs` section of your config file. See `config.example.js` for details.

## Email templates

[Nunjucks](https://mozilla.github.io/nunjucks/) is used for the email and oauth callback templates. The defaults in the `templates` folder. Set `emailTemplates.folder` accordingly when providing your own templates. For each `template` defined in `emailTemplates.templates`, you have two options of including it with `couch-auth` by placing it into `emailTemplates.folder`:

1. Provide a `${template}.html.njk` and/or `${template}.text.njk` file
2. Provide a `base.njk` HTML template and a `${template}.njk` file containing the text

When using option 2), you'll have pretty HTML emails with little maintenance overhead:
- Use line breaks to start new paragraphs
- Use `*..*` or `_..._`, `**...**`, `[desc](url)` for basic markdown styling

The `base.njk` needs to contain a block like this for every paragraph that will be rendered into it:

```                                                                                                  
{% block content %} 
 {% for paragraph in paragraphs %}
   <p>{{paragraph | safe}}</p> 
 {% endfor %}
{% endblock %}
```

Be sure to _never_ use `safe` for data that is passed via `req` inside your nunjucks templates!

You can pass additional data for all templates via `emailTemplates.data` or for a single template via its `data` entry. It will be available in nunjucks as `data. ...`. The `${template}` is available under `templateId`.

Support for `ejs` has been dropped with version `0.17.0`.
## CouchDB Document Update Validation

CouchDB provides the [validate_doc_update function](http://guide.couchdb.org/draft/validation.html) to approve or disapprove what gets written. However, since your CouchDB users are temporary random API keys, you have no idea which user is requesting to write. CouchAuth has inserted the original `user_id` into `userCtx.roles[0]`, prefixed by `user:` (e.g. `user:superman`).


## Adding Providers

You can add support for any Passport OAuth2 strategy to CouchAuth with just a few lines of code. _Maintainers Note: haven't tested this._

#### Configuration

The first step is to add credentials to your config file. You can skip the callback URL as it will be generated automatically. Here is how to add support for Dropbox:

```js
providers: {
  dropbox: {
    // Credentials here will be passed in on the call to passport.use
    credentials: {
      consumerKey: DROPBOX_APP_KEY,
      consumerSecret: DROPBOX_APP_SECRET
    },
    options: {
      // Options here will be passed in on the call to passport.authenticate
    },
    // You should copy the template from this repo that is in `templates/oauth/authCallback.njk` and modify the second parameter
    // from '*' to your page origin, e.g. 'https://example.com', to avoid any malicious site receiving the auth data returned by the pop-up
    // window workflow. The template can be the same for all providers.
    template: path.join(__dirname, './templates/oauth/my-custom-secure-authCallback.njk')
  }
}
```

CouchAuth supports two types of workflows for OAuth2 providers: popup window and client access token.

#### Popup Window Workflow for web browsers (desktop and mobile)

Your client must create a popup window and point it to `/{provider}`, where the user will be directed to authenticate with that provider. After authentication, succeeds or fails, it will [post a message](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) to the parent window with the data set to `{error, session, link }`.

In the parent window add an event listener to wait for the message, e.g:

```js
window.addEventListener('message', (event) => {
  if (event.origin !== "http://auth.example.org:3000") { return; }
  // event.data on success contains
  // {
  //   "error": null,
  //   "session": {
  //     "issued": 1624591356009,
  //     "expires": 1624677756009,
  //     "provider": "google",
  //     ...
  //   },
  //   "link": null
  // }
  console.log(event);
  
}, false);
```

After completing the configuration step above, all you have to do is register your new provider with CouchAuth. Simply follow this pattern:

```js
var DropboxStrategy = require('passport-dropbox-oauth2').Strategy;
couchAuth.registerOAuth2('dropbox', DroboxStrategy);
```
Now, assuming your credentials are valid, you should be able to authenticate with Dropbox by opening a popup window to `/dropbox`. See below in the Routes documentation for more detail.

#### Client Access Token for Cordova / Phonegap and Native Apps

Cordova and most native app frameworks (including iOS and Android) have plugins which authenticate a user with a provider and provide an `access_token` to the client app. All you have to do is post a request to `/{provider}/token` and include your `access_token` in the request body. CouchAuth will respond with a new session or an error message.

You must use Passport strategies that accept `access_token` posted in the body of the request, such as `passport-facebook-token`, `passport-google-token`, etc.

Here is how to setup the Client Access Token strategy:

```js
var FacebookTokenStrategy = require('passport-facebook-token');
couchAuth.registerTokenProvider('facebook', FacebookTokenStrategy);
```

Note that this uses the exact settings in your config as the popup window workflow.

## Adding additional fields

It's easy to add custom fields to user documents. When added to a `profile` field it will automatically be included with the session information (in a profile object).

1. First whitelist the fields in the [config](https://github.com/perfood/couch-auth/blob/master/config.example.js), for example:

   ```js
   userModel: {
     whitelist: ['profile.fullname'];
   }
   ```

2. Include the fields with [registrations](#post-register).
3. To also fill in custom fields after social authentications use the `onCreate` handler. Example:

   ```js
   couchAuth.onCreate(function (userDoc, provider) {
     if (userDoc.profile === undefined) {
       userDoc.profile = {};
     }
     if (provider !== 'local') {
       const displayName = userDoc[provider].profile.displayName;
       if (displayName) {
         userDoc.profile.fullname = displayName;
       }
     }
     return Promise.resolve(userDoc);
   });
   ```

## Brute force protection

To enable brute force protection for the `/login` route you just need to add `loginRateLimit: {}` to `security` in your `config`. The same goes for the `/password-reset` route, where you just need to add `passwordResetRateLimit: {}` accordingly. Adding just the empty object uses following defaults that can be overriden as needed:

```ts
const config {

  ...

  security: {
    
    ...

    loginRateLimit: {
      windowMs: 5 * 60 * 1000,
      delayAfter: 3,
      delayMs: 500
      maxDelayMs: 10000,
      skipSuccessfulRequests: true,
      skipFailedRequests: false,
      onLimitReached: function () {},
      store: undefined, // if undefined uses Memory Store by default
      headers: false
    }
  }
}
```

couch-auth uses [express-slow-down](https://www.npmjs.com/package/express-slow-down) under the hood, feel free to check the docs to dig deeper into configuration options.

### Important notes:
- You won't be able to override the keyGenerator option, as we use usernameField from the config.
- When activating rate limiting for the `/password-reset` route, `username` field is required in the request body!
- If you want to use Redis Store instead of Memory Store you currently need to use [rate-limit-redis@2x](https://github.com/wyattjoh/rate-limit-redis/tree/v2.1.0) for now [due to known issues](https://github.com/express-rate-limit/express-slow-down/issues/40#issuecomment-1548011953) with newer versions of rate-limit-redis.

## Advanced Configuration

Take a look at `config.example.js` or `src/types/config.d.ts` for a complete tour of all available configuration options. You'll find a lot of cool hidden features there that aren't documented here.

`src/config/default.config.ts` contains a list of default settings that will be assumed if you don't specify anything.

## Routes

##### `POST /register`

Creates a new account with a username and password. Required fields are: 
`username`, `email`, `password` and `confirmPassword`. `name` is optional. 
Any additional fields you want to include need to be white listed under 
`userModel` in your config. See `src/config/default.config.ts`, 
`config.example.js` or `src/types/config.d.ts` for details.

If `local.sendConfirmEmail` is true (_recommended_), a confirmation email will 
be sent with a verification link. If `local.requireEmailConfirm` is true, 
(_recommended_) the user will not be able to login until the confirmation is 
complete. If `security.loginOnRegistration` is true (_discouraged_), a session will 
be automatically created and sent as the response. If `local.keepEmailConfirmToken` 
is `true`, the confirmation link will also return `200` if the link
is opened multiple times.

##### `POST /login`

Include `username` and `password` fields to authenticate and initiate a session. 
The field names can be customized in your config under `local.usernameField` 
and `local.passwordField`.

##### `GET /confirm-email/{token}`

This link is included in the confirmation email, and will mark the user as 
confirmed. If `local.confirmEmailRedirectURL` is specified in your config, it 
will redirect to that location with `?success=true` if successful or 
`error={error}&message={msg}` if it failed. Otherwise it will generate a 
standard JSON response.

##### `POST /refresh`

Authentication token required. Extends the life of your current token and 
returns updated token information. The only field that will change is `expires`.
Token life is configurable under `security.sessionLife` and is measured in 
seconds.

##### `POST /logout`

Authentication required. Logs out the current session and deauthorizes the token
on all user databases.

##### `POST /logout-others`

Authentication required. Logs out and deauthorizes all user sessions except the 
current one.

##### `POST /logout-all`

Authentication required. Logs out every session the user has open and 
deauthorizes the user completely on all databases.

##### `POST /forgot-password`

Include `email` field to send the forgot password email containing a password 
reset token. The life of the token can be set under `security.tokenLife` (in 
seconds).

Have the email template redirect back to you're app where you're app presents 
U.I. to gather a new password and then `POST` to `/password-reset` with the 
forgot-password `token` and new password

##### `POST /password-reset`

Resets the password. Required fields: `token`, `password`, and `confirmPassword`.

##### `POST /password-change`

Authentication required. Changes the user's password or creates one if it doesn't exist. Required fields: `newPassword`, and `confirmPassword`. If the user already has a password set then `currentPassword` is required.

##### `GET /validate-username/{username}` (_deprecated_)

**Deprecated**

Checks a username to make sure it is correctly formed and not already in use. Responds with status 200 if successful, or status 409 if unsuccessful.

##### `GET /validate-email/{email}` (_deprecated_)

**Deprecated**

Checks an email to make sure it is valid and not already in use. Responds with status 200 if successful, or status 409 if unsuccessful.

##### `POST /change-email`

Authentication required. Changes the user's email. Required field: `newEmail`.

If `requirePasswordOnEmailChange` is `true`: The `username` (can also be email)
and `password` are also required.

Note: The server returns an answer once the email has been verified as valid and
whether this email already exists in the DB, not waiting for the update of the 
email to complete.

##### `GET /session`

**Deprecated**. Simply attempt to access the (user's) CouchDB `/` instead.

Returns information on the current session if it is valid. Otherwise you will get a 401 unauthorized response.
With 2.0, this route shouldn't be used anymore but is still present for backwards compatibility. You should handle session expiration dates on client side, simply try to connect with the Database and handle 401/403 responses accordingly.

##### `POST /request-deletion`

Authentication required. A valid login (i.e. email, username or UUId) must be 
provided as `username` and the current `password`.
Removes the user's account and all its private databases.
##### `GET /{provider}`

Open this in a popup window to initiate authentication with Facebook, Google, etc. After authentication, the callback will [post a message to the the parent window](#popup-window-workflow-for-web-browsers-desktop-and-mobile) with the data object: `error` explains anything that went wrong, `session` includes the same session object that is generated by `/login` and `link` simply contains the name of the provider that was successfully linked.

##### `GET /link/{provider}?bearer_token={token:password}`

This popup window is opened by a user that is already authenticated in order to link additional providers to the account.

There is a security concern here that the session token is exposed as a query parameter in the URL. While this is secure from interception under HTTPS, it can be stored in the user's browser history and your server logs. If you are concerned about this you can either force your user to log out the session after linking an account, or disable link functionality completely by setting `security.disableLinkAccounts` to `true`.

##### `POST /unlink/{provider}`

Authentication required. Removes the specified provider from the user's account. Local cannot be removed. If there is only one provider left it will fail.

##### `POST /{provider}/token`

This will invoke the client `access_token` strategy for the specified provider if you have registered it. You should include the `access_token` for the provider in the body of your request.

##### `POST /link/{provider}/token`

This will link additional providers to an already authenticated user using the client `access_token` strategy.

## Event Emitter

CouchAuth also provides an [event emitter](https://nodejs.org/api/events.html), which allows you to receive notifications when important things happen.

**Example:**

```js
couchAuth.emitter.on('login', function (userDoc, provider) {
  console.log('User: ' + userDoc._id + ' logged in with ' + provider);
});
```

Here is a full list of the events that CouchAuth emits, and parameters provided:

- `signup`: (`userDoc`, `provider`)
- `signup-attempt`: (`userDoc`, `provider`) // currently only for local
- `link-social`: (`userDoc`, `provider`)
- `login`: (`newSession`, `provider`)
- `refresh`: (`newSession`)
- `password-reset`: (`userDoc`)
- `password-change`: (`userDoc`)
- `forgot-password`: (`userDoc`)
- `forgot-password-attempt`: (`email`)
- `email-verified`: (`userDoc`)
- `email-changed`: (`userDoc`)
- `illegal-email-change`: (`login`, `newEmail`)
- `user-db-added`: (`dbName`)
- `user-db-removed`: (`dbName`)
- `user-deleted`: (`userDoc`, `reason`)
- `logout`: (`user_id`)
- `logout-all`: (`user_id`)
- `consents`: (`userDoc`)

## Main API

##### `new CouchAuth(config, couchServer, passport)`

Constructs a new instance of CouchAuth. All arguments are optional. If you don't supply any config object, default settings will be used for a local CouchDB instance in admin party mode. Emails will be logged to the console but not sent.

- `config`: Your full configuration object.
- `couchServer`: You can pass a `ServerScope` from `@cloudant/cloudant` or your own customized version of `nano` here to make the requests to your CouchDB/Cloudant-instance. Typing issues can be ignored as long as the relevant methods work as in `nano`. If you don't pass a `ServerScope`, your installed `nano`-Version must be `>=9`.
- `passport`: You can pass in your own instance of Passport or CouchAuth will generate one if you do not.

**Returns:** the complete CouchAuth API.

##### `couchAuth.config`

A reference to the configuration object. You can use this to lookup and change configuration settings at runtime. See `src/types/config.d.ts` for details.

##### `couchAuth.router`

A reference to the Express Router that contains all of CouchAuth's routes.

##### `couchAuth.passport`

A reference to Passport

#### `couchAuth.events`

A reference to the event emitter

##### `couchAuth.userDB`

A `nano` instance that gives direct access to the CouchAuth users database

##### `couchAuth.couchAuthDB`

A `nano` instance that gives direct access to the CouchDB authentication (`_users`) database.

##### `couchAuth.registerProvider(provider, configFunction)`

Adds support for additional Passport strategies. See below under Adding Providers for more information.

##### `couchAuth.validateUsername(username)`

Checks that a username is valid and not in use. Resolves with nothing if successful. Resolves with an error object in failed.

##### `couchAuth.validateEmail(email)`

Checks that an email is valid and not in use. Resolves with nothing if successful. Resolves with an error object in failed.

##### `couchAuth.getUser(login)`

Fetches a user document by either username, email or UUID.

##### `couchAuth.createUser(form, req)`

Creates a new local user with a username and password.

`form` requires the following: `username`, `email`, `password`, and `confirmPassword`. `name` is optional. Any additional fields must be whitelisted in your config under `userModel` or they will be removed.

`req` should contain `protocol` and `headers.host` to properly generate the confirmation email link. `ip` will be logged if given.

##### `couchAuth.onCreate(fn)`

Use this to add as many functions as you want to transform the new user document before it is saved. Your function should accept two arguments `(userDoc, provider)` and return a `Promise` that resolves to the modified user document. onCreate functions will be chained in the order they were added.

##### `couchAuth.onLink(fn)`

Does the same thing as `onCreate`, but is called every time a user links a new provider, or their profile information is refreshed. This allows you to process profile information and, for example, create a master profile. If an object called `profile` exists inside the user doc it will be passed to the client along with session information at each login.

##### `couchAuth.createUserSocial(provider, auth, profile)`

Creates a new user following authentication from an OAuth provider. If the user already exists it will update the profile.

- `provider`: the name of the provider in lowercase, (e.g. 'facebook')
- `auth`: credentials supplied by the provider
- `profile`: the profile supplied by the provider

##### `couchAuth.linkUserSocial(login, provider, auth, profile)`

like `createUserSocial`, but for an existing user identified by `login`

##### `couchAuth.unlinkUserSocial(login, provider)`

Removes the specified provider from the user's account.
`local` cannot be removed. If there is only one provider left it will fail.
##### `couchAuth.hashPassword(password)`

Hashes a password using PBKDF2 and returns an object containing `salt` and `derived_key`.

##### `couchAuth.verifyPassword(hashObj, password)`

Verifies a password using a hash object. If you have a user doc, pass in `local` as the hash object.

##### `couchAuth.createSession(params)`

Creates a new session for a user. 

params has the properties:
- `login`: username, email or UUID - if supported by your config
- `provider`: the name of the provider. (eg. `'local'`, `'facebook'`, `'twitter'`.)
- `sessionType`: Optional. See `security` -> `sessionConfig` for details. Allows a dynamic session length by role.
- `byUUID`: Optional. Allows to identify a user by UUID, even if login via UUID is not allowed in your config


##### `couchAuth.changePassword(user_id, password)`

Changes the user's password.

##### `couchAuth.forgotPassword(email, req)`

Sends out the forgot password email and issues a reset token.

##### `couchAuth.resetPassword(form, req)`

Resets the user's password. Required fields are `token` (from the forgot password email), `password`, and `confirmPassword`.

##### `couchAuth.changeEmail(user_id, newEmail)`

Changes the user's email. If email verification is enabled (`local.sendConfirmEmail`) then a new confirmation email will be sent out.

##### `couchAuth.verifyEmail(token, req)`

Marks the user's email as verified. `token` comes from the confirmation email.

##### `couchAuth.addUserDB(user_id, dbName, type, designDoc, permissions, partitioned)`

Associates a new database with the user's account. Will also authenticate all existing sessions with the new database.

- `dbName`: the name of the database. For a shared db, this is the actual path. For a private db `userDBs.privatePrefix` will be prepended, and `${user_id}` appended. **(required)**
- `type`: 'private' (default) or 'shared' (optional)
- `designDoc`: the name of the designDoc (if any) that will be seeded. (optional)
- `permissions`: an array of [permissions](https://docs.cloudant.com/authorization.html) for use with Cloudant. (optional)
- `partitioned`: `false` (default) or `true` if the database should be [partitioned](https://docs.couchdb.org/en/stable/api/partitioned-dbs.html)
 
If the optional fields are not specified they will be taken from `userDBs.model.{dbName}` or `userDBs.model._default` in your config.

##### `couchAuth.removeUserDB(user_id, dbName, deletePrivate, deleteShared)`

Deauthorizes the specified database from the user's account, and optionally destroys it.

- `dbName`: the full path for a shared db, or the base name for a private db
- `deletePrivate`: when `true`, will destroy a db if it is marked as private
- `deleteShared`: when `true`, will destroy a db if it is marked as shared. Caution: may destroy other users' data!

##### `couchAuth.logoutUser(user_id, session_id)`

Logs out all of a user's sessions at once. If `user_id` is not specified CouchAuth will look it up from the `session_id`.

##### `couchAuth.logoutSession(session_id)`

Logs out the specified session.

##### `couchAuth.logoutOthers(session_id)`

Logs out all of a user's sessions, except for the one specified.

##### `couchAuth.logoutAll(login, session_id)`

Logs out all of a user's sessions. Retrieves the user by `login` or `session_id`
##### `couchAuth.removeUser(user_id, destroyDBs)`

Deletes a user, deauthorizes all the sessions, and optionally destroys all private databases if `destroyDBs` is true.

##### `couchAuth.confirmSession(token, password)`

Verifies a user's session.

##### `couchAuth.removeExpiredKeys()`

Deauthorizes every single expired session found in the user database.

##### `couchAuth.sendEmail(templateName, email, locals)`

Renders an email and sends it out. Server settings are specified under `mailer` in your config.

- `templateName`: the name of a template object specified under `emails` in your config. See [here](#email-templates) for details.
- `email`: the email address that the email
- `locals`: local variables that will be passed into the nunjucks template to be rendered

