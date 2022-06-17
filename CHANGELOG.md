## Change Log

#### 0.17.X: ejs -> nunjucks

##### 0.17.1: Invalid token rejection

- Reject with `{status: 401, message: 'invalid token'}` instead of just a string in `confirmSession`
##### 0.17.0: Replace ejs with nunjucks

- :boom: Email templates now use [Nunjucks](https://mozilla.github.io/nunjucks/) instead of EJS
  - A `confirmEmailChange` in addition to `confirmEmail` is now required, the fallback to `confirmEmail` was removed.
  - `req` is available in all mails sent out by couch-auth
  - Support for `pool` when passing SMTP config
- :sparkles: Simplified template management with base HTML templates + some markdown features. Look into `templates/email` and the REAMDE to see how it works.
  - TLDR: you need a `base.njk` which includes a block like this:
  ```
  {% block content %}
    {% for paragraph in paragraphs %}
      <p>{{paragraph | safe}}</p>
    {% endfor %}
  {% endblock %}
  ```
- :goal_net: add option for exponential backoff if sending a mail failed
- :bug: `logout-others` is added to `activityLog` and event emitter
  - :construction: document the currently used session, when available
- :zap: Session keys for each user are documented in `inactiveSessions` and re-used if available when logging in

##### 0.16.2
- :bug: Fix password auth with special characters

##### 0.16.1
- :sparkles: Add support for partinioned databases
- :lock: Update `follow-redirects`

##### 0.16.0: Remove Cloudant

- Core API optionally accepts a `ServerScope` as second argument, but no longer the auth- and user-DB.
  - This way, you can still use IAM by passing the `couchServer` returned by `@cloudant/cloudant` to `superlogin-next`
  - `passport` is now the 3rd optional argument.
- Uses `nano` instead of `@cloudant/cloudant` to connect with CouchDB
##### 0.15.0: Prevent name guessing while email not confirmed

- `login` will only return a generic response if the email is not yet verified.
- renamed a few methods of the API, e.g. `unlink` to `unlinkSocial`
- dependency updates, docs and better usage within TypeScript projects
#### 0.14.X: UUID based schema, more OWASP compliance

##### 0.14.3 OAuth, UUID, types

- OAuth works again now
- `user_uid` is added to entries in `_users` - DB
- All types are emmitted now
##### 0.14.3 Consents Handling

 :sparkles: Introduced handling of consents
    
This allows to optionally specifiy consents with `minVersion`, `currentVersion` and `required` in the config.
- On signup, it is verified whether all `required` consents are accepted with a valid version.
- Retrieve current consents via `GET /consents`
- Update via `POST /consents` -> It's not possible to revoke `required` consents or to update unsupported versions
##### 0.14.2 Bugfix
`auth/register` returned OK even if there are validation errors other than an existing email.
##### 0.14.1 Bugfix
An optional config entry was required to successfully launch the server.

##### 0.14.0: Initial release

The schema for the database IDs has been migrated to UUIDs, these changes to `sl-user` - doc schema must be **manually migrated**:

- previous `_id` in `sl-users` is now the field `key`
- no more PII in document or DB-IDs: a uuid is used for the personal DBs and as `_id` in `sl-users`

Further changes to the `sl-users`:
- IP addresses are no longer saved in the `sl-users` docs
- `lockedUntil` has been removed
- `activityLog` keys have slightly modified and match the emitted events, check the `UserAction`-type in `src/types/typings.d.ts`.
- if `emailUsername` is active, a random `key` is generated instead of being extracted from the email

Changes to the API:

- `change-email` now resolves with `200: change requested`
-`superlogin.emitter` must be used to listen to events, e.g. `superlogin.emitter.on('signup', () => {..})`
instead of listening directly on `superlogin`.
- added `request-deletion` - route (enabled by default).

No external session cache is used anymore:

- removed `redis` and the other adapters
- marked `session` as deprecated: It simply checks whether the entry in `_users` exists. You should handle this by checking the connection to CouchDB instead.

Cloudant legacy auth via API-Keys is no longer supported. Use `couchAuthOnCloudant` instead.

Adjustments to config options, see `src/config/default.config.ts` for the new defaults and `src/types/config.d.ts` for all available options.
- made the defaults more secure
- more than 10 hashing iterations (`security.iterations`)
- disabling of routes (`security.disabledRoutes`)  
- prevent name guessing via `forgot-password`, `register`, `change-email` and `login`
  - only fully available if `requireEmailConfirm` and `emailUsername` are `true`

And fixed a lot of bugs...

#### 0.13.X: Cloudant IAM
##### 0.13.4: Upgrades, email bug

Also lowercasing mails on change-email
##### 0.13.0: Cloudant

Use Cloudant Library for compatibility with IAM auth instead of `user:password` (downgraded nano)

- Added 2x retry when working with cloudant
- Using CookieAuth if `cloudant` is true and not IAM

#### Bugfix forgot-password (0.12.1)

Reject early if no valid email was provided with the request

#### Error Handling (0.12.0)

Only send errors as response that are meant to be user-facing

- Otherwise, just send a generic error
- Adjusted the logging accordingly (warn/error level)

#### TypeScript improvements, Dependency cleanup (0.11.0)

**Breaking**
Compile target is now ES2019, requiring NodeJS 12 or above.

#### Refactoring to TypeScript and Nano (0.10.0)

**Breaking**
Replaced PouchDB with Nano. A PouchDB can no longer be passed to SuperLogin. a Nano-DB can be used instead.

- Made deauthorization behaviour more robust against network failures. `logout` now also resolves if access token has only been removed from `_user`.
- Cloudant and Oauth should work as expected now. Let me know if it does.
- More modules refactored to classes, moved refactored `pouchdb-seed-design` inside this project.

#### Adjusted Email handling (0.9.0)

- If password is reset, email will be marked as confirmed and `"'verified via password reset'"` will be logged.
- new config options:
  - `local.requirePasswordOnEmailChange`: If true, the correct `password` is needed in the request body in order to change the email.
  - `email.confirmEmailChange`: If set, this template is used when requesting an email change and `local.confirmEmail` is active.
  - `/change-email` now responds with `"email change requested"` if the email needs to be confirmed

#### Refactoring, notify on password change, CouchDB as Fallback (0.8.0)

- eslint/prettier for code linting/formatting
- refactored Mailer and User into classes
- provider is now also stored in the doc in CouchDB's `_user` - DB
- new config options:
  - `local.sendPasswordChangedEmail`: if true, send a notification email when password is changed
  - `session.dbFallback`: if true, CouchDB will be checked as a fallback if the adapter does not have that session stored
- Travis CI to Node 12, Node 10 no longer supported due to private fields

#### Updates and Adjustments: SuperloginX (0.7.1)

- Removal of Bluebird in favour of native Promises
- Adjustment of Travis CI for NodeJS 10 with ES6
- Updating all packages to more secure versions
- not allowing `_` as prefix for userDBs
- Updated E-Mail Regex
- Added two custom options to config (shorter PW-reset token, sending UUID with session info)

#### Misc. Bug Fixes (0.6.1) 2016-04-02

- Misc bugfixes
- Documentation improvements
- Now testing against Node 4.x and 5.x

##### Improved Tests, Enhancements, Bugfixes (0.6.0) 2016-04-02

- Updated dependencies
- Improved unit tests (thanks [@tohagan](https://github.com/tohagan) and [@ybian](https://github.com/ybian))
- CouchDB server can now have a separate URL for public access
- Misc bug fixes

##### Enable Logout of Expired Sessions (0.5.0) 2015-10-08

Previously a user could only logout if the session token was still valid. API keys would be expired, but database credentials could still be used. Now logout will ensure the user is completely logged out, even if the session is already expired. Also fixed a bug that was causing `sessionLife` and `tokenLife` settings not to work.

##### Custom Permissions for Cloudant (0.4.0) 2015-09-21

Default per-DB Cloudant permissions no longer save in the user doc. You can set custom permissions in the user doc, otherwise it will use the settings in your config. Misc bug fixes.

##### Security Roles For CouchDB (0.3.0) 2015-09-18

Created configuration options to setup \_security roles when user databases are created. Improved tests and updated PouchDB.

##### Client Access Token Strategies (0.2.0) 2015-09-13

Added client `access_token` strategies to support OAuth2 flows from Cordova, PhoneGap, and native apps.

##### Initial Release (0.1.0) 2015-09-10

The intense power of SuperLogin is unleashed on a world that may not be ready! Tested with Node.js 0.12.7 and 4.0.0.
