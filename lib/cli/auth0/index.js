module.exports.command = 'auth0'

module.exports.describe = 'Start an Auth0 auth unit.'

module.exports.builder = function(yargs) {
  return yargs
    .env('STF_AUTH_AUTH0')
    .strict()
    .option('app-url', {
      alias: 'a'
    , describe: 'URL to the app unit.'
    , type: 'string'
    , demand: true
    })
    .option('client-id', {
      describe: 'auth0 client id.'
    , type: 'string'
    , default: process.env.AUTH0_DOMAIN
    })
    .option('domain', {
      describe: 'auth0 domain.'
    , type: 'string'
    , default: process.env.AUTH0_DOMAIN
    })
    .option('client-secret', {
      describe: 'auth0 client secret.'
    , type: 'string'
    , default: process.env.AUTH0_CLIENT_SECRET
    })
    .option('callback-url', {
      describe: 'LDAP search DN.'
    , type: 'string'
    , default: process.env.AUTH0_CALLBACK_URL || 'http://localhost:3000/callback'
    })
    .epilog('?.')
}

module.exports.handler = function(argv) {
  return require('../../units/auth/auth0')({
  appUrl: argv.appUrl,
  clientId: argv.clientId,
  domain: argv.domain,
  clientSecret: argv.clientSecret,
  callbackUrl: argv.callbackUrl
  })
}
