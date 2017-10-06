var http = require('http')

var express = require('express')
var validator = require('express-validator')
var cookieSession = require('cookie-session')
var bodyParser = require('body-parser')
var csrf = require('csurf')
var Promise = require('bluebird')

var logger = require('../../util/logger')
var pathutil = require('../../util/pathutil')
var lifecycle = require('../../util/lifecycle')

var session = require('express-session')
var cookieParser = require('cookie-parser')
var dotenv = require('dotenv')
var passport = require('passport')
var Auth0Strategy = require('passport-auth0')
var flash = require('connect-flash')

dotenv.load()

module.exports = function(options) {
  var log = logger.createLogger('auth-mock')
  var app = express()
  var server = Promise.promisifyAll(http.createServer(app))

  lifecycle.observe(function() {
    log.info('Waiting for client connections to end')
    return server.closeAsync()
      .catch(function() {
        // Okay
      })
  })

  // This will configure Passport to use Auth0
  const strategy = new Auth0Strategy(
    {
      domain: options.domain,
      clientID: options.clientId,
      clientSecret: options.clientSecret,
      callbackURL: options.callbackUrl
    },
    function(accessToken, refreshToken, extraParams, profile, done) {
      // accessToken is the token to call Auth0 API (not needed in the most cases)
      // extraParams.id_token has the JSON Web Token
      // profile has all the information from the user
      return done(null, profile)
    }
  )

  passport.use(strategy)

  // you can use this section to keep a smaller payload
  passport.serializeUser(function(user, done) {
    done(null, user)
  })

  passport.deserializeUser(function(user, done) {
    done(null, user)
  })

  app.set('view engine', 'pug')
  app.set('views', pathutil.resource('auth/mock/views'))
  app.set('strict routing', true)
  app.set('case sensitive routing', true)

  app.use(cookieSession({
    name: options.ssid
  , keys: [options.secret]
  }))
  app.use(bodyParser.json())
  app.use(csrf())
  app.use(validator())
  app.use(cookieParser())
  app.use(
    session({
      secret: 'shhhhhhhhh',
      resave: true,
      saveUninitialized: true
    })
  )
  app.use(passport.initialize())
  app.use(passport.session())

  app.use(flash())

  app.use(function(req, res, next) {
    res.locals.loggedIn = req.session.passport && typeof req.session.passport.user != 'undefined'

    function unauthorized(res) {
      return res.redirect('/login')
    }

    if (res.locals.loggedIn) {
      return res.redirect(options.appUrl)
    }
    else {
      return unauthorized(res)
    }
  })

  app.get('/', function(req, res) {
    res.redirect('/auth/auth0/')
  })

  app.get('/auth/auth0/', function(req, res) {
    res.redirect('/auth/auth0/login')
  })

  app.get('/login', passport.authenticate('auth0', {
  clientID: options.clientId,
  domain: options.domain,
  redirectUri: options.callbackUrl,
  responseType: 'code',
  audience: 'https://' + options.domain + '/userinfo',
  scope: 'openid profile'}),
  function(req, res) {
    res.redirect('/')
})

  app.get('/logout', function(req, res) {
    req.logout()
    res.redirect('/')
  })

app.get('/callback',
  passport.authenticate('auth0', {
    failureRedirect: '/failure'
  }),
  function(req, res) {
    res.redirect(req.session.returnTo || options.appUrl)
  }
)

app.get('/failure', function(req, res) {
  var error = req.flash('error')
  var errorDescription = req.flash('error_description')
  req.logout()
  res.render('failure', {
    error: error[0],
    error_description: errorDescription[0],
  })
})

  server.listen(options.port)
  log.info('Listening on port %d', options.port)
}
