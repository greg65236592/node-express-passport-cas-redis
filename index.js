var express = require('express');
var passport = require('passport');
var Strategy = require('passport-cas').Strategy;

const SSO_BASE_URL = 'http://cas.server.com';
const SSO_LOGOUT_URL = 'http://cas.server.com/logout';
const SERVER_RETURN_URL = 'http://localhost:3000';

passport.use(new (Strategy)({
    ssoBaseURL: SSO_BASE_URL,
    serverBaseURL: SERVER_RETURN_URL
}, function (login, done) {
    console.log('LOGIN DONE, user: ' + login);
    return done(null, login);
}));

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.
passport.serializeUser(function (user, cb) {
    cb(null, user);
});

passport.deserializeUser(function (id, cb) {
    cb(null, id);
});

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
// express session
var session = require('express-session');
// redis session
var RedisStore = require('connect-redis')(session);
// use redis session
app.use(session({
    store: new RedisStore({
        host: "localhost",
        port: 6379
    }),
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());


// Cas Authentication Middleware
/**
 * 
 * @param {Express.Request} req 
 * @param {*} res 
 * @param {*} next 
 */
function authenticationMiddleware(req, res, next) {
    console.log('in authenticationMiddleware');
    // GET: '/cas_login'
    passport.authenticate('cas', function (err, user, info) {
        if (err) {
            console.log('auth failed, err: ' + err);
            return res.redirect('/failed');
        }

        if (!user) {
            console.log('auth failed, no user, err: ' + err);
            req.session.messages = info.message;
            return res.redirect('/failed');
        }

        req.logIn(user, function (err) {
            if (err) {
                return next(err);
            }

            req.session.messages = 'good auth time: ' + new Date();
            return next();
        });
    })(req, res, next);
}

// Define routes.
app.get('/', authenticationMiddleware,
    function (req, res) {
        res.redirect('/success');
    });

app.get('/logout',
    function (req, res) {
        req.session.destroy();
        req.logout();
        res.redirect(SSO_LOGOUT_URL); // single logout!
    });

app.get('/success',
    function (req, res) {
        res.session.testAttr1 = 'Hello, I am succeed.'
        res.render('success', { user: req.user });
    });

app.get('/failed',
    function (req, res) {
        res.session.testAttr1 = 'Hello, I am failed.'
        res.render('failed');
    });

app.listen(3000);