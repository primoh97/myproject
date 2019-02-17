/**
 * Module dependencies.
 */
const express = require('express');
const compression = require('compression');
const session = require('express-session');
const bodyParser = require('body-parser');
const logger = require('morgan');
const chalk = require('chalk');
const errorHandler = require('errorhandler');
const lusca = require('lusca');
const dotenv = require('dotenv');
const MongoStore = require('connect-mongo')(session);
const flash = require('express-flash');
const path = require('path');
const mongoose = require('mongoose');
const passport = require('passport');
const expressValidator = require('express-validator');
const expressStatusMonitor = require('express-status-monitor');
const sass = require('node-sass-middleware');
const multer = require('multer');

const upload = multer({ dest: path.join(__dirname, 'uploads') });

/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.load({ path: '.env.example' });

/**
 * Controllers (route handlers).
 */
const homeController = require('./controllers/home');
const userController = require('./controllers/user');
const apiController = require('./controllers/api');
const contactController = require('./controllers/contact');

/**
 * API keys and Passport configuration.
 */
const passportConfig = require('./config/passport');

/**
 * Create Express server.
 */
const app = express();

/**
 * Connect to MongoDB.
 */
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useNewUrlParser', true);
mongoose.connect(process.env.MONGODB_URI);
mongoose.connection.on('error', (err) => {
  console.error(err);
  console.log('%s MongoDB connection error. Please make sure MongoDB is running.', chalk.red('✗'));
  process.exit();
});

/**
 * Express configuration.
 */
app.set('host', process.env.OPENSHIFT_NODEJS_IP || '0.0.0.0');
app.set('port', process.env.PORT || process.env.OPENSHIFT_NODEJS_PORT || 8080);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.use(expressStatusMonitor());
app.use(compression());
app.use(sass({
  src: path.join(__dirname, 'public'),
  dest: path.join(__dirname, 'public')
}));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressValidator());
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: process.env.SESSION_SECRET,
  cookie: { maxAge: 1209600000 }, // two weeks in milliseconds
  store: new MongoStore({
    url: process.env.MONGODB_URI,
    autoReconnect: true,
  })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use((req, res, next) => {
  if (req.path === '/api/upload') {
    next();
  } else {
    lusca.csrf()(req, res, next);
  }
});
app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.xssProtection(true));
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});
app.use((req, res, next) => {
  // After successful login, redirect back to the intended page
  if (!req.user
    && req.path !== '/login'
    && req.path !== '/signup'
    && !req.path.match(/^\/auth/)
    && !req.path.match(/\./)) {
    req.session.returnTo = req.originalUrl;
  } else if (req.user
    && (req.path === '/account' || req.path.match(/^\/api/))) {
    req.session.returnTo = req.originalUrl;
  }
  next();
});
app.use('/', express.static(path.join(__dirname, 'public'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/popper.js/dist/umd'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/js'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/jquery/dist'), { maxAge: 31557600000 }));
app.use('/webfonts', express.static(path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free/webfonts'), { maxAge: 31557600000 }));

/**
 * Primary app routes.
 */
app.get('/', homeController.index);
app.get('/editorial', homeController.editorial);
app.get('/login', userController.getLogin);
app.post('/login', userController.postLogin);
app.get('/logout', userController.logout);
app.get('/forgot', userController.getForgot);
app.post('/forgot', userController.postForgot);
app.get('/reset/:token', userController.getReset);
app.post('/reset/:token', userController.postReset);
app.get('/signup', userController.getSignup);
app.post('/signup', userController.postSignup);
app.get('/contact', contactController.getContact);
app.post('/contact', contactController.postContact);
app.get('/account', passportConfig.isAuthenticated, userController.getAccount);
app.post('/account/profile', passportConfig.isAuthenticated, userController.postUpdateProfile);
app.post('/account/password', passportConfig.isAuthenticated, userController.postUpdatePassword);
app.post('/account/delete', passportConfig.isAuthenticated, userController.postDeleteAccount);
app.get('/account/unlink/:provider', passportConfig.isAuthenticated, userController.getOauthUnlink);

/**
 * API examples routes.
 */
app.get('/api', apiController.getApi);
app.get('/api/lastfm', apiController.getLastfm);
app.get('/api/nyt', apiController.getNewYorkTimes);
app.get('/api/aviary', apiController.getAviary);
app.get('/api/steam', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getSteam);
app.get('/api/stripe', apiController.getStripe);
app.post('/api/stripe', apiController.postStripe);
app.get('/api/scraping', apiController.getScraping);
app.get('/api/twilio', apiController.getTwilio);
app.post('/api/twilio', apiController.postTwilio);
app.get('/api/clockwork', apiController.getClockwork);
app.post('/api/clockwork', apiController.postClockwork);
app.get('/api/foursquare', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getFoursquare);
app.get('/api/tumblr', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getTumblr);
app.get('/api/facebook', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getFacebook);
app.get('/api/github', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getGithub);
app.get('/api/twitter', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getTwitter);
app.post('/api/twitter', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.postTwitter);
app.get('/api/linkedin', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getLinkedin);
app.get('/api/instagram', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getInstagram);
app.get('/api/paypal', apiController.getPayPal);
app.get('/api/paypal/success', apiController.getPayPalSuccess);
app.get('/api/paypal/cancel', apiController.getPayPalCancel);
app.get('/api/lob', apiController.getLob);
app.get('/api/upload', apiController.getFileUpload);
app.post('/api/upload', upload.single('myFile'), apiController.postFileUpload);
app.get('/api/pinterest', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getPinterest);
app.post('/api/pinterest', passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.postPinterest);
app.get('/api/google-maps', apiController.getGoogleMaps);

/**
 * OAuth authentication routes. (Sign in)
 */
app.get('/auth/instagram', passport.authenticate('instagram'));
app.get('/auth/instagram/callback', passport.authenticate('instagram', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/snapchat', passport.authenticate('snapchat'));
app.get('/auth/snapchat/callback', passport.authenticate('snapchat', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'public_profile'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/github', passport.authenticate('github'));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/google', passport.authenticate('google', { scope: 'profile email' }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/twitter', passport.authenticate('twitter'));
app.get('/auth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/linkedin', passport.authenticate('linkedin', { state: 'SOME STATE' }));
app.get('/auth/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/login' }), (req, res) => {
  res.redirect(req.session.returnTo || '/');
});

/**
 * OAuth authorization routes. (API examples)
 */
app.get('/auth/foursquare', passport.authorize('foursquare'));
app.get('/auth/foursquare/callback', passport.authorize('foursquare', { failureRedirect: '/api' }), (req, res) => {
  res.redirect('/api/foursquare');
});
app.get('/auth/tumblr', passport.authorize('tumblr'));
app.get('/auth/tumblr/callback', passport.authorize('tumblr', { failureRedirect: '/api' }), (req, res) => {
  res.redirect('/api/tumblr');
});
app.get('/auth/steam', passport.authorize('openid', { state: 'SOME STATE' }));
app.get('/auth/steam/callback', passport.authorize('openid', { failureRedirect: '/api' }), (req, res) => {
  res.redirect(req.session.returnTo);
});
app.get('/auth/pinterest', passport.authorize('pinterest', { scope: 'read_public write_public' }));
app.get('/auth/pinterest/callback', passport.authorize('pinterest', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/api/pinterest');
});
var forms = require('forms');
var fields = forms.fields;
var validators = forms.validators;

var bcrypt = require('bcrypt');

ar login_form = forms.create({
  username: fields.string({required: true}),
  password: fields.password({required: true}),
});

var replyform = forms.create({
  content: fields.string({required: true, widget: forms.widgets.textarea()})
});

var newtopicform = forms.create({
  subject: fields.string({required: true}),
  content: fields.string({required: true, widget: forms.widgets.textarea()})
});

var registrationForm = forms.create({
  username: fields.string({required: true, validators: [
    validators.maxlength(20),
    validateUsernameFree
  ]}),
  password: fields.password({required: true}),
  confirm: fields.password({
    required: true,
    validators: [validators.matchField('password')]
  })
});

function validateUsernameFree(form, field, callback) {
  db.get('SELECT * FROM user WHERE username = ?', field.data, 
         function (err, row) {
    if (row !== undefined) {
      callback('Username already taken.');
    } else {
      callback();
    }
  });
}

// View helpers

app.helpers({
  formattime: function (time) {
    var seconds = timestamp() - time;
    var minutes = Math.floor(seconds / 60);
    var hours = Math.floor(minutes / 60);
    var days = Math.floor(hours / 24);
    if (days > 1) { return days + ' days ago'; }
    else if (days === 1) { return '1 day ago'; }
    else if (hours > 1) { return hours + ' hours ago'; }
    else if (hours === 1) { return '1 hour ago'; }
    else if (minutes > 1) { return minutes + ' minutes ago'; }
    else if (minutes === 1) { return '1 minute ago'; }
    else if (seconds > 1) { return seconds + ' seconds ago'; }
    else { return '1 second ago'; }
  }
});

app.dynamicHelpers({
  is_logged_in: function (req, res) {
    return (req.session.username !== undefined);
  },
  username: function (req, res) {
    return req.session.username;
  },
  flashes: function (req, res) {
    var f = req.flash();
    var msgs = [];
    if (f.error) {
      for (i = 0; i < f.error.length; i++) { msgs.push(f.error[i]); }
    }
    if (f.info) {
      for (i = 0; i < f.info.length; i++) { msgs.push(f.info[i]); }
    }
    return msgs;
  }
});

// Route helpers

function timestamp() {
  var n = new Date();
  return Math.round(n.getTime() / 1000);
}

// posts reply and calls callback(topic_id)
function postReply(topic_id, content, username, callback) {
  db.run('INSERT INTO reply (topic_id, time, content, author) values \
         (?, ?, ?, ?);', topic_id, timestamp(), content, username, 
         function (err) {
    callback(topic_id);
  });
}

// posts topic and calls callback(topic_id)
function postTopic(subject, content, username, callback) {
  db.run('INSERT INTO topic (subject) values (?)', subject, function (err) {
    db.get('SELECT last_insert_rowid()', function (err, row) {
      postReply(row['last_insert_rowid()'], content, username, callback);
    });
  });
}

// wrap a route function with this to cause 403 error if not logged in
function require_login(callback) {
  return function (req, res) {
    if (req.session.username === undefined) {
      res.send('Login required', 403);
    } else {
      callback(req, res);
    }
  };
}

app.get('/', function (req, res) {
  //TODO: some better SQL could make this a lot simpler
  db.all('SELECT * FROM topic ORDER BY (SELECT MAX(time) FROM reply WHERE \
         reply.topic_id = topic.topic_id) DESC', {}, function (err, rows) {
    function get_reply_count(num, callback) {
      db.get('SELECT count(*) FROM reply WHERE topic_id = ?', 
             rows[num].topic_id, function (err, row) {
        rows[num].replies = row['count(*)'] - 1;
        callback();
      });
    }
    for_loop(rows.length, get_reply_count, function () {
      function get_last_reply_date(num, callback) {
        db.get('SELECT time FROM reply WHERE topic_id = ? ORDER BY time DESC \
               LIMIT 1', rows[num].topic_id, function (err, row) {
          rows[num].last_reply_date = row.time;
          callback();
        });
      }
      for_loop(rows.length, get_last_reply_date, function () {
        res.render('topics', { topics: rows });
      });
    });
  });
});

app.get('/topic/new', function (req, res) {
  res.render('newtopic', { form: newtopicform.toHTML() });
});

app.post('/topic/new', require_login(function (req, res) {
  newtopicform.handle(req, {
    success: function (form) {
      // post topic
      postTopic(form.data.subject, form.data.content, 
                req.session.username, function (topic_id) {
        req.flash('info', 'New topic posted.');
        res.redirect('/topic/' + topic_id);
      });
    },
    other: function (form) {
      res.render('newtopic', { form: form.toHTML() });
    }
  });
}));

app.get('/topic/:topic_id', topic);

app.post('/topic/:topic_id', require_login(topic));

function topic (req, res) {
  var topic_id = req.params.topic_id;
  db.get('SELECT subject FROM topic WHERE topic_id = ?', topic_id, 
         function (err, row) {
    if (row === undefined) {
      res.send(404);
    } else {
      replyform.handle(req, {
        success: function (form) {
          postReply(topic_id, form.data.content, req.session.username,
                    function () {
            req.flash('info', 'Reply posted.');
            render(replyform);
          });
        },
        other: function (form) {
          // only show form errors if form was submitted
          if (req.method === 'GET') {
            render(replyform);
          } else {
            render(form);
          }
        }
      });
    }
    function render (form) {
      db.all('SELECT * FROM reply WHERE topic_id = ? ORDER BY time', topic_id, 
          function(err, rows){
        res.render('topic', {
          subject: row.subject,
          replies: rows,
          form: form.toHTML()
        });
      });
    }
  });
}

app.get('/login', function (req, res) {
  res.render('login', { form: login_form.toHTML() });
});

app.post('/login', function (req, res) {
  login_form.handle(req, {
    success: function (form) {
      var username = form.data.username;
      var password = form.data.password;
      db.get('SELECT password_hash FROM user WHERE username = ?', username,
             function (err, row) {
        if (row === undefined) {
          // user does not exist
          req.flash('error', 'Incorrect username or password.');
          res.render('login', { form: form.toHTML() });
        } else {
          bcrypt.compare(password, row.password_hash, function (err, success) {
            if (success) {
              // success
              req.session.username = username;
              req.flash('info', 'Login successful.');
              res.redirect('/');
            } else {
              // password incorrect
              req.flash('error', 'Incorrect username or password.');
              res.render('login', { form: form.toHTML() });
            }
          });
        }
      });
    },
    other: function (form) {
      res.render('login', { form: form.toHTML() });
    }
  });
});

app.post('/logout', function (req, res) {
  delete req.session.username;
  req.flash('info', 'You have been logged out.');
  res.redirect('/');
});

app.get('/register', function (req, res) {
  res.render('register', { form: registrationForm.toHTML() });
});

app.post('/register', function (req, res) {
  registrationForm.handle(req, {
    success: function (form) {
      bcrypt.gen_salt(12, function (err, salt) {
        bcrypt.encrypt(form.data.password, salt, function (err, hash) {
          db.run('INSERT INTO user (username, password_hash) values (?, ?)', 
                 form.data.username, hash, function (err) {
            req.flash('info', 'Account created. Login to continue.');
            res.redirect('/login');
          });
        });
      });
    },
    other: function (form) {
      res.render('register', { form: form.toHTML() });
    }
  });
});

app.listen(3000);
console.log("Express server listening on port %d", app.address().port);


/**
 * Error Handler.
 */
if (process.env.NODE_ENV === 'development') {
  // only use in development
  app.use(errorHandler());
} else {
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send('Server Error');
  });
}

/**
 * Start Express server.
 
app.listen(app.get('port'), () => {
  console.log('%s App is running at http://localhost:%d in %s mode', chalk.green('✓'), app.get('port'), app.get('env'));
  console.log('  Press CTRL-C to stop\n');
});*/
module.exports = app;

