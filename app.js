var express = require('express');
var bodyParser = require('body-parser');
var path = require('path');
//about session
var passport = require('passport');
var session = require('express-session');
var flash = require("connect-flash");

//router
//var test = require('./routes/test')

var identityChain = require('./routes/identityChain')
var e_portfolio = require('./routes/E-portfolio')

//const { Contract } = require('fabric-contract-api');
//const { Gateway,Wallets, Api } = require('fabric-network');


const db = require("./models");

// If you don't want to drop, leave empty.
db.sequelize.sync();

/*
db.sequelize.sync({ force: true }).then( () => {
    console.log('\x1b[36m%s\x1b[0m', 'Drop and re-sync db.');  //cyan
});*/


var app = express();

app.use(session({
    secret:'secret',
    saveUninitialized: true,
    resave: true
}))
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

passport.serializeUser(function(user, done) {
    done(null, user);
});
passport.deserializeUser(function(user, done) {
    done(null, user);
});

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname,'public')));
app.use('/contracts', express.static(__dirname + '/contracts/identityChain/'));
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

//app.use('/', test);
//app.use('/externalCert',externalCert);
app.use('/identityChain',identityChain);
app.use('/E-portfolio',e_portfolio)



module.exports = app;