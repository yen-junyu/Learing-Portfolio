var express = require('express');
var Web3 = require('web3');
var fs = require('fs');

var passport = require('passport');
var LocalStrategy = require('passport-local');

var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var identityManger = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));

var router = express.Router();
var require_signature = "0xnycu";


passport.use('verifySign', new LocalStrategy( {
    // Override those field if you don'y need it
    // https://stackoverflow.com/questions/35079795/passport-login-authentication-without-password-field
    usernameField: 'account',
    passwordField: 'signature',
    passReqToCallback: true
},
    async function (req, username, password, done) {
        let account = username.toUpperCase()
        let signature = password;
        try
        {
            let signingAccount = web3.eth.accounts.recover(require_signature, signature).toUpperCase();
        }
        catch
        {
            req.flash('info', 'Failed to verify signature');
            return done(null,false);
        }
        let contractInstance = new web3.eth.Contract(identityManger.abi, contract_address);
        let result = await contractInstance.methods.getId().call({from: account})
        if(result){
            // exist DID 

            // To do list
            // 1.get CSR
            // 2.check CSR ID
            // 3.register and enrollment
            // 4.create access control
            console.log("not empty")
        }
        else{
            req.flash('info', 'DID is not exist');
            return done(null,false);
        }

        /*
        if(signingAccount==account){
            return done(null,{"identity":account});
        }
        else{
            return done(null,false);
        }*/
    }
));

router.get("/",async function(req,res){
    res.render('E-portfolio/highSchool/homepage.ejs',{"require_signature":require_signature,})
});

router.post('/loginWithMetamask', passport.authenticate('verifySign', {
    failureRedirect: '/E-portfolio/highSchool'
}), function (req, res) {
    res.send({'url':'/E-portfolio/highSchool/profile'})
});

module.exports = router;

// Retrieve all Tutorials
//router.get("/", token.findAll);

// Delete a Tutorial with id
//router.delete("/:identity/:org", token.delete);

