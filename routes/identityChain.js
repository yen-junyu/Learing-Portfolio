var express = require('express');
var fs = require('fs');
var Web3 = require('web3');
// ession
var passport = require('passport');
var LocalStrategy = require('passport-local');
// tool
var keccak256 = require('keccak256');
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var identityManger = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
var router = express.Router();

var User = require("../controllers/user.controller");
var Organization = require("../controllers/organization.controller");
// sub-router
var apiUser = require('./identityChain/api.user')
var apiOrganization = require('./identityChain/api.organization')

var IM = new web3.eth.Contract(identityManger.abi, contract_address);
//IM.events.AddUserEvent({fromBlock: 14},function(error, event){ console.log(event)})
//IM.events.BindUserAccountEvent({fromBlock: 0},function(error, event){ console.log(event)})

var isAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        req.flash('info', 'Login first.');
        res.redirect('/identityChain');
    }
};

passport.use('user', new LocalStrategy(
    {
        usernameField: 'userName',
        passwordField: 'IDNumber',
        passReqToCallback: true
    },
    async function(req, userName, IDNumber , done){
        let option = {
            'IDNumber': IDNumber,
            'userName' : userName
        }
        let user = await User.findOne(option);
        if(user){
            return done(null,{"identity":user.hashed,"type":"user"});
        }
        else{
            req.flash('info', 'User is not exist.');
            return done(null,false)
        }
    }
))
passport.use('org', new LocalStrategy(
    {
        usernameField: 'organizationName',
        passwordField: 'uniformNumber',
        passReqToCallback: true
    },
    async function(req, organizationName, uniformNumber , done){
        let option = {
            'organizationName': organizationName,
            'UniformNumbers' : uniformNumber
        }
        let organization = await Organization.findOne(option);
        if(organization){
            return done(null,{"identity":organization.hashed , "type":"org"});
        }
        else{
            req.flash('info', 'User is not exist.');
            return done(null,false)
        }
    }
))
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
        signingAccount = web3.eth.accounts.recover(config.require_signature, signature).toUpperCase();
        if(signingAccount==account){
            return done(null,{"identity":account});
        }
        else{
            return done(null,false);
        }
    }
));
//sub-router (api)
router.use('/api/user',apiUser);
router.use('/api/organization',apiOrganization);

router.post('/addUser',async function(req,res){
    let {type,IDNumber,Name} = req.body;
    let user;
    if(type=="person"){
        let option = {
            'IDNUmber': IDNumber,
            'userName' : Name,
        }
        user = await User.findOne(option);
    }
    else{
        let option = {
            'UniformNumbers': IDNumber,
            'organizationName' : Name,
        }
        user = await Organization.findOne(option);
    }

    
    if(!user){
        return res.send({
            msg: `user ${Name} is not exist.`
        });
    }
    let hashed = user.hashed
    let contractInstance = new web3.eth.Contract(identityManger.abi, contract_address);

    let txHash;
    let signedTxObj;
    let tx_builder = contractInstance.methods.addUser(hashed);
    let encode_tx = tx_builder.encodeABI();
    let transactionObject = {
        gas: 6721975,
        data: encode_tx,
        from: config.admin_address,
        to: contract_address
    }
    await web3.eth.accounts.signTransaction(transactionObject, config.admin_key, async function (error, signedTx) {
        if (error) {
            console.log("sign error");
        } else {
            signedTxObj = signedTx;
        }
    })

    web3.eth.sendSignedTransaction(signedTxObj.rawTransaction)
    .on('receipt',async function (receipt) {
        user.set({
            status: "true",
        });
        await user.save();
        return res.send({
            msg: `${Name}-${receipt.transactionHash}`
        });
    })
    .on('error', function (error) {
        console.log(`Send signed transaction failed.`);
        console.log(error)
        return res.status(500).send({
            msg: "error"
        });
    })
    .catch((error) => {
        console.error(error);
        return res.send({
            msg:error
        })
    })
})
router.post('/bindAccount',isAuthenticated, async function(req,res){
    let {address,IDNumber,pubkey} = req.body;
    let type = req.user.type;
    console.log(pubkey)
    let hashed = req.user.identity;
    
    let user;
    if(type=="org"){
        if(pubkey == undefined)
        {
            console.log(1244)
            return res.send({
                msg: `User is not exist.`
            })
            
        }
        let option = {
            'hashed' : hashed,
        }
        user = await Organization.findOne(option);
        console.log(user)
    }
    else
    {
        let option = {
            'IDNUmber': IDNumber,
            'hashed' : hashed,
        }
        user = await User.findOne(option);
    }
    
    if(!user){
        return res.send({
            msg: `User is not exist.`
        })
    }
    let contractInstance = new web3.eth.Contract(identityManger.abi, contract_address);

    let txHash;
    let signedTxObj;
    let tx_builder = contractInstance.methods.bindAccount(hashed, address);
    let encode_tx = tx_builder.encodeABI();
    let transactionObject = {
        gas: 6721975,
        data: encode_tx,
        from: config.admin_address,
        to: contract_address
    }
    await web3.eth.accounts.signTransaction(transactionObject, config.admin_key, async function (error, signedTx) {
        if (error) {
            console.log("sign error");
        } else {
            signedTxObj = signedTx;
        }
    })

    web3.eth.sendSignedTransaction(signedTxObj.rawTransaction)
    .on('receipt', async function (receipt) {
        user.set({
            address: address,
            pubkey: pubkey
        });
        await user.save();
        return res.send({
            msg: `${IDNumber}-${receipt.transactionHash}`
        });
    })
    .catch((error) => {
        console.log(`Send signed transaction failed.`);
        return res.send({
            msg: "This address already binded."
        })
    })
})
router.get('/profile',isAuthenticated, async function(req,res){
    let option = {
        'hashed': req.user.identity
    }
    let user;
    let portfolioOrg;
    if(req.user.type=="org")
    {
        user = await Organization.findOne(option)
    }
    else{
        user = await User.findOne(option);
        portfolioOrg =  await Organization.findAll({"type":"E-portfolio"})
    }
    res.render('identityChain/profile.ejs',{'user':user ,'type':req.user.type,'portfolioOrg':portfolioOrg, 'contract_address':contract_address });
})
router.post('/loginWithMetamask', passport.authenticate('verifySign', {
    failureRedirect: '/identityChain/loginFail'
}), function (req, res) {
    res.send({'url':'/identityChain/profile'})
});
router.post('/login',passport.authenticate('user',{
    failureRedirect: '/identityChain'
}), async function(req,res){
    res.redirect('/identityChain/profile')
});

router.post('/loginOrg',passport.authenticate('org',{
    failureRedirect: '/identityChain'
}), async function(req,res){
    res.redirect('/identityChain/profile')
})
router.get('/logout', function(req, res) {
    req.logOut();
    res.redirect('/identityChain/');
});

router.get('/audit',isAuthenticated , async function(req,res){
    //let option = {"status":"false"};
    //let users = await User.findAll(option);
    res.render('identityChain/audit.ejs',{'user':true});
})
router.get('/register',async function(req,res){
    res.render('identityChain/register.ejs',{"info":req.flash('info')});
})
router.get('/', async function(req,res){
    if(req.user){
        res.redirect("/identityChain/profile")
    }
    else{
        res.render('identityChain/identityHomePage.ejs',{'require_signature':config.require_signature ,'info':req.flash('info')});
    }
});

module.exports = router;

