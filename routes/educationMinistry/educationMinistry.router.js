var express = require('express');
var Web3 = require('web3');
var fs = require('fs');
var path = require('path')
var openssl = require('openssl-nodejs');

// session
var passport = require('passport');
var LocalStrategy = require('passport-local');

// config and abi 
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
var personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));

var router = express.Router();
var Mapping = require("../../controllers/mapping.controller")

//fabric SDK and Util
var { Gateway, Wallets} = require('fabric-network');
var { buildCAClient, registerAndEnrollUser, enrollAdmin ,getAdminIdentity , buildCertUser} = require('../../Util/CAUtil.js');
var { buildCCPOrg1, buildWallet } = require('../../Util/AppUtil.js');
var FabricCAServices_1  = require('../../Util/FabricCAService_1.js');


var caClient,wallet;
var gateway,network;

var accInstance,certInstance;
var require_signature =  "EM"

passport.use('EM_local', new LocalStrategy( {
    // Override those field if you don'y need it
    // https://stackoverflow.com/questions/35079795/passport-login-authentication-without-password-field
    usernameField: 'account',
    passwordField: 'signature',
    passReqToCallback: true
},
    async function (req, username, password, done) {
        let account = username.toLowerCase()
        if(req.status == "pass"){
            return done(null,{'identity':account});
        }
    }
));

async function init(){
    //build ca client
    let ccp = buildCCPOrg1();
    caClient = await buildCAClient(FabricCAServices_1, ccp, 'ca.org1.example.com');

    //build wallet to store cert
    let walletPath = path.join(__dirname, '..', '..' ,'wallet','educationMinistry');
    wallet = await buildWallet(Wallets, walletPath);
    
    //enroll ca admin 
    let mspOrg1 = 'Org1MSP';
    await enrollAdmin(caClient, wallet, mspOrg1);

    //register and enroll app admin (need admin attribute)
    await registerAndEnrollUser(caClient, wallet, mspOrg1, 'educatuinMinistry', 'org1.department1' ,null, 'admin');

    //create Gateway to connect to peer
    gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet,
        identity: 'educatuinMinistry',
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
    });
    network = await gateway.getNetwork('mychannel');
    accInstance = network.getContract('accessControl');
    certInstance = network.getContract('cert');
    //let r = await accInstance.evaluateTransaction("GetIdentity")
    //console.log(r.toString())
}
init();

let isAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        return res.redirect("/E-portfolio/educationMinistry/")
    }
};

router.post("/addAttribute", isAuthenticated, async function(req,res){
    //user address to get pubkey 
    console.log(req.user)
    let {account,attribute} = req.body;
    let {identity} = req.user;
    let result = await certInstance.evaluateTransaction('GetState',identity+attribute);

    if(result.toString().length==0){
        req.flash('info', 'Permission denied.');
        return res.redirect('/E-portfolio/educationMinistry/addAttribute');
    }
    let mapping = await Mapping.findOne({'address':account})
    if(!mapping){
        req.flash('info', "User doesn't exist.");
        return res.redirect('/E-portfolio/educationMinistry/addAttribute');
    }
    let pubkey = mapping.pubkey
    try{
        result = await accInstance.submitTransaction('AddAttributeForUser',pubkey, attribute);
        req.flash('info', 'Add Successfully.');
    }
    catch{
        req.flash('info', 'Add failed.');
    }
    
    return res.redirect('/E-portfolio/educationMinistry/addAttribute');
})

router.get("/addAttribute", isAuthenticated, async function(req,res){
    //login successfully
    let activitys = await certInstance.evaluateTransaction('GetState',req.user.identity)
    activitys = activitys.toString()
    activitys = JSON.parse(activitys)
    /*
    activityList = []
    for(let i=0;i<activitys.length;i++){
        let activity = await certInstance.evaluateTransaction('GetState',req.user.identity + activitys[i])
        if(activity){
            activity = JSON.parse(activity.toString())
            activityList.push(activity)
        }
    }*/
    res.render('E-portfolio/educationMinistry/addAttribute.ejs', {'activityList':activitys,'info':req.flash('info'),user:req.user.identity});
})

router.post("/loginWithMetamask",async function(req,res,next){
    let {account,signature} = req.body
    let signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();
    if(signingAccount != account.toLowerCase()){
        return res.send({'msg':'Failed to verify signature'});
    }
    let activityList = await certInstance.evaluateTransaction('GetState',signingAccount)
    activityList = activityList.toString()
    if(activityList.length==0){
        return res.send({"msg":"you don't have right to create reward."})
    }
    req.status = "pass"
    next()
},passport.authenticate('EM_local'),async function(req,res){
    res.send({url: "/E-portfolio/educationMinistry/addAttribute"})
})
router.get("/logout", isAuthenticated, async function(req,res){
    req.logOut();
    res.redirect('/E-portfolio/educationMinistry/');
})
router.get("/",async function(req,res){
    res.render('E-portfolio/educationMinistry/homepage.ejs',{"require_signature":require_signature,})
});

module.exports = router;


