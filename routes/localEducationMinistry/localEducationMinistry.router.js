var express = require('express');
var Web3 = require('web3');
var fs = require('fs');
var path = require('path')

// session
var passport = require('passport');
var LocalStrategy = require('passport-local');

// controller
var ApplyCert = require("../../controllers/applyCert.controller");

// config and abi 
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var localEducationMinistry_address = config.org_address.localEducationMinistry;
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
var gateway,network,certInstance;
var require_signature = "LEM"

passport.use('LEM_local', new LocalStrategy( {
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
    // initial some object

    //build ca client
    let ccp = buildCCPOrg1();
    caClient = await buildCAClient(FabricCAServices_1, ccp, 'ca.org1.example.com');

    //build wallet to store cert
    let walletPath = path.join(__dirname, '..', '..' ,'wallet','localEducatuinMinistry');

    wallet = await buildWallet(Wallets, walletPath);
    
    //enroll ca admin 
    let mspOrg1 = 'Org1MSP';
    await enrollAdmin(caClient, wallet, mspOrg1);

    //get ca admin to register and enroll user
    //adminUser = await getAdminIdentity(caClient,wallet)

    //register and enroll app admin (need admin attribute)
    await registerAndEnrollUser(caClient, wallet, mspOrg1, 'localEducatuinMinistry', 'org1.department1' ,null, 'admin');

    //create Gateway to connect to peer
    gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet,
        identity: 'localEducatuinMinistry',
        discovery: { enabled: true, asLocalhost: true }, // using asLocalhost as this gateway is using a fabric network deployed locally
        
    });
    network = await gateway.getNetwork('mychannel');
    certInstance = await network.getContract('cert');
    
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
let isAdmin = function (req ,res, next){
    let {identity} = req.user
    console.log(identity)
    if(identity==localEducationMinistry_address){
        next();
    }
    else{
        return res.redirect("/E-portfolio/localEducationMinistry/")
    }
}


router.post("/loginWithMetamask",async function(req,res,next){
    let {account,signature} = req.body
    let signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();
    if(signingAccount != account.toLowerCase()){
        return res.send({'msg':'Failed to verify signature'});
    }
    // Check this account is org 
        
    // =========================
    req.status = "pass"
    next()
},passport.authenticate('LEM_local'),async function(req,res){
    res.send({url: "/E-portfolio/localEducationMinistry/applyCert"})
})
router.post("/applyCert",isAuthenticated, async function(req,res){
    const {activityName,type,number,API} = req.body
    let applycert = {
        account : req.user.identity,
        activityName : activityName,
        type: type,
        number: number,
        API: API
    }
    try{
        applycert = await ApplyCert.create(applycert)
        req.flash('info', 'Apply successfully.');
    }
    catch(message){
        console.log(message)
        req.flash('info', 'Apply incorrectly.');
    }
    res.redirect('/E-portfolio/localEducationMinistry/applyCert/');
})
router.get("/applyCert",isAuthenticated, async function(req,res){
    let admin;
    let {identity} = req.user
    if(identity == localEducationMinistry_address){
        admin = true
    }
    res.render('E-portfolio/localEducationMinistry/applyCert.ejs',{require_signature,'info':req.flash('info'), admin: admin, user: req.user})
})
router.post("/consentCert", isAuthenticated, isAdmin, async function(req,res){
    let {organization,activityName} = req.body;
    let applycert = await ApplyCert.findOne({activityName:activityName})
    console.log(applycert)
    if(applycert){
        try{
            let result = await certInstance.submitTransaction('applyIssueCert',applycert.account,applycert.activityName,applycert.type,applycert.number,applycert.API);
            await ApplyCert.update({"activityName":activityName});
            //result = await certInstance.evaluateTransaction('GetState',applycert.account)
            //console.log(result.toString())
            res.send({"msg":"Successfully."})
        }
        catch(e){
            console.log(e)
            res.send({"msg":"Error."})
        }
    }
    else
    {
        res.send({"msg":"activity Name is not exist."})
    }
})
router.get("/consentCert",isAuthenticated,isAdmin, async function(req,res){
    let applyCerts = await ApplyCert.findAll()
    res.render('E-portfolio/localEducationMinistry/consentCert.ejs',{'info':req.flash('info'),'applyCerts':applyCerts,admin:true,user:req.user })
})
router.get("/",async function(req,res){
    res.render('E-portfolio/localEducationMinistry/homepage.ejs',{"require_signature":require_signature,})
});
router.get('/logout', function(req, res) {
    req.logOut();
    res.redirect('/E-portfolio/localEducationMinistry/');
});

module.exports = router;


