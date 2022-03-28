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
var { buildCCPOrg3, buildWallet } = require('../../Util/AppUtil.js');
var FabricCAServices_1  = require('../../Util/FabricCAService_1.js');
const e = require('express');

var caClient,wallet;
var gateway,certChannel,certInstance,awardInstance;

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
    let ccp = buildCCPOrg3();
    caClient = await buildCAClient(FabricCAServices_1, ccp, 'ca.org3.example.com');

    //build wallet to store cert
    let walletPath = path.join(__dirname, '..', '..' ,'wallet','localEducatuinMinistry');
    wallet = await buildWallet(Wallets, walletPath);
    
    //enroll ca admin 
    let mspOrg3 = 'Org3MSP';
    await enrollAdmin(caClient, wallet, mspOrg3);

    //register and enroll app admin (need admin attribute)
    await registerAndEnrollUser(caClient, wallet, mspOrg3, 'TaipeiDepartmentofEducation', 'org1.department1' ,null, 'admin');

    //create Gateway to connect to peer
    gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet,
        identity: 'TaipeiDepartmentofEducation',
        discovery: { enabled: true, asLocalhost: true }, // using asLocalhost as this gateway is using a fabric network deployed locally
        
    });
    certChannel = await gateway.getNetwork('cert-channel');
    certInstance = await certChannel.getContract('certManager');
    certInstance = certChannel.getContract('certManager');
    awardInstance = certChannel.getContract('issueAward');
}
init();

let isAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        return res.redirect("/E-portfolio/localEducationMinistry/")
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
router.post("/addAttribute", isAuthenticated, async function(req,res){
    
    let {userAddress, attribute} = req.body;
    console.log(userAddress)
    let {identity} = req.user;

    //confirm identity has right to addAttribute
    let responseBuffer = await certInstance.evaluateTransaction('get', identity + attribute);
    let response = JSON.parse(responseBuffer.toString())
    let activityInfo;

    if(response.success){
        activityInfo = JSON.parse(response.success)
        console.log(activityInfo)
    }
    else
    {
        req.flash('info', 'Permission denied.');
        return res.redirect('/E-portfolio/localEducationMinistry/addAttribute');
    }
    
    //execute AddAttributeForUser
    try{ 
        let resultBuffer = await awardInstance.submitTransaction('IssueAwardForUser', identity, attribute, userAddress);
        let result = JSON.parse(resultBuffer.toString());
        console.log(result)
        req.flash('info', 'Add Successfully.');
    }
    catch(e){
        console.log(e)
        req.flash('info', 'Add failed.');
    }

    return res.redirect('/E-portfolio/localEducationMinistry/addAttribute');
})
router.get("/addAttribute", isAuthenticated, async function(req,res){
    
    let activitys
    let responseBuffer = await certInstance.evaluateTransaction('get',req.user.identity)
    let response = JSON.parse(responseBuffer.toString())

    if(response.success){
        activitys = JSON.parse(response.success)
    }
    console.log(activitys)
    res.render('E-portfolio/localEducationMinistry/addAttribute.ejs',{'activityList':activitys,'info':req.flash('info'),'user':req.user.identity});
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
router.post("/consentCert", isAuthenticated, isAdmin, async function(req, res){
    let {organization,activityName} = req.body;
    let applycert = await ApplyCert.findOne({activityName:activityName})

    if(applycert){
        try{
            let result = await certInstance.submitTransaction('applyIssueCert', applycert.account, applycert.activityName, applycert.type, applycert.number, applycert.API);
            console.log(result.toString())
            await ApplyCert.update(
                {"activityName": activityName},
                {"status": "true"}
            );
            //result = await certInstance.evaluateTransaction('GetState',applycert.account)
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
router.get("/consentCert",isAuthenticated, isAdmin, async function(req, res){
    let applyCerts = await ApplyCert.findAll()
    res.render('E-portfolio/localEducationMinistry/consentCert.ejs',{'info':req.flash('info'),'applyCerts':applyCerts,admin:true,user:req.user })
})
router.get("/", async function(req,res){
    res.render('E-portfolio/localEducationMinistry/homepage.ejs',{"require_signature":require_signature,})
});
router.get('/logout', function(req, res) {
    req.logOut();
    res.redirect('/E-portfolio/localEducationMinistry/');
});

module.exports = router;


