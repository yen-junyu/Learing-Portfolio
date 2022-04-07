var express = require('express');
var Web3 = require('web3');
var fs = require('fs');
var path = require('path')

// session
var passport = require('passport');
var LocalStrategy = require('passport-local');

// config and abi 
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var em_address = config.org_info.education.address.toLowerCase()
var identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
var personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));

var router = express.Router();
var Mapping = require("../../controllers/mapping.controller");
const db = require("./../../models");
const Reviewer = db.reviewer;

let tls = require('tls');
let net = require('net');

//fabric SDK and Util
var { Gateway, Wallets} = require('fabric-network');
var { buildCAClient, registerAndEnrollUser, enrollAdmin ,getAdminIdentity , buildCertUser} = require('../../Util/CAUtil.js');
var { buildCCPOrg1, buildWallet } = require('../../Util/AppUtil.js');
var FabricCAServices_1  = require('../../Util/FabricCAService_1.js');

var color = require("colors")
var caClient,wallet;
var certInstance , awardInstance ,accInstance;
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
        let user = {'identity':account}
        if(account == em_address){
            user['admin'] = true;
        }
        else{
            user['admin'] = false;
        }
        return done(null,user);
    }
));

async function init(){
    //build ca client
    let ccp = buildCCPOrg1();
    caClient = await buildCAClient(FabricCAServices_1, ccp, 'ca.org1.example.com');

    //build wallet to store cert
    let walletPath = path.join(__dirname, '..', '..' ,'wallet','educationMinistry') 
    wallet = await buildWallet(Wallets, walletPath);
   
    //enroll ca admin 
    let mspOrg1 = 'Org1MSP';
    await enrollAdmin(caClient, wallet, mspOrg1);

    /*
    //register and enroll university 
    let universityWalletPath = path.join(__dirname, '..', '..' ,'wallet','university');
    universityWallet = await buildWallet(Wallets, universityWalletPath);
    const adminIdentity = await wallet.get('admin');
    const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
	const adminUser = await provider.getUserContext(adminIdentity, 'admin');

    const secret = await caClient.register({
        affiliation: 'org1.department1',
        enrollmentID: 'University',
        role: 'client',
        attrs: [ {'name': 'role' , 'value': 'reviewer' ,'ecert':true }],
    }, adminUser);

    const enrollment = await caClient.enroll({
        enrollmentID: 'University',
        enrollmentSecret: secret
    });
    const x509Identity = {
        credentials: {
            certificate: enrollment.certificate,
            privateKey: enrollment.key.toBytes(),
        },
        mspId: mspOrg1,
        type: 'X.509',
    };
    await universityWallet.put('University', x509Identity);
    */
    //register and enroll app admin (need admin attribute)
    await registerAndEnrollUser(caClient, wallet, mspOrg1, 'educatuinMinistry', 'org1.department1' ,null, 'admin');
    

    //create Gateway to connect to peer
    gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet,
        identity: 'educatuinMinistry',
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
    });

    let certChannel = await gateway.getNetwork('cert-channel');
    certInstance =  await certChannel.getContract('certManager');
    awardInstance = await certChannel.getContract('issueAward');

    let accChannel = await gateway.getNetwork('acc-channel');
    accInstance = await accChannel.getContract('AccessControlManager');
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
    let {admin} = req.user
    if(admin){
        next();
    }
    else{
        return res.redirect("/E-portfolio/educationMinistry/")
    }
}
function getPubkey(certificate){
    let secureContext = tls.createSecureContext({
        cert: certificate
    });
    let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
    let cert = secureSocket.getCertificate();
    publicKey = cert.pubkey.toString('hex');

    return publicKey
}
router.post("/loginWithMetamask",async function(req,res,next){
    let {account,signature} = req.body
    let signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();
    if(signingAccount != account.toLowerCase()){
        return res.send({'msg':'Failed to verify signature'});
    }
    //不用登入直接申請 簽個名表身份
    next()
},passport.authenticate('EM_local'),async function(req,res){
    let url;
    if(req.user.admin){
        url = "/E-portfolio/educationMinistry/addReviewer"
    }
    else{
        url = "/E-portfolio/educationMinistry/getCert"
    }
    res.send({url:url})
})
router.get("/logout", isAuthenticated, async function(req,res){
    req.logOut();
    res.redirect('/E-portfolio/educationMinistry/');
})
router.get("/getCert", isAuthenticated ,async function(req,res){
    let {identity} = req.user;
    let filePath = `./wallet/educationMinistry/${identity}.id`
    console.log(filePath)
    try {
        if (fs.existsSync(filePath)) {
            console.log("exist")
            res.download(filePath)
        }
        else{
            res.json({error:"your x509certificate dose't exist."})
        }
    }
    catch(err) {
        res.json({error:"error x509certificate dose't exist."})
    }
})
router.post("/addReviewer",isAuthenticated, isAdmin , async function(req,res){
    let {reviewerName, address} = req.body
    let pubkey;
    if(!reviewerName || !address){
        return res.json({msg:"reviewerName or address is empty."})
    }
    address = address.toLowerCase()
    try{
        let mspOrg1 = 'Org1MSP';
        const adminIdentity = await wallet.get('admin');
        const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
        const adminUser = await provider.getUserContext(adminIdentity, 'admin');

        const secret = await caClient.register({
            affiliation: 'org1.department1',
            enrollmentID: address,
            role: 'client',
            attrs: [ {'name': 'role' , 'value': 'reviewer' ,'ecert':true }],
        }, adminUser);

        const enrollment = await caClient.enroll({
            enrollmentID: address,
            enrollmentSecret: secret
        });
        const x509Identity = {
            credentials: {
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
            },
            mspId: mspOrg1,
            type: 'X.509',
        };
        pubkey = getPubkey(x509Identity.credentials.certificate)
        await wallet.put(address,x509Identity);
        Reviewer.create({
            reviewerName: reviewerName,
            address : address,
            pubkey: pubkey
        })
    }
    catch(e){
        return res.json({msg:`${address} is already registered.`})
    }

    try{
        await certInstance.submitTransaction("addReviewer", reviewerName, pubkey);
        return res.json({msg:"successfully"})
    }
    catch(e){
        console.log(e);
        return res.json({msg:`addReviewer error.`})
    }
})
router.get("/addReviewer", isAuthenticated, isAdmin, async function(req,res){
    let {identity, admin} = req.user;
    let reviewers = await certInstance.evaluateTransaction("getReviewer");
    reviewers = JSON.parse(reviewers.toString())
    
    reviewers.forEach(function(object, index, array){
        console.log(object.value)
        let value = JSON.parse(object.value)
        array[index] = value;
    });
    return res.render('E-portfolio/educationMinistry/addReviewer.ejs',{admin: admin, user:identity ,reviewers:reviewers})
})
router.get("/",async function(req,res){
    res.render('E-portfolio/educationMinistry/homepage.ejs',{"require_signature":require_signature})
});

module.exports = router;


