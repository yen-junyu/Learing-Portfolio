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
//controller
var Mapping = require("../../controllers/mapping.controller")
var router = express.Router();

//fabric SDK and Util
var fabric_common = require("fabric-common");
var { Gateway, Wallets} = require('fabric-network');
var { buildCAClient, registerAndEnrollUser, enrollAdmin ,getAdminIdentity , buildCertUser} = require('../../Util/CAUtil.js');
var { buildCCPOrg1, buildWallet } = require('../../Util/AppUtil.js');
var FabricCAServices_1  = require('../../Util/FabricCAService_1.js');

//ecdsa
const elliptic = require('elliptic');
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);

//hash function
var cryptoSuite = fabric_common.Utils.newCryptoSuite()
var hashFunction = cryptoSuite.hash.bind(cryptoSuite)


//global variable 
var require_signature = "0xnycu";
var caClient,wallet,adminUser;
var gateway,network;
var accInstance;
var addAttribte = {};




const preventMalleability = (sig, ecdsa) => {
    const halfOrder = ecdsa.n.shrn(1);
    if (sig.s.cmp(halfOrder) === 1) {
        const bigNum = ecdsa.n;
        sig.s = bigNum.sub(sig.s);
    }
    return sig;
};

async function init(){
    // initial some object

    //build ca client
    let ccp = buildCCPOrg1();
    caClient = await buildCAClient(FabricCAServices_1, ccp, 'ca.org1.example.com');

    //build wallet to store cert
    let walletPath = path.join(__dirname, '..', '..' ,'wallet','highSchool');
    wallet = await buildWallet(Wallets, walletPath);
    
    //enroll ca admin 
    let mspOrg1 = 'Org1MSP';
    await enrollAdmin(caClient, wallet, mspOrg1);
    //get ca admin to register and enroll user
    adminUser = await getAdminIdentity(caClient,wallet)

    //register and enroll app admin (need admin attribute)
    await registerAndEnrollUser(caClient, wallet, mspOrg1, 'appAdmin', 'org1.department1' ,null, 'admin');

    //create Gateway to connect to peer
    gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet,
        identity: 'appAdmin',
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
    });
    network = await gateway.getNetwork('mychannel');
    accInstance = network.getContract('accessControl');
}
init();

let isAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        return res.redirect("/E-portfolio/highSchool/")
    }
};
async function opensslDecode(buffer_input){
    return new Promise(function(reslove,reject){
        openssl(['req', '-text','-in', { name:'key.csr',buffer:buffer_input } ,'-pubkey'], function(err,result){
            reslove(result.toString())
        })
    })
}
passport.use('local',new LocalStrategy({
    usernameField: 'account',
    passwordField: 'signature',
    passReqToCallback: true
},
    async function (req, username, password, done) {
        console.log(req.hashed)
        console.log("un:",username)
        if(req.hashed && req.pubkey ){
            return done(null,{'identity':username.toLowerCase(),'pubkey':req.pubkey});
        }
    }
))
router.get("/profile",isAuthenticated ,async function(req,res){
    console.log(req.user)
    let acc = await accInstance.evaluateTransaction('GetUserAccControl',req.user.pubkey);
    let accJson = JSON.parse(acc)
    console.log(accJson)
    return res.render("E-portfolio/highSchool/profile.ejs",{"acc":accJson,"contract_address":contract_address,"user":req.user.identity})
})
router.get("/delete",async function(req,res){
    let r = await accInstance.submitTransaction('Deletekey','0410dee8185f58c25565b47db7e822c188cc7d3b6b9bce1a1907e76dfb3271db317737015cb70b7e1df8459ae285a3edd36df1d12ad3c8a8d689522acc2e034fe1');
    //console.log(r.toString())
    //let r = await accInstance.submitTransaction('GetUserAccControl','0410dee8185f58c25565b47db7e822c188cc7d3b6b9bce1a1907e76dfb3271db317737015cb70b7e1df8459ae285a3edd36df1d12ad3c8a8d689522acc2e034fe1');
    //let r = await accInstance.submitTransaction('AddAttribute',"0410dee8185f58c25565b47db7e822c188cc7d3b6b9bce1a1907e76dfb3271db317737015cb70b7e1df8459ae285a3edd36df1d12ad3c8a8d689522acc2e034fe1","test");
    console.log(r.toString())
})
router.get("/",async function(req,res){
    res.render('E-portfolio/highSchool/homepage.ejs',{"require_signature":require_signature,})
});
router.get("/logout",async function(req ,res){
    req.logOut();
    res.redirect('/E-portfolio/highSchool');
})
router.post('/loginWithMetamask',
async function(req,res,next){
    let {account,signature} = req.body
    let signingAccount = web3.eth.accounts.recover(require_signature, signature).toLowerCase();
    if(signingAccount != account.toLowerCase()){
        return res.send({'msg':'Failed to verify signature'});
    }
    let identityManagerInstance = new web3.eth.Contract(identityManager.abi, contract_address);
    let DID = await identityManagerInstance.methods.getId().call({from: account})

    if(DID){
        let PIContractAddress = await identityManagerInstance.methods.getAccessManagerAddress(account).call({from: account});
        personalIdentityInstance = new web3.eth.Contract(personalIdentity.abi , PIContractAddress);
        let CSR = await personalIdentityInstance.methods.getEncryptMaterial("HLFCSR").call({from: account})
        let CSRDecode = await opensslDecode(Buffer.from(CSR))

        // Decode CSR to get CN and pubkey.
        let CN = CSRDecode.substr(CSRDecode.indexOf('CN=')+3,account.length);
        let start_index = '-----BEGIN PUBLIC KEY-----'.length 
        let end_index = CSRDecode.indexOf('-----END PUBLIC KEY-----')
        let pubkey_base64 = CSRDecode.substring(start_index,end_index).replace(/\n/g,'');
        let pubkey_hex = Buffer.from(pubkey_base64, 'base64').toString('hex');

        // exist useless prefix 3059301306072a8648ce3d020106082a8648ce3d030107034200
        pubkey_hex = pubkey_hex.substr('3059301306072a8648ce3d020106082a8648ce3d030107034200'.length)
        let accExist = await accInstance.evaluateTransaction('UserAccControlExist',pubkey_hex);
        
        if(accExist.toString()!="false"){
            req.hashed = DID;
            req.pubkey = pubkey_hex;
            next();
        }
        else if(CN.toUpperCase()== account.toUpperCase()){
            
            // access control is not exist create one (in ethereum address store lowerCase in ledger.)
            try{
                // if first login this app.
                let attrs = [
                    {'name': 'category', 'value': 'student', 'ecert':true }
                ]
                let secret = await caClient.register({
                    affiliation: 'org1.department1',
                    enrollmentID: CN,
                    role: 'client',
                    attrs: attrs,
                }, adminUser);
                let enrollment = await caClient.enrollWithCSR({'csr':CSR ,'enrollmentID':CN , 'enrollmentSecret': secret})
                const x509Identity = {
                    credentials: {
                        certificate: enrollment.certificate,
                    },
                    mspId: 'Org1MSP',
                    type: 'X.509',
                };

                await wallet.put(CN, x509Identity);
                console.log('\x1b[33m%s\x1b[0m', "create x509 cert successfully.");  
            }
            catch(e){
                console.log("already register in ca")
                //return res.send({'msg':'CN and account are different.'});
            }
            //Create access control on app chain
            try{
                var result = await accInstance.submitTransaction('AddPersonalAccessControl',pubkey_hex);
                console.log('\x1b[33m%s\x1b[0m',result.toString());
                var mapping = await Mapping.create({address:account.toLowerCase(),pubkey:pubkey_hex});
                req.hashed = DID;
                req.pubkey = pubkey_hex;
                next();
            }
            catch(e){
                return res.send({'msg':'create acc error.'});
            }
        }
        else{
            return res.send({'msg':'CN and account are different.'});
        }
    }
    else{
        return res.send({'msg':'DID dose not exist.'});
    }
},
passport.authenticate('local'),
async function(req,res){
    res.send({url: "/E-portfolio/highSchool/profile"});
})
router.post("/addAttribue_1",isAuthenticated,async function(req,res){
    let attribute = req.body.attribute
    //console.log(user)
    var user = await buildCertUser(wallet,fabric_common , req.user.identity);
    var userContext = gateway.client.newIdentityContext(user)
    // create tx 
    var endorsement = network.channel.newEndorsement('accessControl');
    var build_options = { fcn: 'AddAttribute', args: [attribute], generateTransactionId: true }
    var proposalBytes = endorsement.build(userContext, build_options);
    addAttribte[req.user.identity] = endorsement
    const digest = hashFunction(proposalBytes);

    return res.send({'digest':digest})
})

router.post("/addAttribue_2",isAuthenticated,async function(req,res){
    if(addAttribte[req.user.identity]){
        let {signature} = req.body;
        let endorsement = addAttribte[req.user.identity]

        signature = signature.split("/");
        let signature_array = new Uint8Array(signature.length);
        for(var i=0;i<signature.length;i++){
            signature_array[i] = parseInt(signature[i])
        }
        let signature_buffer = Buffer.from(signature_array)
        
        endorsement.sign(signature_buffer);
        const proposalResponses = await endorsement.send({ targets: network.channel.getEndorsers() });
        let result = proposalResponses.responses[0].response.payload.toString();
        
        if(proposalResponses.responses[0].response.status==200){
            let user = await buildCertUser(wallet,fabric_common,req.user.identity);
            let userContext = gateway.client.newIdentityContext(user)

            let commit = endorsement.newCommit();
            let commitBytes = commit.build(userContext)
            let commitDigest = hashFunction(commitBytes)
            addAttribte[req.user.identity] = commit
            return res.send({'status':200,'commitDigest':commitDigest,'msg':result})
        }
        else{
            return res.send({'status':500})
        }
    }else{
        res.send({'msg':'error'})
    }
})
router.post("/addAttribue_3",isAuthenticated,async function(req,res){
    if(addAttribte[req.user.identity]){
        let {signature} = req.body;
        let commit = addAttribte[req.user.identity]

        signature = signature.split("/");
        let signature_array = new Uint8Array(signature.length);
        for(var i=0;i<signature.length;i++){
            signature_array[i] = parseInt(signature[i])
        }
        let signature_buffer = Buffer.from(signature_array)
        commit.sign(signature_buffer)

        const commitSendRequest = {};
        commitSendRequest.requestTimeout = 300000
        commitSendRequest.targets = network.channel.getCommitters();
        const commitResponse = await commit.send(commitSendRequest);

        if(commitResponse['status']=="SUCCESS"){
            return res.send({'status':200,'msg':""})
        }
        else{
            return res.send({'status':500,'msg':'commit error'})
        }
    }
    else{
        return res.send({'status':500,'msg':"no endorsement"})
    }
    
})

module.exports = router;
