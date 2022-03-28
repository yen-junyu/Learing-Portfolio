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
var privateKey = config.org_address.highSchool.privateKey

var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));


//controller
var Mapping = require("../../controllers/mapping.controller")
var router = express.Router();

//fabric SDK and Util
var fabric_common = require("fabric-common");
var { Gateway, Wallets} = require('fabric-network');
var { buildCAClient, registerAndEnrollUser, enrollAdmin ,getAdminIdentity , buildCertUser} = require('../../Util/CAUtil.js');
var { buildCCPOrg2, buildCCPOrg3, buildWallet } = require('../../Util/AppUtil.js');
var FabricCAServices_1  = require('../../Util/FabricCAService_1.js');

//encrypt 
var { ethers } = require("ethers")
var { decrypt, encrypt } = require("eth-sig-util")
var crypto = require("crypto");

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
var mspOrg2 = 'Org2MSP';
var caClient, wallet, adminUser;
var gatewayOrg2, gatewayOrg3;

var accChannel, accInstance;
var addAttribte = {};




const preventMalleability = (sig, ecdsa) => {
    const halfOrder = ecdsa.n.shrn(1);
    if (sig.s.cmp(halfOrder) === 1) {
        const bigNum = ecdsa.n;
        sig.s = bigNum.sub(sig.s);
    }
    return sig;
};
var awardInstanceListener = async (event) => {
    const eventInfo = JSON.parse(event.payload.toString());

    if(event.eventName == "IssueAward"){
        try{
            //confirm this student in org
            let result = await Mapping.findOne({pubkey: eventInfo.student});
            let pubkey = result.dataValues.pubkey
            let response = await accInstance.submitTransaction("AddAttributeForUser",pubkey,eventInfo.activityName)
            console.log(response.toString())
        }
        catch(e){
            console.log(e)
        }
        
    }
    
	// notice how we have access to the transaction information that produced this chaincode event
    //const eventTransaction = event.getTransactionEvent();
    //console.log(eventTransaction.transactionData.actions[0].payload.chaincode_proposal_payload.input.chaincode_spec.input.args[3].toString())
	//console.log(`*** transaction: ${eventTransaction.transactionId} status:${eventTransaction.status}`);
}

async function init(){
    // initial some object

    //build ca client
    let ccpOrg2 = buildCCPOrg2();
    caClient = await buildCAClient(FabricCAServices_1, ccpOrg2, 'ca.org2.example.com');

    //build wallet to store cert
    let walletPath = path.join(__dirname, '..', '..' ,'wallet','highSchool');
    wallet = await buildWallet(Wallets, walletPath);
    
    //enroll ca admin 
    await enrollAdmin(caClient, wallet, mspOrg2);

    //get ca admin to register and enroll user
    adminUser = await getAdminIdentity(caClient,wallet)

    //register and enroll app admin (need admin attribute)
    await registerAndEnrollUser(caClient, wallet, mspOrg2, 'schoolA', 'org1.department1', null, 'admin');

    //create Gateway to connect to peer
    gatewayOrg2 = new Gateway();
    await gatewayOrg2.connect(ccpOrg2, {
        wallet,
        identity: 'schoolA',
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gatewayOrg2 is using a fabric network deployed locally
    });
    accChannel = await gatewayOrg2.getNetwork('acc-channel');
    accInstance = await accChannel.getContract('AccessControlManager');
    //await accInstance.submitTransaction("Deletekey","041e26667dee0b081371428273abf7aa6995e1443033476fffaa31525262f19915b2188ca7656f394fe22ac8129fd510f673a6d2607347f271f74352dd5d582279")
    //=========================
    let ccpOrg3 = buildCCPOrg3();
    gatewayOrg3 = new Gateway();
    await gatewayOrg3.connect(ccpOrg3, {
        wallet,
        identity: 'APP_schoolA',
        discovery: { enabled: true, asLocalhost: true } 
    });
    certChannel = await gatewayOrg3.getNetwork('cert-channel');
    awardInstance = certChannel.getContract('issueAward');
    await awardInstance.addContractListener(awardInstanceListener);
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
router.get("/profile", isAuthenticated, async function(req,res){
    console.log(req.user)
    let acc = await accInstance.evaluateTransaction('GetUserAccControl',req.user.pubkey);
    let accJson = JSON.parse(acc)
    console.log(accJson)
    return res.render("E-portfolio/highSchool/profile.ejs",{"acc":accJson,"contract_address":contract_address,"user":req.user.identity})
})
router.get("/delete", async function(req,res){
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
    let DID = await identityManagerInstance.methods.getId().call({from: account});

    if(DID){
        var pubkey;
        try{
            //Confirm from DB that the user has logged in
            let result = await Mapping.findOne({address: account.toLowerCase()});
            pubkey = result.dataValues.pubkey
        }
        catch{
            pubkey = null
        }
       
        if(pubkey){
            req.hashed = DID;
            req.pubkey = pubkey;
            next();
        }
        else{
            // access control is not exist create one (in ethereum address store lowerCase in ledger.)
            let PIContractAddress = await identityManagerInstance.methods.getAccessManagerAddress(account).call({from: account});
            let personalIdentityInstance = new web3.eth.Contract(personalIdentity.abi, PIContractAddress);
            let EncryptCSRHex = await personalIdentityInstance.methods.getEncryptMaterial("HLFCSR").call({from: account})
            let EncryptCSR = JSON.parse(ethers.utils.toUtf8String(EncryptCSRHex))
            let CSR = decrypt(EncryptCSR, privateKey)
            let CSRDecode = await opensslDecode(Buffer.from(CSR))

            // Decode CSR to get CN and pubkey.
            let CN = CSRDecode.substr(CSRDecode.indexOf('CN=')+3,account.length);
            let start_index = '-----BEGIN PUBLIC KEY-----'.length 
            let end_index = CSRDecode.indexOf('-----END PUBLIC KEY-----')
            let pubkey_base64 = CSRDecode.substring(start_index,end_index).replace(/\n/g,'');
            let pubkey_hex = Buffer.from(pubkey_base64, 'base64').toString('hex');
            // exist useless prefix 3059301306072a8648ce3d020106082a8648ce3d030107034200
            pubkey_hex = pubkey_hex.substr('3059301306072a8648ce3d020106082a8648ce3d030107034200'.length)
            
            console.log(pubkey_hex)
            //check CN and account
            if(CN.toLowerCase()== account.toLowerCase()){
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
                        mspId: mspOrg2,
                        type: 'X.509',
                    };
    
                    await wallet.put(CN, x509Identity);
                    console.log('\x1b[33m%s\x1b[0m', "create x509 cert successfully.");  
                }
                catch(e){
                    console.log("already register in ca")
                }
                //Create access control on app chain
                try{
                    //var result = await accInstance.submitTransaction('AddPersonalAccessControl', pubkey_hex);
                    console.log('\x1b[33m%s\x1b[0m',result.toString());
                    var mapping = await Mapping.create({address:account.toLowerCase(), pubkey:pubkey_hex});
                    req.hashed = DID;
                    req.pubkey = pubkey_hex;
                    next();
                }
                catch(e){
                    return res.send({'msg':'create acc error.'});
                }
                
            }
            else{
                console.log("CN and account are different.")
                return res.send({'msg':'CN and account are different.'});
            }
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
    var userContext = gatewayOrg2.client.newIdentityContext(user)
    // create tx 
    var endorsement = accChannel.channel.newEndorsement('AccessControlManager');
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
        console.log(accChannel.channel.getEndorsers())
        const proposalResponses = await endorsement.send({ targets: accChannel.channel.getEndorsers() });
        let result = proposalResponses.responses[0].response.payload.toString();
        
        if(proposalResponses.responses[0].response.status==200){
            let user = await buildCertUser(wallet,fabric_common,req.user.identity);
            let userContext = gatewayOrg2.client.newIdentityContext(user)

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
        commitSendRequest.targets = accChannel.channel.getCommitters();
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
