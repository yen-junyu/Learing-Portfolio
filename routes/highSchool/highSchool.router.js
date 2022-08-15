var express = require('express');
var Web3 = require('web3');
var fs = require('fs');
var path = require('path')
var openssl = require('openssl-nodejs');
var crypto = require("crypto");
var jwt = require('jsonwebtoken');

// session
var passport = require('passport');
var LocalStrategy = require('passport-local');

// config and abi 
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
var personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
var highSchoolAddress = config.org_info.highSchool.address;
var contract_address = config.contracts.identityManagerAddress;
var privateKey = config.org_info.highSchool.key

var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));

//controller
var Mapping = require("../../controllers/mapping.controller")
var db = require("../../models");
var Grade = db.grade;
var Rank = db.rank;
var StudentInfo = db.studentInfo;
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

//ecdsa
const elliptic = require('elliptic');
const e = require('express');
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);

//hash function
var cryptoSuite = fabric_common.Utils.newCryptoSuite()
var hashFunction = cryptoSuite.hash.bind(cryptoSuite)


//global variable 
var require_signature = "schoolA?nonce:4521";
var activityName = "schoolGrade"
var OrgName = 'Org2'
var mspOrg2 = 'Org2MSP';
var caClient, wallet, adminUser;
var gatewayOrg2, gatewayOrg3;

var accChannel, accInstance ,awardInstance ,certInstance;
var addAttribte = {};
var upatePermission ={};
var revokePermission = {};

var awardInstanceListener = async (event) => {
    const eventInfo = JSON.parse(event.payload.toString());

    if(event.eventName == "IssueAward"){
        try{
            //confirm this student in org
            let result = await Mapping.findOne({pubkey: eventInfo.student});
            if(!result){
                return
            }
            let pubkey = result.dataValues.pubkey
            let acc = await accInstance.evaluateTransaction('GetUserAccControl',pubkey);
            let accJson = JSON.parse(acc)
            
            if(!accJson.AddAttribute.includes(eventInfo.activityName) && !accJson.Attribute.includes(eventInfo.activityName)){
                let response = await accInstance.submitTransaction("AddAttributeForUser",pubkey,eventInfo.activityName)
                console.log(response.toString())
            }
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
let delay = async(ms) => {
    return new Promise(resolve => setTimeout(resolve, ms))
}
async function init(){
    await delay(5000);
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

    //create Gateway to connect to school peer
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
        identity: 'cert_schoolA',
        discovery: { enabled: true, asLocalhost: true } 
    });
    certChannel = await gatewayOrg3.getNetwork('cert-channel');
    awardInstance = certChannel.getContract('issueAward');
    certInstance =  certChannel.getContract('certManager');
    await awardInstance.addContractListener(awardInstanceListener);   
}
init();

var isAuthenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        return res.redirect("/E-portfolio/highSchool/")
    }
};
var verifyToken = async function (req, res, next) {
    var {user} = req.query;
    var token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (token) {
        jwt.verify(token, privateKey, async function(err, decoded) {
            if (err) {
                return res.status(403).json({success: false, message: 'Failed to authenticate token.'})
            } else {
                // check with BC
                let permitBuffer = await accInstance.evaluateTransaction('ConfirmUserAuthorization', user, decoded.sub, OrgName + "SchoolGrade");
                let permit = (permitBuffer.toString() === 'true');
                if (permit) {
                    req.sub = decoded.sub
                    req.decoded = decoded
                    next();
                }
                else {
                    return res.status(403).send({
                        success: false,
                        message: `Permission Denied .`
                    })
                }
            }
        });
    } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        })
    }   
};
async function opensslDecode(buffer_input){
    return new Promise(function(reslove,reject){
        openssl(['req', '-text','-in', { name:'key.csr',buffer:buffer_input } ,'-pubkey'], function(err,result){
            reslove(result.toString())
        })
    })
}
async function createTransaction(){
    // parameter 0 is user identity
    // parameter 1 is chaincode function Name
    // parameter 2 to end is chaincode function parameter
    var user = await buildCertUser(wallet, fabric_common, arguments[0]);
    var userContext = gatewayOrg2.client.newIdentityContext(user)

    var endorsementStore;
    switch (arguments[1]){
        case 'AddAttribute':
            endorsementStore = addAttribte;
            break;
        case 'UpatePermission':
            endorsementStore = upatePermission
            break;
        case 'RevokePermission':
            endorsementStore = revokePermission
            break;
    }
    var paras = [];
    for(var i= 2 ; i< arguments.length ; i++){
        paras.push(arguments[i])
    }
    var endorsement = accChannel.channel.newEndorsement('AccessControlManager');
    var build_options = { fcn: arguments[1], args: paras, generateTransactionId: true }
    var proposalBytes = endorsement.build(userContext, build_options);
    const digest = hashFunction(proposalBytes);
    endorsementStore[arguments[0]] = endorsement
    
    return new Promise(function(reslove,reject){
        reslove(digest);
    })
}
async function proposalAndCreateCommit(){
    // parameter 0 is user identity
    // parameter 1 is chaincode function Name
    // parameter 2 is signature

    var endorsementStore;
    switch (arguments[1]){
        case 'AddAttribute':
            endorsementStore = addAttribte;
            break;
        case 'UpatePermission':
            endorsementStore = upatePermission
            break;
        case 'RevokePermission':
            endorsementStore = revokePermission
            break;
    }
    if(typeof(endorsementStore) == "undefined"){
        return new Promise(function(reslove,reject){
            reject({
                'error': true,
                'result': "func dosen't exist."
            });
        })
    }
    let endorsement = endorsementStore[arguments[0]]
    endorsement.sign(arguments[2]);
    let proposalResponses = await endorsement.send({ targets: accChannel.channel.getEndorsers() });

    if(proposalResponses.responses[0].response.status == 200){
        let user = await buildCertUser(wallet, fabric_common, arguments[0]);
        let userContext = gatewayOrg2.client.newIdentityContext(user)

        let commit = endorsement.newCommit();
        let commitBytes = commit.build(userContext)
        let commitDigest = hashFunction(commitBytes)
        let result = proposalResponses.responses[0].response.payload.toString();
        endorsementStore[arguments[0]] = commit;

        return new Promise(function(reslove,reject){
            reslove({
                'commitDigest':commitDigest,
                'result': result
            });
        })
    }
    else
    {
        return new Promise(function(reslove,reject){
            reject({
                'error': true,
                'result': proposalResponses.responses[0].response.message
            });
        })
    }
}
async function commitSend(){
    // parameter 0 is user identity
    // parameter 1 is chaincode function Name
    // parameter 2 is signature

    var endorsementStore;
    switch (arguments[1]){
        case 'AddAttribute':
            endorsementStore = addAttribte;
            break;
        case 'UpatePermission':
            endorsementStore = upatePermission
            break;
        case 'RevokePermission':
            endorsementStore = revokePermission
            break;
    }
    if(typeof(endorsementStore) == "undefined"){
        return new Promise(function(reslove,reject){
            reject({
                'error': true,
                'result': "func doesn't exist."
            });
        }) 
    }
    let commit = endorsementStore[arguments[0]]
    commit.sign(arguments[2])
    let commitSendRequest = {};
    commitSendRequest.requestTimeout = 300000
    commitSendRequest.targets = accChannel.channel.getCommitters();
    let commitResponse = await commit.send(commitSendRequest);

    if(commitResponse['status']=="SUCCESS"){
        return new Promise(function(reslove,reject){
            reslove({
                'result': true
            });
        })
    }
    else{
        return new Promise(function(reslove,reject){
            reject({
                'error': true,
                'result': "commit error"
            });
        })
    }
}
function convertSignature(signature){
    signature = signature.split("/");
    let signature_array = new Uint8Array(signature.length);
    for(var i=0;i<signature.length;i++){
        signature_array[i] = parseInt(signature[i])
    }
    let signature_buffer = Buffer.from(signature_array)
    return signature_buffer;
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
router.post('/authenticate', async function(req, res) {
    const {publicKey, signature, nonce} = req.body;
    // show info about authenticate
    //console.log("request hashed:"+identity);
    console.log("request target:" + publicKey);
    console.log(signature);
    console.log(nonce);
    
    let  publickeyObject = ecdsa.keyFromPublic(publicKey,'hex')
    let verify = publickeyObject.verify(Buffer.from(nonce.nonce),signature)

    if(!verify){
        return res.json({
            success: false,
            message: 'verify error.'
        })
    }
    // Check nonce is issued by me
    await db.nonce.findByPk(nonce.id)
        .then( data => {
            if (!data)
                return res.json({status: false, message: "Nonce not exist"});
            else
                // if exist, delete it.
                db.nonce.destroy({ where: {id: nonce.id}})
                    .then( num => {
                        if (num == 1) 
                            console.log("Nonce was deleted successfully.");
                        else
                            console.log(`Cannot delete nonce with id ${nonce.id}, maybe not found`);
                    })
                    .catch( err => res.status(500).send({ message: `could not delete nonce with id=${nonce.id}`}));
    });
    let info = {
        activity : activityName
    }
    let token = jwt.sign(info, privateKey, {
        expiresIn: 60*60*30,
        issuer: highSchoolAddress,
        subject: publicKey
    });

    return res.json({
        success: true,
        message: 'Got token',
        token: token
    })
})
router.get('/auth/nonce', async function (req, res) {
    const {org} = req.query;
    if (!org)
        return res.json({msg: "address of org is missing."});
 
    let nonceObject = await db.nonce.create({org: org, value: crypto.randomBytes(8).toString('hex')})
    let id = nonceObject.id
    let nonce = nonceObject.value;
    res.json({id: id, nonce: nonce});
});
router.get("/getSchoolData", verifyToken ,async function(req ,res){
    
    var {user} = req.query;
    let studentInfo = (await StudentInfo.findOne({where:{publicKey:user}})).get({plain: true})
    let account = studentInfo.account

    let grade = await Grade.findAll({where:{account:account}})
    grade.forEach(function(value, index, array){
        array[index] = value.get({
            plain: true
        })
    });
    let rank = await Rank.findAll({where:{account:account}})
    rank.forEach(function(value, index, array){
        array[index] = value.get({
            plain: true
        })
    });

    let data = {
        status : true,
        studentInfo : studentInfo,
        grade : grade,
        rank : rank
    }
    
    return res.json(data)
})
router.get("/getPubkey", isAuthenticated , async function(req , res){
    let pubkey = req.user.pubkey
    console.log(pubkey.length)
    res.json({'pubkey':pubkey})
})
router.get("/profile", isAuthenticated, async function(req,res){
    // get user ACC
    let acc = await accInstance.evaluateTransaction('GetUserAccControl',req.user.pubkey);
    let accJson = JSON.parse(acc.toString())

    // get reviewer list
    reviewerList = {};
    let reviewers = await certInstance.evaluateTransaction("getReviewer");
    reviewers = JSON.parse(reviewers.toString())
    reviewers.forEach(function(object, index, array){
        let value = JSON.parse(object.value)
        reviewerList[value.pubkey] = value.reviewerName
    });
    console.log(reviewerList)

    return res.render("E-portfolio/highSchool/profile.ejs",{"acc":accJson,"contract_address":contract_address,"user":req.user.identity,"reviewerList":reviewerList})
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
            console.log(pubkey)
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
                    console.log(pubkey_hex)
                    var result = await accInstance.submitTransaction('AddPersonalAccessControl', pubkey_hex);
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
router.post("/revokePermission", isAuthenticated, async function(req,res){
    let {revokeOrgName} = req.body
    try{
        const digest = await createTransaction(req.user.identity, 'RevokePermission', revokeOrgName);
        return res.send({'digest':digest})
    }
    catch(e){
        console.log(e)
        return res.send({'error': "error","result": e})
    }
})
router.post("/addAttribue", isAuthenticated, async function(req,res){
    let {attribute} = req.body
    try{
        const digest = await createTransaction(req.user.identity, 'AddAttribute', attribute);
        return res.send({'digest':digest})
    }
    catch(e){
        console.log(e)
        return res.send({'error': "error","result": e})
    }
})
router.post("/updatePermission", isAuthenticated, async function(req,res){
    let { orgPubkey, attributes} = req.body
    try
    {
        let acc = await accInstance.evaluateTransaction('GetUserAccControl',req.user.pubkey);
        let accJson = JSON.parse(acc.toString())
        let attrbutesString = attributes.join("|")

        // check all attributes in user acc 
        attributes.forEach(attribute => {
            if(!accJson.Attribute.includes(attribute)){
                return res.send({'error': true , 'result':`${attribute} dosen't exist.`})
            }
        });
        
        // check orgPubkey exist
        const digest = await createTransaction(req.user.identity, 'UpatePermission', orgPubkey, attrbutesString);
        return res.send({'digest':digest})
    }
    catch(e){
        console.log(e)
        return res.send({'error': "error","result": e})
    }
})
router.post("/proposalAndCreateCommit", isAuthenticated, async function(req,res){
    try {
        let {signature,func} = req.body;
        let signature_buffer = convertSignature(signature)
        let response = await proposalAndCreateCommit(req.user.identity, func, signature_buffer)
        console.log(response)
        return res.send(response)

    } catch (error) {
        console.log(error)
        return res.send(error)
    }
})
router.post("/commitSend", isAuthenticated, async function(req,res){
    try {
        let {signature , func} = req.body;
        let signature_buffer = convertSignature(signature);
        let response  = await commitSend(req.user.identity, func, signature_buffer);
        console.log(response)
        return res.send(response)
    } catch (error) {
        console.log(error)
        return res.send(error)
    }
})
router.post("/addData", async function(req,res){
    
    var {account} = req.body;
    account = account.toLowerCase()
    
    var semester = ["1081","1082","1091","1092","1101"]
    var classList = ["國文","英文","數學","物理","化學","生物","地科"]
    for(var j=0;j<2;j++){
        for(var i=0;i<classList.length;i++){
            let x = Math.floor(Math.random()*(100-60+1))+60;
            x = x.toString()
            let grade = {
                account : account,
                semester: semester[j],
                className:classList[i],
                grade :x
            }
            await Grade.create(grade);
        }
    }
    for(var i=0;i<5;i++){
        let x = Math.floor(Math.random()*(100-15+1))+15;
        x = x.toString()
        let total = '/234';
        let rank ={
            account:account,
            semester:semester[i],
            rank : x + total
        }
        await Rank.create(rank)
    }
    
    let result = await Mapping.findOne({address: account.toLowerCase()});
    let pubkey = result.dataValues.pubkey
    let studentInfo = {
        account : account,
        publicKey : pubkey,
        Name : "王小明",
        highSchool : "建功高中"
    }
    await StudentInfo.create(studentInfo)
    res.json({"success":"good"})
})


module.exports = router;
