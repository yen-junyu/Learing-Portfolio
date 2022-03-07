var express = require('express');
var router = express.Router();
var fs = require('fs');
var path = require('path');
//var FabricCAServices = require('fabric-ca-client');
var { Gateway, Wallets} = require('fabric-network');
var fabric_common = require("fabric-common");
var { buildCAClient, registerAndEnrollUser, enrollAdmin ,getAdminIdentity , buildCertUser} = require('../Util/CAUtil.js');
var { buildCCPOrg1, buildWallet } = require('../Util/AppUtil.js');
var FabricCAServices_1  = require('../Util/FabricCAService_1.js');
const elliptic = require('elliptic');
const { KEYUTIL } = require('jsrsasign');
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];

const ecdsa = new EC(ecdsaCurve);
const db = require("../models");
const ApplyCert = db.applyCert;




var ccp;
var caClient;
var walletPath;
var wallet;
var adminUser;
var gateway;
var network;

const preventMalleability = (sig, ecdsa) => {
    const halfOrder = ecdsa.n.shrn(1);
    if (sig.s.cmp(halfOrder) === 1) {
        const bigNum = ecdsa.n;
        sig.s = bigNum.sub(sig.s);
    }
    return sig;
};

async function init(){
    const mspOrg1 = 'Org1MSP';
    ccp = buildCCPOrg1();
    caClient = await buildCAClient(FabricCAServices_1, ccp, 'ca.org1.example.com');
    walletPath = path.join(__dirname,'..', 'wallet');
    wallet = await buildWallet(Wallets, walletPath);
    await enrollAdmin(caClient, wallet, mspOrg1);
    // build admin user
    /*
    await registerAndEnrollUser(caClient, wallet, mspOrg1, 'app_admin', 'org1.department1' ,[
        {'name': 'eth_adress' , 'value': '0x1234567890' ,'ecert':true },
    ], 'admin');
    */
    adminUser = await getAdminIdentity(caClient,wallet)
    gateway = new Gateway();
    try {
        await gateway.connect(ccp, {
            wallet,
            identity: 'app_admin',
            discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
        });
        // admin has private key 
        /*
        let userJson = await wallet.get('admin');
        let provider = wallet.getProviderRegistry().getProvider(userJson.type);
        let adminUser = await provider.getUserContext(userJson,'admin');
        let adminUserContext = gateway.client.newIdentityContext(adminUser);
        */
        //network = await gateway.getNetwork('mychannel');
        //var contract = network.getContract('chaincode1');
        //var result = await contract.submitTransaction('addOrgAdmin');
        //var result = await contract.submitTransaction('GetAllState');
        //var result = await contract.submitTransaction('DeleteOrgAdmin','Org1MSP');
        //var result = await contract.submitTransaction('applyIssueCert','023');

        
        //console.log(result.toString())
        //console.log(result.toString())
        
        //console.log("========================")
        
        /*
        // user without private key 
        var user = await buildCertUser(wallet,fabric_common , 'maomao2')
        var userContext = gateway.client.newIdentityContext(user).calculateTransactionId()
        // create tx 
        var endorsement = network.channel.newEndorsement('chaincode1');
        var build_options = { fcn: 'GetIdentity', args: [], generateTransactionId: false }
        var proposalBytes = endorsement.build(userContext, build_options);
        
        // hash function 
        let cryptoSuite = fabric_common.Utils.newCryptoSuite()
        let hashFunction = cryptoSuite.hash.bind(cryptoSuite)

        // sign tx 
        const digest = hashFunction(proposalBytes);

        const signKey = ecdsa.keyFromPrivate('2ec48cb08f950324a09bbbea30853ebb6c00137b748086d0a38494b71d9f6bd8', 'hex');
        const sig = ecdsa.sign(Buffer.from(digest, 'hex'), signKey);

        var halfOrderSig = preventMalleability(sig, ecdsa);
        const signature = Buffer.from(halfOrderSig.toDER());
       
        
        endorsement.sign(signature);
        const proposalResponses = await endorsement.send({ targets: network.channel.getEndorsers() });
        // here is response 
        console.log(proposalResponses)

        const commit = endorsement.newCommit();
        let commitBytes = commit.build(userContext)
        let commitDigest = hashFunction(commitBytes);
        let commiSig = ecdsa.sign(Buffer.from(commitDigest, 'hex'), signKey);
        let commitHalfOrderSig = preventMalleability(commiSig, ecdsa);
        let commitSignature = Buffer.from(commitHalfOrderSig.toDER());
        commit.sign(commitSignature)
        //console.log(commitBytes)

        
        commit.build(adminUserContext);
        commit.sign(adminUserContext);
        

        const commitSendRequest = {};
        commitSendRequest.requestTimeout = 300000
        commitSendRequest.targets = network.channel.getCommitters();
        const commitResponse = await commit.send(commitSendRequest);
        
        //console.log()
        //console.log(commitResponse)
        //console.log(commit)
        


        //console.log(endorsement_sign)
        
        //console.log(result)
        
       // const discoveryService = network.channel.newDiscoveryService('chaincode1')
        //console.log(discoveryService)
        //this.discoveryService = this.network.getChannel().newDiscoveryService(this.chaincodeId);
        //console.log(x)
        


        //hashFunction()
        //cryptoSuite
        //console.log(fabric_common.Utils.newCryptoSuite().hash.bind(this._cryptoSuite);)
        //console.log(proposalBytes)



        //endorsement.build(userContext, proposalBuildRequest);
        //console.log(endorsement)
        


        //console.log(network)
        */

    }
    finally {
        
    }
    
}
init()

router.get('/', function(req, res) {
    res.render('homepage', { title: 'hello', info: "hello world"});
});

router.get('/applyRegister',async function(req , res){
    /*
    // store id, attrs , status in db 
    id = {
        名稱,
        數量,
        用途,
        描述,
        api,
    }
    */
})
router.get('/test',async function(req ,res){
    res.json(id_map_pw);
})
router.get('/registerNewUser',async function(req, res){
    // 1.需做身份認證admin的才可新增user

    let address = req.query.address
    if(!address){
        return res.send("address miss")
    }
    let user = await ApplyCert.findByPk(address);
    if(!user){
        return res.send("adress is not exist")
    }

    let attrs = [
        {'name': 'address', 'value': user.dataValues.address, 'ecert':true },
        //{'name': 'e-mail',  'value': data.email ,'ecert':true}
    ]
    
    
    const secret = await caClient.register({
        affiliation: 'org1.department1',
        enrollmentID: user.dataValues.activityName,
        role: 'client',
        attrs: attrs,
    }, adminUser);


    user.set({
        status: "true",
        pw : secret
    });
    await user.save();
    var contract = network.getContract('chaincode1');
    var result = await contract.submitTransaction('applyIssueCert',user.dataValues.pubkey);

    return res.send({'status' : 'good'});
})

router.post('/enroll',async function(req,res){
    let { id , pw , csr } = req.body;
   
    console.log(pw)
    console.log(id)
    console.log(csr)
    csr = csr.replace(/\\r/g,'\r');
    csr = csr.replace(/\\n/g,'\n');
    console.log(csr)
    let enrollment = await caClient.enrollWithCSR({'csr':csr,'enrollmentID':id , 'enrollmentSecret': pw})

    const x509Identity = {
        credentials: {
            certificate: enrollment.certificate,
        },
        mspId: 'Org1MSP',
        type: 'X.509',
    };

    console.log(x509Identity)
    await wallet.put(id, x509Identity);
    
    res.json({"status": 'success'});
})

router.get('/getKey',async function(req,res){
    /*
    create key to enroll
    */
    let id = req.query.id
    if(!id){
        res.json({'msg':'id is empty'})
    }
    let key = await caClient.createKeyAndCSR(id)
    res.json(key);
})

router.get('/userID',async function(req, res){
    let id = req.query.id  
    //console.log(ccp)
    //console.log(wallet)

    res.json({"id": id});
})

router.get('/postSignature',async function(req , res){
    res.render('homepage');
})


module.exports = router;