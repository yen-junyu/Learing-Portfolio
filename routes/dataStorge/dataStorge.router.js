var express = require('express');
var Web3 = require('web3');
var fs = require('fs');
var path = require('path')
var db = require("../../models");
var crypto = require("crypto");
var jwt = require('jsonwebtoken');


// some tools
let tls = require('tls');
let net = require('net');
const { KEYUTIL } = require('jsrsasign');
const elliptic = require('elliptic')
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);
/*
var privateKEY  = fs.readFileSync('./routes/dataStorge/user0.pem', 'utf8');
var publicKey  = fs.readFileSync('./routes/dataStorge/user0Pubkey.pem', 'utf8');

var signOptions = {
    issuer:  "test",
    subject:  "trst",
    expiresIn:  "12h",
    algorithm:  "ES256"   // RSASSA [ "RS256", "RS384", "RS512" ]
};
var token = jwt.sign({"123":"hello"}, privateKEY, signOptions);
console.log(token)

var verifyOptions = {
    issuer:  "test",
    subject:  "trst",
    expiresIn:  "12h",
    algorithm:  ["ES256"]
   };
var legit = jwt.verify(token, publicKey, verifyOptions);
console.log(legit)
*/
// controller


// config and abi 
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var dataStorge_address = config.org_info.dataStorge.address;
var dataStorge_key = config.org_info.dataStorge.key;
//var identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
//var personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
//var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
var router = express.Router();
//var Mapping = require("../../controllers/mapping.controller")

/*fabric SDK and Util
var { Gateway, Wallets} = require('fabric-network');
var { buildCAClient, registerAndEnrollUser, enrollAdmin ,getAdminIdentity , buildCertUser} = require('../../Util/CAUtil.js');
var { buildCCPOrg3, buildWallet } = require('../../Util/AppUtil.js');
var FabricCAServices_1  = require('../../Util/FabricCAService_1.js');

var caClient,wallet;
var gateway,certChannel,certInstance,awardInstance;

var require_signature = "LEM"

async function init(){

}
init();*/
var activityName = "toeic"

var verifyToken = function (req, res, next) {
    var token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (token) {
        jwt.verify(token, dataStorge_key, async function(err, decoded) {
            if (err) {
                return res.status(403).json({success: false, message: 'Failed to authenticate token.'})
            } else {
                let permit = false;
                console.log(decoded);
                /*
                if (permit) {
                    req.sub = decoded.sub
                    req.decoded = decoded
                    next();
                }
                else {
                    return res.status(403).send({
                        success: false,
                        message: `((bill)), Already revoke please request token with ${admin_address} again.`
                    })
                }*/
            }
        });
    } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        })
    }   
};
router.post('/authenticate', async function(req, res) {
    const {publicKey, signature, nonce} = req.body;
    // show info about authenticate
    //console.log("request hashed:"+identity);
    console.log("request target:"+publicKey);
    console.log(signature);
    console.log(nonce);
    
    let  publickeyObject = ecdsa.keyFromPublic(publicKey,'hex')
    let verify = publickeyObject.verify(Buffer.from(nonce.nonce),signature)
    console.log(verify)

    /*
    const recoverAddress = web3.eth.accounts.recover(req.body.signature);
    if (recoverAddress !== org_address)
        return res.json({
            success: false,
            message: 'Target address is not the same'
    })*/
    /*
    // Chceck nonce whether are the same
    if (signature.message !== nonce.nonce)
        return res.json({
            success: false,
            message: 'Nonce is not the same'
    })

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
    let token = jwt.sign(info, dataStorge_key, {
        expiresIn: 60*60*30,
        issuer: dataStorge_address,
        subject: org_address
    });

    return res.json({
        success: true,
        message: 'Got token',
        token: token
    })*/
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
router.get('/getProtectedData',verifyToken, async function(req, res){
    res.json({status:200})
})
/*
router.get('/protected', verifyTokenForDeposit, async function(req, res) {
    let data = req.decoded;
    let hashed = data.hashed;
    let opts = {
        filter: `(hashed=${hashed})`,
        scope: 'one',
        attributes: ['mail', 'phone', 'balance'],
        attrsOnly: true
    };
    let specificUser = await user.userSearch(opts, 'ou=location2,dc=jenhao,dc=com')
    if (specificUser.length !== 0){

        return res.json({success: true, message: "ok, got token", data: specificUser});
    }
    else 
        return res.json({success: false, message: "not found", data: []});
});
*/

module.exports = router;

