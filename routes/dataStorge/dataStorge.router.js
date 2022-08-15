var express = require('express');
var Web3 = require('web3');
var fs = require('fs');
var path = require('path')
var db = require("../../models");
var Awards = db.awards
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

// config and abi 
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var dataStorge_address = config.org_info.dataStorge.address;
var dataStorge_key = config.org_info.dataStorge.key;

//var identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
//var personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
//var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
var identityManager = JSON.parse(fs.readFileSync('./contracts/identityChain/IdentityManager.json', 'utf-8'));
var personalIdentity = JSON.parse(fs.readFileSync('./contracts/identityChain/PersonalIdentity.json', 'utf-8'));
var contract_address = config.contracts.identityManagerAddress;
var router = express.Router();
//var Mapping = require("../../controllers/mapping.controller")

var { Gateway, Wallets} = require('fabric-network');
var { buildCCPOrg3, buildWallet } = require('../../Util/AppUtil.js');
var certInstance, accInstance , awardInstance;

var colors = require('colors');
async function init(){

    let ccp = buildCCPOrg3();
    let dataStorgeWalletPath = path.join(__dirname, '..', '..' ,'wallet','dataStorge');
    let dataStorgeWallet = await buildWallet(Wallets, dataStorgeWalletPath);
    let gateway = new Gateway();

    await gateway.connect(ccp, {
        wallet : dataStorgeWallet,
        identity: 'dataStorge',
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
    });

    console.log('finish gateway connection'.yellow);
    let certChannel = await gateway.getNetwork('cert-channel');
    certInstance =  await certChannel.getContract('certManager');

    let accChannel = await gateway.getNetwork('acc-channel');
    accInstance = await accChannel.getContract('AccessControlManager');
    
    
    console.log('get contract instance successfully'.yellow);
}
init();
var activityName = "python class"
var verifyToken = function (req, res, next) {
    var {user} = req.query;
    var token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (token) {
        jwt.verify(token, dataStorge_key, async function(err, decoded) {
            if (err) {
                return res.status(403).json({success: false, message: 'Failed to authenticate token.'})
            } else {
                // check with BC
                let permitBuffer = await accInstance.evaluateTransaction('ConfirmUserAuthorization', user, decoded.sub, activityName);
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

router.get("/",async function(req,res){
    var require_signature = "activityVendor?nonce=6512"
    res.render('E-portfolio/dataStorge/homepage.ejs',{"require_signature":require_signature})
});
router.post('/authenticate', async function(req, res) {
    const {publicKey, signature, nonce} = req.body;
    // show info about authenticate
    
    console.log("request target:"+publicKey);
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
    let token = jwt.sign(info, dataStorge_key, {
        expiresIn: 60*60*30,
        issuer: dataStorge_address,
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
router.get('/getProtectedData', verifyToken, async function(req, res){
    var {user} = req.query;
    var award = await Awards.findOne({where:{publicKey:user,activity:activityName}})
    award = award.get({plain: true})
    res.json({
        status:true,
        data:award
    })
})
router.get('/addAward',async function(req,res){
    let award = {
        publicKey : "040d6a1b6903afac76b0d87b05dae5fca1a3d6f06e650d434cd78ebb49e7804a76166f854b7e44cd98766cafd4f5be678242bfaaa67004659dd4cd578eee753844",
        data : "累積課程時數35小時",
        activity : "python class",
        type : "class"
    }
    await Awards.create(award);
    res.json({"status":"good"})
})
router.get('/askPubkey',async function(req,res){
    var require_signature = "activityVendor?nonce=7812"
    res.render('E-portfolio/dataStorge/askpubkey.ejs',{"require_signature":require_signature,contract_address})
})
router.post('/loginWithMetamask',
async function(req,res,next){
    let {account,signature} = req.body
    var require_signature = "activityVendor?nonce=6512"
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
            throw("no")
            let result = await Mapping.findOne({address: account.toLowerCase()});
            pubkey = result.dataValues.pubkey
            console.log(pubkey)
        }
        catch(e){
            console.log(e)
            pubkey = null
        }
        if(pubkey){
            req.hashed = DID;
            req.pubkey = pubkey;
            next();
        }
        else{
            res.send({url: "/E-portfolio/dataStorge/askPubkey"});
        }
    }
    else{
        return res.send({'msg':'DID dose not exist.'});
    }
},
async function(req,res){
    res.send({url: "/E-portfolio/dataStorge/profile"});
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

