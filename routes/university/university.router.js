var express = require('express');
var router = express.Router();
var fs = require('fs');
var path = require('path')
var fetch = require('node-fetch');
var db = require("../../models");
var Web3 = require('web3');
var Mapping = require("../../controllers/mapping.controller")

// some tools
let tls = require('tls');
let net = require('net');
const { KEYUTIL } = require('jsrsasign');
const elliptic = require('elliptic')
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);

var x509JSON = JSON.parse(fs.readFileSync('./wallet/university/University.id', 'utf-8'));


var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
const web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
const org_address = config.org_info.university.address; // org0
const key = config.org_info.university.key; // org0

// debug
var colors = require('colors');


// hyperledger connection 
var { Gateway, Wallets} = require('fabric-network');
var { buildCCPOrg1, buildWallet } = require('../../Util/AppUtil.js');
var certInstance, accInstance , awardInstance;
var publicKey,privateKey;

let getProtectedData = async(address) =>{
    return new Promise(async function(resolve,reject){
        try{
            // get user pubkey
            let user = await Mapping.findOne({address:address.toLowerCase()});
            let pubkey = user.dataValues.pubkey;
            
            let linksBuffer = await awardInstance.evaluateTransaction('getAccessLink', pubkey);
            let links  = JSON.parse(linksBuffer.toString());
            let accessLinks = {}

            links.forEach(function(object, index, array){
                let key = object.key.replace(/\0/g, '').replace(pubkey,'');
                accessLinks[key] =  object.value;
            });

            let acc = await accInstance.evaluateTransaction('GetPermission',pubkey);
            let attrs = JSON.parse(acc.toString());
            /*
            attrs.forEach(function(object, index, array){
                if(accessLinks[object]){
                    await fetch(`http://${api}`, {
                        headers: { 'x-access-token': token.jwt }
                    })
                }
            })*/
        }
        catch(e){
            console.log(e)
            resolve(null)
        } 
    })
    //find token 
    let token = await db.token.findOne({where:{"activity":"toeic"}});
    
    //find reviewer list
    let users = await Mapping.findAll();
    
    // get user attribute 

    // get data
    let api = "localhost:3001/E-portfolio/dataStorge/getProtectedData";
    await fetch(`http://${api}`, {
        headers: { 'x-access-token': token.jwt }
    })

}
let getIdentityToken = async(activity, host) => {
    return new Promise(async function(reslove,reject){
        // get nonce
        let nonceObject;
        await fetch(`http://${host}/auth/nonce?org=${org_address}`)
        .then(res => res.json())
        .then(json => {
            console.log(json)
            if (!json.success) reject({message: json.message})
            nonceObject = json;
        })
        .catch((err) => {
            console.log("GetNonce Error");
            reject(`Get Nonce Error with Error code:　${err.errno}`)
        });
        // sign nonce
        const signKey = ecdsa.keyFromPrivate(privateKey, 'hex');
        const sig = ecdsa.sign(Buffer.from(nonceObject.nonce), signKey);
        const signature = Buffer.from(sig.toDER('hex')).toString();
        console.log(signature)
        // * let signatureObject = web3.eth.accounts.sign(nonceObject.nonce, key);
        // get identity token
        let jwt;
        
        await fetch(`http://${host}/authenticate`, {
            method: 'POST',
            body: JSON.stringify({
                publicKey: publicKey,
                signature: signature,
                nonce: nonceObject
            }),
            headers: { 'Content-Type': 'application/json' }
        })
        .then(res => res.json())
        .then(json => {
                if (!json.success) reject({message: json.message});
                jwt = json.token
        })
        .catch((err) => {
            console.log("Authenticate Error");
            reject(`Authenticate Error, Error code:　${err.errno}`)
        })
        // store this token
        let token = {
            activity : activity,
            org : "",
            jwt: jwt
        }
        let tokens = [token]
        await db.token.bulkCreate(tokens, { updateOnDuplicate: ["jwt", "updatedAt"] });
        reslove(token)
    })
}
let delay = async(ms) => {
    return new Promise(resolve => setTimeout(resolve, ms))
}
async function init(){
    await delay(1000);
    // get public key and private key
    let secureContext = tls.createSecureContext({
        cert: x509JSON.credentials.certificate
    });
    let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
    let cert = secureSocket.getCertificate();
    publicKey = cert.pubkey.toString('hex');

    let { prvKeyHex } = KEYUTIL.getKey(x509JSON.credentials.privateKey);
    privateKey = prvKeyHex

    console.log(publicKey.green, privateKey.green)

    console.log('start university'.green);
    /* 
     * const gateway = new Gateway();
     * const wallet = await Wallets.newFileSystemWallet('./WALLETS/wallet');
     * const connectionProfileJson = (await fs.promises.readFile('network.json')).toString();
     * const connectionProfile = JSON.parse(connectionProfileJson);
     * await gateway.connect(connectionProfile, {
     *     identity: 'admin',
     *     wallet: wallet
     * });*/
    let ccp = buildCCPOrg1();
    let universityWalletPath = path.join(__dirname, '..', '..' ,'wallet','university');
    let universityWallet = await buildWallet(Wallets, universityWalletPath);
    let gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet : universityWallet,
        identity: 'University',
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
    });
    console.log('finish gateway connection'.green);
    let certChannel = await gateway.getNetwork('cert-channel');
    certInstance =  await certChannel.getContract('certManager');
    awardInstance = await certChannel.getContract('issueAward');

    let accChannel = await gateway.getNetwork('acc-channel');
    accInstance = await accChannel.getContract('AccessControlManager');
    console.log('get contract instance successfully'.green);
    
    
    let host = "localhost:3001/E-portfolio/dataStorge/";
    try{
        let token = await getIdentityToken('toeic',host)
    }
    catch(e){
        console.log(e)
    }
    
}
router.get("/dataSharing",async function(req,res){
    let {address} = req.query;
    if(!address){
        return res.json({error:"error"})
    }
    let data = await getProtectedData(address.toLowerCase());
    if(data){
        return res.json({data:data})
    }
    else{
        return res.json({data:'error'})
    }
})
router.post("/addReviewUser",async function(req,res){
    const {address, pubkey} = req.body;
    let mapping = {};
    mapping['dataValues'] = {error:true}
    try{
        mapping = await Mapping.create(req.body);
        console.log(mapping.dataValues)
    }
    catch(e){
        console.log(e)
    }
    return res.json(mapping.dataValues)
})
init()
module.exports = router;

