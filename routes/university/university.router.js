var express = require('express');
var router = express.Router();
var fs = require('fs');
var path = require('path')
var fetch = require('node-fetch');
var db = require("../../models");
var Web3 = require('web3');
var Mapping = require("../../controllers/mapping.controller")

// some ecdsa tools
let tls = require('tls');
let net = require('net');
const { KEYUTIL } = require('jsrsasign');
const elliptic = require('elliptic')
const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);


var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
const web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
const org_address = config.org_info.university.address; // org0
const key = config.org_info.university.key; // org0
var x509JSON = JSON.parse(fs.readFileSync(`./wallet/university/${org_address}.id`, 'utf-8'));

// debug
var colors = require('colors');


// hyperledger connection 
var { Gateway, Wallets} = require('fabric-network');
var { buildCCPOrg1, buildWallet } = require('../../Util/AppUtil.js');
var certInstance, accInstance , awardInstance;
var publicKey,privateKey;
var tokens = {}
var hosts = {}

let getProtectedData = async(address) =>{
    return new Promise(async function(resolve,reject){
        try{
            let data = {}
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
            console.log(attrs.yellow)
            if(attrs.length==0){
                resolve(null)
            }
            let awards = []
            // fetch data
            for(var i=0;i<attrs.length;i++){
                //highschool data  
                if(attrs[i].includes('SchoolGrade')){
                    await fetch(`http://${hosts[attrs[i]]}/getSchoolData?user=${pubkey}`,{
                        headers: { 'x-access-token': tokens[attrs[i]].jwt }
                    })
                    .then(res => res.json())
                    .then(json => {
                        console.log(json)
                        if(json.status){
                            data['schoolData'] = json
                        }
                    })
                }
                else{
                    
                    await fetch(`http://${accessLinks[attrs[i]]}`,{
                        headers: { 'x-access-token': tokens[attrs[i]].jwt }
                    })
                    .then(res => res.json())
                    .then(json => {
                        if(json.status){
                            awards.push(json)
                        }
                        else{
                            throw `fetch ${attrs[i]} error.`
                        }
                       
                    })
                    .catch((err) => {
                        console.log(err)
                        console.log("Authenticate Error");
                        reject(`Authenticate Error, Error code:　${err.errno}`)
                    })
                }
            }
            data['award'] = awards;
            return resolve(data)
        }
        catch(e){
            console.log(e)
            resolve(null)
        } 
    })
}
let getIdentityToken = async(activity, host) => {
    return new Promise(async function(reslove,reject){
        // get nonce
        let nonceObject;
        await fetch(`http://${host}/auth/nonce?org=${org_address}`)
        .then(res => res.json())
        .then(json => {
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
        tokens[activity] = token;
        await db.token.bulkCreate(tokens, { updateOnDuplicate: ["jwt", "updatedAt"] });
        reslove(token)
    })
}
let delay = async(ms) => {
    return new Promise(resolve => setTimeout(resolve, ms))
}
async function init(){
    await delay(3000);
    // get public key and private key
    let secureContext = tls.createSecureContext({
        cert: x509JSON.credentials.certificate
    });
    let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
    let cert = secureSocket.getCertificate();
    publicKey = cert.pubkey.toString('hex');

    let { prvKeyHex } = KEYUTIL.getKey(x509JSON.credentials.privateKey);
    privateKey = prvKeyHex
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
        identity: org_address,
        discovery: { enabled: true, asLocalhost: true } // using asLocalhost as this gateway is using a fabric network deployed locally
    });
    console.log('finish gateway connection'.green);
    let certChannel = await gateway.getNetwork('cert-channel');
    certInstance =  await certChannel.getContract('certManager');
    awardInstance = await certChannel.getContract('issueAward');

    let accChannel = await gateway.getNetwork('acc-channel');
    accInstance = await accChannel.getContract('AccessControlManager');
    console.log('get contract instance successfully'.green);
    
    for(var key in config.org_info) {
        if(config.org_info[key].hasOwnProperty('host')){
            let host = config.org_info[key].host;
            let activityName = config.org_info[key].activityName;
            hosts[activityName] = host
            try{
                let token = await getIdentityToken(activityName, host);
            }
            catch(e){
                console.log(`get token ${activityName} error`)
            }
            
        }
    }
}
router.get("/reviewer", async function(req,res){
    let {address} = req.query;
    if(!address){
        return res.json({error:"error"})
    }
    let data = await getProtectedData(address.toLowerCase());
    if(data){
        let schoolData = data["schoolData"];
        let award = data["award"]
        return res.render('E-portfolio/university/reviewer.ejs',{"schoolData":schoolData,"award":award});
    }
    else{
        return res.render('E-portfolio/university/reviewer.ejs',{"schoolData":null,"award":null});
    }
})
router.get("/dataSharing",async function(req,res){
    let {address} = req.query;
    if(!address){
        return res.json({error:"error"})
    }
    
    let data = await getProtectedData(address.toLowerCase());
    console.log(data)
    
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
    mapping['dataValues'] = { error:true}
    try{
        mapping = await Mapping.create(req.body);
       
    }
    catch(e){
        console.log(e)
    }
    return res.json(mapping.dataValues)
})
init()
module.exports = router;

