var Buffer = require('buffer').Buffer
var elliptic = require('elliptic');
var ecies = require("eth-ecies");
var {encrypt } = require("eth-sig-util")
var {KEYUTIL} = require('jsrsasign');
var {ethers} = require("ethers")

const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);

function encrypt(publicKey, data) {
    let userPublicKey = Buffer.from(publicKey, 'hex');
    let bufferData = Buffer.from(data);
    let encryptedData = ecies.encrypt(userPublicKey, bufferData);
    return encryptedData.toString('base64')
}



/*
function decrypt(privateKey, encryptedData) {
    let userPrivateKey = Buffer.from(privateKey, 'hex');
    let bufferEncryptedData = Buffer.from(encryptedData, 'base64');
    let decryptedData = ecies.decrypt(userPrivateKey, bufferEncryptedData);
    
    return decryptedData.toString('utf8');
}*/
global.window.Buffer = Buffer
global.window.ecdsa = ecdsa
global.window.encrypt_s = encrypt
global.window.KEYUTIL = KEYUTIL
global.window.ethers = ethers




