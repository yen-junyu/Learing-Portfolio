var Buffer = require('buffer').Buffer
var elliptic = require('elliptic')
var {KEYUTIL} = require('jsrsasign');
var ecies = require("eth-ecies");
var {encrypt } = require("eth-sig-util")
var {ethers} = require("ethers")

function encrypt(publicKey, data) {
    let userPublicKey = Buffer.from(publicKey, 'hex');
    let bufferData = Buffer.from(data);
    let encryptedData = ecies.encrypt(userPublicKey, bufferData);
    return encryptedData.toString('base64')
}

function decrypt(privateKey, encryptedData) {
    let userPrivateKey = Buffer.from(privateKey, 'hex');
    let bufferEncryptedData = Buffer.from(encryptedData, 'base64');
    let decryptedData = ecies.decrypt(userPrivateKey, bufferEncryptedData);
    
    return decryptedData.toString('utf8');
}

global.window.Buffer = Buffer
global.window.elliptic = elliptic
global.window.KEYUTIL= KEYUTIL
global.window.ecies = ecies
global.window.encrypt_s = encrypt
global.window.ethers = ethers



