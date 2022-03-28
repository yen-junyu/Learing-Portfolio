var Buffer = require('buffer').Buffer
var elliptic = require('elliptic');
var ecies = require("eth-ecies");
var {encrypt } = require("eth-sig-util")
var {KEYUTIL} = require('jsrsasign');
var {ethers} = require("ethers")

const EC = elliptic.ec;
const ecdsaCurve = elliptic.curves['p256'];
const ecdsa = new EC(ecdsaCurve);


global.window.Buffer = Buffer
global.window.ecdsa = ecdsa
global.window.encrypt_s = encrypt
global.window.KEYUTIL = KEYUTIL
global.window.ethers = ethers




