var express = require('express');
var fs = require('fs');
var Web3 = require('web3');
// session
var passport = require('passport');
var LocalStrategy = require('passport-local');
// tool
var keccak256 = require('keccak256');
var config = JSON.parse(fs.readFileSync('./config/server_config.json', 'utf-8'));
var identityManger = JSON.parse(fs.readFileSync('./contracts/identityChain/identityManager.json', 'utf-8'));
var contract_address = config.contracts.identityManagerAddress;
var web3 = new Web3(new Web3.providers.WebsocketProvider(config.web3_provider));
var router = express.Router();

//sub router
var highSchool = require("./highSchool/highSchool.router")

router.use('/highSchool',highSchool);

module.exports = router;




