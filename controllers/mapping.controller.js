const db = require("../models");
const keccak256 = require('keccak256');
const Mapping = db.mapping;
const Op = db.Sequelize.Op;

exports.create = async (option) => {
    return new Promise(async function(resolve,reject){
        const {address,pubkey} = option;
        if (!address || !pubkey) {
            return reject("address or pukey is empty.")
        }
        let mapping = {
            address: address,
            pubkey: pubkey
        }
        try{
            let new_mapping = await Mapping.create(mapping);
            return resolve(new_mapping);
        }
        catch{
            return reject(null)
        }
    })
}
exports.findOne = async (option) => {
    return new Promise(async function(resolve,reject){
        try{
            let mapping = await Mapping.findOne({where:option});
            resolve(mapping);
        }
        catch(e){
            reject(e);
        }
    })
}
exports.findAll = async (option) => {
    return new Promise(async function(resolve,reject){
        try{
            let mapping = await Mapping.findAll({where:option});
            resolve(mapping);
        }
        catch{
            reject(null);
        }
    })
}