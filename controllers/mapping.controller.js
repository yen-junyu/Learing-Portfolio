const db = require("../models");
const keccak256 = require('keccak256');
const Mapping = db.mapping;
const Op = db.Sequelize.Op;

exports.create = async (option) => {
    console.log(option)
    const {address,pubkey} = option;
    if (!address || !pubkey) {
        return "address or pukey is empty."
    }
    let mapping = {
        address: address,
        pubkey: pubkey
    }
    try{
        let new_mapping = await Mapping.create(mapping);
        return new_mapping;
    }
    catch{
        return null
    }
}
exports.findOne = async (option) => {
    return new Promise(async function(resolve,reject){
        let mapping = await Mapping.findOne({where:option});
        resolve(mapping);
    })
}