const db = require("../models");
const keccak256 = require('keccak256');
const Organization = db.organization;
const Op = db.Sequelize.Op;

exports.create = async (option) => {
    return new Promise(async function(resolve,reject){
        const {organizationName,personInCharge, phone, email, UniformNumbers, type } = option;
        console.log(option)
        if (!organizationName || !personInCharge || !phone ||!email || !UniformNumbers || !type   ) {
            console.log('d')
            return null
        }
        let hashed = keccak256(UniformNumbers).toString('hex');
        let organization = {
            organizationName : organizationName,
            personInCharge : personInCharge,
            phone : phone,
            email : email,
            UniformNumbers : UniformNumbers,
            type : type,
            address : "0x",
            status : "false",
            hashed : hashed,
            pubkey : "0x"
        }
        try{
            let create_organization = await Organization.create(organization);
            resolve(create_organization);
        }
        catch
        {
            resolve(null);
        }

    })
}
exports.findOne = async (option) => {
    return new Promise(async function(resolve,reject){
        try{
            let organization = await Organization.findOne({where:option});
            resolve(organization)
            
        }
        catch{
            resolve(null)
        }
    })
    
}
exports.findAll = async (option) =>{
    return new Promise(async function(resolve,reject){
        try{
            let organizations = await Organization.findAll({where:option})
            resolve(organization)
           
        }
        catch{
            resolve(null)
        }
    })
}
exports.update = async (option) => {
    return new Promise(async function(resolve,reject){
        const {UniformNumbers} = option;
        let hashed = keccak256(UniformNumbers).toString('hex');
        let organization = await Organization.findByPk(hashed);

        organization.set({
            status: "true"
        });
        await organization.save();
        resolve(organization)
    })
}