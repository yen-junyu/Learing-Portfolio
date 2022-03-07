const db = require("../models");
const keccak256 = require('keccak256');
const User = db.user;
const Op = db.Sequelize.Op;

exports.create = async (option) => {
    const {IDNumber,userName, birth, email, phone} = option;
    console.log(option)
    if (!IDNumber || !userName || !birth || !email || !phone ) {
        return res.status(400).send({
            message: "IDNumber, userName, birth, email ,phone"
          });
    }
    let hashed = keccak256(IDNumber).toString('hex');
    let user = {
        IDNumber : IDNumber,
        userName : userName,
        birth : birth,
        email : email,
        phone : phone,
        address : "0x",
        status : "false",
        hashed : hashed,
        pubkey : "0x"
    }
    try{
        let create_user = await User.create(user);
        return create_user;
    }
    catch
    {
        return null
    }
}
exports.findOne = async (option) => {
    try{
        let user = await User.findOne({where:option});
        return user;
    }
    catch{
        return null;
    }
}
exports.findAll = async (option) =>{
    try{
        let users = await User.findAll({where:option})
        return users;
    }
    catch{
        return null
    }
}