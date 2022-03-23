const db = require("../models");
const ApplyCert = db.applyCert;
const Op = db.Sequelize.Op;


exports.create = async (option) => {
    return new Promise(async function(resolve,reject){
       
        const {account,activityName, number, type, API} = option;
        if (!account || !activityName || !number || !type || !API ) {
            reject("lost something.")
        }
        
        let applyCert = {
            account : account,
            activityName : activityName,
            number : number,
            type : type,
            API : API,
            status : "false"
        }
        try{
            applyCert = await ApplyCert.create(applyCert);
            resolve(applyCert);
        }
        catch{
            reject("create error")
        }
        
    })
}
exports.findOne = async (option) => {
    return new Promise(async function(resolve,reject){
        let applyCert = await ApplyCert.findOne({where:option});
        resolve(applyCert);
    })
}
exports.update = async (option) => {
    return new Promise(async function(resolve,reject){
        const {activityName} = option;
        if(!activityName){
            return "missing activityName."
        }
        let applyCert = await ApplyCert.findByPk(activityName);
        applyCert.set({
            status: "true"
        });
        await applyCert.save();
        resolve(applyCert)
    })
}
exports.findAll = async (option) =>{
    return new Promise(async function(resolve,reject){
        let applyCert = await ApplyCert.findAll({where:option});
        resolve(applyCert);
    })
}