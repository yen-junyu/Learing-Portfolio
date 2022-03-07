const db = require("../models");
const ApplyCert = db.applyCert;
const Op = db.Sequelize.Op;

exports.create = (req, res) => {    
    const {address,pubkey, activityName, quantity, description, api} = req.body;
    
    if (!address || !activityName || !quantity || !description || !api ) {
        return res.status(400).send({
            message: "name, quantity, description, api"
          });
    }
    let applyCert = {
        address : address,
        pubkey : pubkey,
        activityName : activityName,
        quantity : quantity,
        description : description,
        api : api,
        status : "false",
        pw : "false"
    }
    ApplyCert.create(applyCert).then(data => {
        console.log(data)
        return res.send(data)
    })
    .catch(err => {
        return res.send("err")
    });
}
exports.findAll = async (req , res) => {
    let data = await ApplyCert.findAll({ where: true});
    return  res.send(data)
}
exports.update = async (req , res) => {
    const {address} = req.body;
    if(!address){
        return res.status(400).send({
            message: "address miss"
        });
    }
    let data = await ApplyCert.findByPk(address);
    data.set({
        status: "true",
    });
    await data.save();
    if (data) {
        return res.send(data);
    }
    else {
        return res.status(500).send("Not found.");
    }
}