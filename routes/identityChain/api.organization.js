var express = require('express');

var router = express.Router();

const Organization = require("../../controllers/organization.controller");

router.post("/", async function(req,res){
    console.log(req.body)
    let organization = await Organization.create(req.body);
    
    if(organization){
        req.flash('info', 'Created successfully.');
        res.redirect('/identityChain/register');
    }
    else
    {
        req.flash('info', 'Created incorrectly.');
        res.redirect('/identityChain/register');
    }
});

module.exports = router;

