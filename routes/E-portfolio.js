var express = require('express');
// tool
var router = express.Router();

//sub router
var highSchool = require("./highSchool/highSchool.router")
var educationMinistry = require("./educationMinistry/educationMinistry.router")
var localEducationMinistry = require("./localEducationMinistry/localEducationMinistry.router")


router.use('/highSchool',highSchool);
router.use('/educationMinistry',educationMinistry)
router.use('/localEducationMinistry',localEducationMinistry)

module.exports = router;




