var express = require('express');
// tool
var router = express.Router();

//sub router
var highSchool = require("./highSchool/highSchool.router")
var educationMinistry = require("./educationMinistry/educationMinistry.router")
var localEducationMinistry = require("./localEducationMinistry/localEducationMinistry.router")
var dataStorge = require("./dataStorge/dataStorge.router")
var university = require("./university/university.router")

router.use('/highSchool',highSchool);
router.use('/educationMinistry',educationMinistry)
router.use('/localEducationMinistry',localEducationMinistry)
router.use('/dataStorge',dataStorge)
router.use('/university',university)


module.exports = router;




