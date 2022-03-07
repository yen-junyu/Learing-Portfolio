var express = require('express');
var router = express.Router();

const applyCert = require("../controllers/applyCert.controller.js");

router.post("/", applyCert.create);
router.get("/", applyCert.findAll);
router.post("/update",applyCert.update);

module.exports = router;

// Retrieve all Tutorials
//router.get("/", token.findAll);

// Delete a Tutorial with id
//router.delete("/:identity/:org", token.delete);

