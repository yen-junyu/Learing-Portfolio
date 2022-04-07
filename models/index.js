const dbConfig = require("../config/db.config.js");

const Sequelize = require("sequelize");
const sequelize = new Sequelize({
    dialect: dbConfig.dialect,
    storage: dbConfig.storage
});

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.applyCert = require("./applyCert.model.js")(sequelize, Sequelize);
db.user = require("./user.model.js")(sequelize,Sequelize);
db.mapping = require("./mapping.model.js")(sequelize,Sequelize);
db.organization = require("./organization.model.js")(sequelize,Sequelize);

db.nonce = require("./nonce.model.js")(sequelize, Sequelize);
db.token = require("./tokens.model.js")(sequelize, Sequelize);
db.reviewer = require("./reviewer.model.js")(sequelize, Sequelize);

module.exports = db;
