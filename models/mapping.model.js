module.exports = (sequelize, Sequelize) => {
    const mapping = sequelize.define("mapping", {
      address :{
        type: Sequelize.STRING,
        primaryKey: true
      },
      pubkey :{
        type: Sequelize.STRING
      }
    });
    return mapping;
};