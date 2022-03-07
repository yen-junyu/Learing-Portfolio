module.exports = (sequelize, Sequelize) => {
  const applyCert = sequelize.define("applyCert", {
    address :{
      type: Sequelize.STRING,
      primaryKey: true
    },
    pubkey : {
      type: Sequelize.STRING,
    },
    activityName: {
      type: Sequelize.STRING
    },
    quantity: {
      type: Sequelize.STRING
    },
    description: {
      type: Sequelize.STRING
    },
    api: {
      type: Sequelize.STRING
    },
    pw:{
      type: Sequelize.STRING
    },
    status :{
      type: Sequelize.STRING
    }
  });
  return applyCert;
};