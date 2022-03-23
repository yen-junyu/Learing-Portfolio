module.exports = (sequelize, Sequelize) => {
  const applyCert = sequelize.define("applyCert", {
    account :{
      type: Sequelize.STRING,
    },
    activityName: {
      type: Sequelize.STRING,
      primaryKey: true
    },
    number: {
      type: Sequelize.STRING
    },
    type:{
      type: Sequelize.STRING
    },
    API: {
      type: Sequelize.STRING
    },
    status :{
      type: Sequelize.STRING
    }
  });
  return applyCert;
};