module.exports = (sequelize, Sequelize) => {
    const awards = sequelize.define("awards", {
      publicKey :{
        type: Sequelize.STRING
      },
      data:{
        type: Sequelize.STRING
      },
      activity:{
        type: Sequelize.STRING
      },
      type:{
        type: Sequelize.STRING
      }
    });
    return awards;
};