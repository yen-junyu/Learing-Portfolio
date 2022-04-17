module.exports = (sequelize, Sequelize) => {
    const rank = sequelize.define("rank", {
      semester :{
        type: Sequelize.STRING,
      },
      account:{
        type: Sequelize.STRING
      },
      rank:{
        type: Sequelize.STRING
      }
    });
    return rank;
};