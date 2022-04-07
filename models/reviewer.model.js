module.exports = (sequelize, Sequelize) => {
    const reviewer = sequelize.define("reviewer", {
      reviewerName :{
            type: Sequelize.STRING
      },
      address :{
        type: Sequelize.STRING,
        primaryKey: true
      },
      pubkey :{
        type: Sequelize.STRING
      }
    });
    return reviewer;
};