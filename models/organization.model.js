module.exports = (sequelize, Sequelize) => {
    const organization = sequelize.define("organization", {
      organizationName :{
        type: Sequelize.STRING
      },
      personInCharge :{
        type: Sequelize.STRING
      },
      phone :{
        type: Sequelize.STRING,
      },
      email :{
        type: Sequelize.STRING,
      },
      UniformNumbers :{
        type: Sequelize.STRING,
      },
      address: {
        type: Sequelize.STRING
      },
      type: {
        type: Sequelize.STRING
      },
      status :{
        type: Sequelize.STRING
      },
      hashed:{
        type: Sequelize.STRING,
        primaryKey: true
      },
      pubkey:{
        type: Sequelize.STRING,
      }
    });
    return  organization;
};