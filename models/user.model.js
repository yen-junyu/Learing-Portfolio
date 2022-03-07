module.exports = (sequelize, Sequelize) => {
    const user = sequelize.define("user", {
      IDNumber :{
        type: Sequelize.STRING
      },
      userName :{
        type: Sequelize.STRING
      },
      birth :{
        type: Sequelize.STRING,
      },
      email :{
        type: Sequelize.STRING,
      },
      phone :{
        type: Sequelize.STRING,
      },
      address: {
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
    return user;
};