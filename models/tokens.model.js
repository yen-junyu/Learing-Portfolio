module.exports = (sequelize, Sequelize) => {
    const Token = sequelize.define("token", {
      activity: {
        type: Sequelize.STRING,
        primaryKey: true
      },
      org: {
        type: Sequelize.STRING,
        primaryKey: true
      },
      jwt: {
        type: Sequelize.STRING
      }
    });
  
    return Token;
  };