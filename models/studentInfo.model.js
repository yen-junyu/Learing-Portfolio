module.exports = (sequelize, Sequelize) => {
    const studentInfo = sequelize.define("studentInfo", {
      account :{
        type: Sequelize.STRING,
      },
      publicKey:{
        type: Sequelize.STRING
      },
      Name:{
        type: Sequelize.STRING
      },
      highSchool :{
        type: Sequelize.STRING
      }
    });
    return studentInfo;
};