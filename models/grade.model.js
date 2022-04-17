module.exports = (sequelize, Sequelize) => {
    const grade = sequelize.define("grade", {
      account :{
        type: Sequelize.STRING,
      },
      semester:{
        type: Sequelize.STRING
      },
      className:{
        type: Sequelize.STRING
      },
      grade :{
        type: Sequelize.STRING
      }
    });
    return grade;
};