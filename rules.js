'use strict';

const methods = {

  "createUser":(req,kit,params) => {
    return kit.auth.createUser(req.data);
  },
  "deleteUser":(req,kit,params) => {
    return kit.auth.deleteUser(req.data);
  },
  "signIn":(req,kit,params) => {
    return kit.auth.signIn(req.data);
  },
  "verifyToken":(req,kit,params) => {
    return kit.auth.verifyToken(req.data);
  },
  "refreshToken":(req,kit,params) => {
    return kit.auth.refreshToken(req.data);
  },
  "changePassword":(req,kit,params) => {
    return kit.auth.changePassword(req.data);
  }

};

const rule = (req,kit,params) =>{
  return true;
};

const Rules = [

  {
    "path":"/",
    "methods":{
      "createUser":methods.createUser,
      "signIn":methods.signIn,
      "verifyToken":methods.verifyToken,
      "deleteUser":methods.deleteUser,
      "refreshToken":methods.refreshToken,
      "changePassword":methods.changePassword,
    },
    "rules":{
      "createUser":rule,
      "deleteUser":rule,
      "signIn":rule,
      "verifyToken":rule,
      "refreshToken":rule,
      "changePassword":rule
    }
  }

];

module.exports = Rules;
