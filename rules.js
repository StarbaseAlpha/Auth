'use strict';

const methods = {

  "createUser":(body,kit,params) => {
    return kit.auth.createUser(body.data);
  },
  "deleteUser":(body,kit,params) => {
    return kit.auth.deleteUser(body.data);
  },
  "signIn":(body,kit,params) => {
    return kit.auth.signIn(body.data);
  },
  "verifyToken":(body,kit,params) => {
    return kit.auth.verifyToken(body.data);
  },
  "refreshToken":(body,kit,params) => {
    return kit.auth.refreshToken(body.data);
  },
  "changePassword":(body,kit,params) => {
    return kit.auth.changePassword(body.data);
  }

};

const rule = (body,kit,params) =>{
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
