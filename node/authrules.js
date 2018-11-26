'use strict';

const authMethods = {

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

const authRules = [

  {
    "path":"/",
    "methods":authMethods,
    "rules":{
      "createUser":(req,kit,params)=>{
        return true;
      },
      "deleteUser":(req,kit,params)=>{
        return true;
      },
      "signIn":(req,kit,params)=>{
        return true;
      },
      "verifyToken":(req,kit,params)=>{
        return true;
      },
      "refreshToken":(req,kit,params)=>{
        return true;
      },
      "changePassword":(req,kit,params)=>{
        return true;
      }
    }
  },

];

module.exports = authRules;
