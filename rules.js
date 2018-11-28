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

const Rules = [

  {
    "path":"/createUser",
    "methods":{
      "put":methods.createUser
    },
    "rules":{
      "put":(req,kit,params) => {
        return true;
      }
    }
  },

  {
    "path":"/deleteUser",
    "methods":{
      "put":methods.deleteUser
    },
    "rules":{
      "put":(req,kit,params) => {
        return true;
      }
    }
  },

  {
    "path":"/signIn",
    "methods":{
      "put":methods.signIn
    },
    "rules":{
      "put":(req,kit,params) => {
        return true;
      }
    }
  },

  {
    "path":"/verifyToken",
    "methods":{
      "put":methods.verifyToken
    },
    "rules":{
      "put":(req,kit,params) => {
        return true;
      }
    }
  },

  {
    "path":"/refreshToken",
    "methods":{
      "put":methods.refreshToken
    },
    "rules":{
      "put":(req,kit,params) => {
        return true;
      }
    }
  },

  {
    "path":"/changePassword",
    "methods":{
      "put":methods.changePassword
    },
    "rules":{
      "put":(req,kit,params) => {
        return true;
      }
    }
  },

];

module.exports = Rules;
