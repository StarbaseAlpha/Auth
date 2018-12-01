'use strict';

function Auth(api=null,localDB=null,options={}) {

  if (!options || typeof options !== 'object') {
    options = {};
  }

  if (!api) {
    throw('Starbase Channels API Client is missing.');
  }

  if (!localDB) {
    throw('Starbase Channels Database is missing.');
  }

  let db = localDB;

  let request = (method,credentials) => {
    return api.path('/').request({"method":method,"data":credentials});
  };

  let tokenPath = (options.parentChannel || '/auth/token').toString();
  let stateHandler = null;
  let authToken = null;
  let user = null;

  let stateChange = async (token) => {
    if (!token) {
      token = null;
    }
    authToken = token;
    if (db) {
      let write = await db.path(tokenPath).put({"token":authToken});
    }
    if (authToken && authToken.user) {
      user = authToken.user;
      auth.user = user;
    } else {
      user = null;
      auth.user = user;
    }
    if (stateHandler && typeof stateHandler === 'function') {
      stateHandler(authToken);
    }
  };

  let refreshToken = async () => {
    return new Promise(async (resolve,reject) => {
      if (!authToken && db) {
        let storedToken = await db.path(tokenPath).get().then(result=>{return result.data}).catch(err=>{return null;});
        if (storedToken && storedToken.token) {
          authToken = storedToken.token;
          stateChange(authToken);
        }
      }
      if (!authToken) {
        return reject({"code":400,"message":"Invalid or expired token."});
      }

      if (authToken.accessExpires < Date.now()) {
        if (authToken.refreshExpires > Date.now()) {
          request('/refreshToken',authToken).then(result=>{
            stateChange(result);
            return resolve(result.accessToken);
          }).catch(err=>{
            stateChange(null);
            return reject(err);
          });
        } else {
          stateChange(null);
          return reject({"code":400,"message":"Invalid or expired token."});
        }
      } else {
        return resolve(authToken.accessToken);
      }
      
    });
  };

  let auth = {};
  auth.user = null;

  auth.getToken = () => {
    return refreshToken();
  };

  auth.onStateChange = (cb) => {
    stateHandler = cb;
  };

  auth.createUser = (username,password) => {
    return new Promise((resolve,reject) => {
      request('createUser',{"username":username,"password":password}).then(resolve).catch(reject);
    });
  };

  auth.deleteUser = (username,password) => {
    return new Promise((resolve,reject) => {
      request('deleteUser',{"username":username,"password":password}).then(resolve).catch(reject);
    });
  };

  auth.changePassword = (username,password,newPassword) => {
    return new Promise((resolve,reject) => {
      request('changePassword',{"username":username,"password":password,"newPassword":newPassword}).then(resolve).catch(reject);
    });
  };

  auth.signIn = (username,password) => {
    return new Promise((resolve,reject) => {
      request('signIn',{"username":username,"password":password}).then(token=>{
        stateChange(token);
        resolve(token);
      }).catch(err=>{
        reject(err);
      });
    });
  };

  auth.signOut = () => {
    return new Promise((resolve,reject) => {
      stateChange(null);
      resolve({"message":"Signed out."});
    });
  };

  if (db) {
    auth.getToken().catch(err=>{});
  }

  return auth;

}
