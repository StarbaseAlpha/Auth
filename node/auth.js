'use strict';

const theRules = require('@starbase/therules');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const rules = require(__dirname + path.sep + '..' + path.sep + 'rules');

function Auth(db, secret, options={}) {
  if (!options || typeof options !== 'object') {
    options = {};
  }

  let SECRET = (secret || '').toString();

  if (!db) {
    throw("Starbase Channels Database object is missing.");
  }

  if (!SECRET || typeof SECRET !== 'string' || SECRET.length < 1) {
    throw("A secret string for token signing is required.");
  }

  let parentChannel = (options.parentChannel || "/auth/users").toString();
  let accessTokenExpires = options.accessTokenExpires || parseInt(1000 * 60 * 10);
  let refreshTokenExpires = options.refreshTokenExpires || parseInt(1000 * 60 * 60 * 24 * 7); 
  let passwordRounds = options.passwordRounds || 8;

  let createToken = async (user) => {
    let newToken = {};
    newToken.user = {"username":user.username};
    newToken.accessExpires = Date.now() + parseInt(accessTokenExpires);
    newToken.refreshExpires = Date.now() + parseInt(refreshTokenExpires);
    newToken.accessToken = await jwt.sign({"exp":newToken.accessExpires / 1000,"user":newToken.user},SECRET);
    newToken.refreshToken = await jwt.sign({"exp":newToken.refreshExpires / 1000,"user":newToken.user},SECRET + user.password);
    return newToken;
  };

  let auth = {};

  auth.express = () => {
    return (req,res) => {
      let body = {};
      if (req.body && typeof req.body === 'object') {
        body = req.body;
      }
      let kit = {
        "auth":auth
      };
      theRules(rules,body,kit).then(result=>{
        res.json(result);
      }).catch(err=>{
        res.status(err.code||400).json({"code":err.code||400,"message":err.message||err.tostring()||"ERROR!"});
      });
    };
  };

  auth.createUser = async (credentials) => {

    let username = (credentials.username || "").toString().toLowerCase();
    let password = (credentials.password || "").toString();

    if (!username || username.length < 2 || username.length > 16 || username[0].replace(/[^a-z]/g,'') !== username[0] || username.replace(/[^a-z0-9]/g,'') !== username) {
      return Promise.reject({
        "code":400, "message": "Invalid username. Usernames must contain 2 to 16 English letters and numbers and must start with an english letter."
      });
    }

    if (!password || password.length < 8 || password.length > 72) {
      return Promise.reject({
        "code":400, "message": "Invalid password. Password must be between 8 and 72 characters in length."
      });
    }

    let exists = await db.path(parentChannel).path(username).get().catch(err=>{return false;});
    if (exists) {
      return Promise.reject({
        "code":409, "message": "Username is unavailable."
      });
    }

    let hash = await bcrypt.hash(password,passwordRounds);
    let user = {"username":username,"password":hash};
    return db.path(parentChannel).path(username).put(user).then(result=>{
      return Promise.resolve({"message":"User created.","user":{"username":username}});
    }).catch(err=>{
      return Promise.reject({"code":400,"message":"Error creating user. " + err.message||err.toString()});
    });

  };

  auth.deleteUser = async (credentials) => {

    let username = (credentials.username || "").toString().toLowerCase();
    let password = (credentials.password || "").toString();

    let exists = await db.path(parentChannel).path(username).get().catch(err=>{return false;});

    if (!exists) {
      return Promise.reject({
        "code":400, "message": "Invalid username or password."
      });
    }

    let verified = await bcrypt.compare(password,exists.data.password);

    if (!verified) {
      return Promise.reject({
        "code":400, "message": "Invalid username or password."
      });
    }

    return db.path(parentChannel).path(username).del().then(deleted=>{
      return Promise.resolve({"message":"User deleted"});
    }).catch(err=>{
      return Promise.reject({
        "code":400, "message": "Invalid username or password."
      });
    });

  };

  auth.signIn = async (credentials) => {

    let username = (credentials.username || "").toString().toLowerCase();
    let password = (credentials.password || "").toString();

    if (!username || !password) {
      return Promise.reject({"code":400, "message": "Invalid username or password."});
    }

    let exists = await db.path(parentChannel).path(username).get().catch(err=>{return false;});

    if (!exists) {
      return Promise.reject({
        "code":400, "message": "Invalid username or password."
      });
    }

    let verified = await bcrypt.compare(password,exists.data.password);

    if (!verified) {
      return Promise.reject({
        "code":400, "message": "Invalid username or password."
      });
    }

    let newToken = createToken(exists.data);
    return Promise.resolve(newToken);
  };

  auth.verifyToken = async (credentials) => {

    let accessToken = (credentials.accessToken || "").toString();

    let valid = false;
    try {
      valid = jwt.verify(accessToken,SECRET);
    } catch(err) {
      return Promise.reject({"code":400,"message":"Invalid or expired access token."});
    }

    return {"user":valid.user};

  };

  auth.refreshToken = async (credentials) => {
    let refreshToken = (credentials.refreshToken || "").toString();

    let decoded = jwt.decode(refreshToken);
    let username = "";
    if (decoded && decoded.user.username) {
      username = decoded.user.username;
    }

    let exists = await db.path(parentChannel).path(username).get().catch(err=>{return false;});

    if (!exists) {
      return Promise.reject({
        "code":404, "message": "User not found."
      });
    }

    let valid = false;
    try {
      valid = await jwt.verify(refreshToken,SECRET + exists.data.password);
    } catch(err) {
      // do nothing
    }

    if (!valid) {
      return Promise.reject({
        "code":400, "message": "Invalid or expired refresh Token."
      });      
    }

    let newToken = await createToken(exists.data);
    return Promise.resolve(newToken);

  };

  auth.changePassword = async (credentials) => {

    let username = (credentials.username || "").toString().toLowerCase();
    let password = (credentials.password || "").toString();
    let newPassword = (credentials.newPassword|| '').toString();

    if (!newPassword || newPassword.length < 8 || newPassword.length > 72) {
      return Promise.reject({
        "code":400, "message": "New password is invalid."
      });
    }

    let exists = await db.path(parentChannel).path(username).get().catch(err=>{return false;});

    if (!exists) {
      return Promise.reject({
        "code":404, "message": "User not found."
      });
    }

    let verified = await bcrypt.compare(password,exists.data.password);

    if (!verified) {
      return Promise.reject({
        "code":400, "message": "Current password is invalid."
      });
    }

    let hash = await bcrypt.hash(newPassword,passwordRounds);
    return db.path(parentChannel).path(exists.data.username).put({
      "username":exists.data.username,
      "password":hash
    }).then(changed=>{
      return Promise.resolve({"message":"Password changed."});
    });

  };

  return auth;

}

module.exports = Auth;
