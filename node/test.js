'use strict';

const Auth = require('./auth');

const auth = Auth({
  'dbPath':'./authdb',
  'secret':'secretpassword'
});

var credentials = {
  "username": "mike",
  "password": "password"
};

auth.createUser(credentials).then(created=>{

  console.log('created: ', created);

  auth.signIn(credentials).then(token=>{

    console.log('token: ', token);

    credentials.accessToken = token.accessToken;
    credentials.refreshToken = token.refreshToken;

    auth.verifyToken(credentials).then(verified=>{

      console.log('verified: ', verified);

console.log('Please wait...');
setTimeout(()=>{
      auth.refreshToken(credentials).then(async refreshed=>{

        console.log('refreshed: ', refreshed);

        credentials.accessToken = refreshed.accessToken;
        credentials.refreshToken = refreshed.refreshToken;

        credentials.newPassword = 'newpass123';

        auth.changePassword(credentials).then(changed=>{

          console.log('changed: ', changed);
          credentials.password = credentials.newPassword;

          auth.deleteUser(credentials).then(deleted=>{

            console.log('deleted: ', deleted);

            auth.deleteDB().then(console.log);

          }).catch(console.log);
        }).catch(console.log);
      });
},2000);
    }).catch(console.log);
  }).catch(console.log);
}).catch(console.log);
