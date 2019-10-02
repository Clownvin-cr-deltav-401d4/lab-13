'use strict';

const User = require('./users-model.js');
const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  
  try {
    let [authType, authString] = req.headers.authorization.split(/\s+/);
    
    switch( authType.toLowerCase() ) {
      case 'basic': 
        return _authBasic(authString);
      case 'bearer':
        return _authBearer(authString);
      default: 
        return _authError();
    }
  }
  catch(e) {
    next(e);
  }
  
  async function _authBearer(str) {
    req.token = str;
    let tokenData = jwt.decode(str);
    req.usedPerm = !!tokenData.perm;
    let user = await User.authenticateToken(str, tokenData);
    return _authenticate(user);
  }
  
  function _authBasic(str) {
    // str: am9objpqb2hubnk=
    let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
    let bufferString = base64Buffer.toString();    // john:mysecret
    let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
    let auth = {username,password}; // { username:'john', password:'mysecret' }
    return User.authenticateBasic(auth)
      .then(user => _authenticate(user) )
      .catch(next);
  }

  function _authenticate(user) {
    if(user) {
      req.user = user;
      if (!req.usedPerm) {
        req.token = req.user.generateToken();
      }
      next();
    }
    else {
      _authError();
    }
  }
  
  function _authError() {
    next('Invalid User ID/Password');
  }
  
};