'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const singleUses = [];

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', async function() {
  if (this.isModified('password'))
  {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

users.statics.authenticateToken = async function(token, tokenData) {
  try {
    
    let user = await this.findById(tokenData.id);

    if (user && jwt.verify(token, user.generateSecret())) {
      if (!tokenData.perm && process.env.AUTH_TYPE === 'single-use') {
        if (!singleUses.includes(token)) {
          return null;
        } else {
          singleUses.splice(singleUses.indexOf(token), 1);
        }
      }
      return user;
    }
  } catch (error) {
    console.log(error);
  }
  return null;
};

users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
    .then(user => {
      if( !user ) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch( error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({username, password, email});
    });

};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password))
    .catch(error => {throw error;});
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};

users.methods.generateToken = function(perm) {

  let options = {
  };

  if (!perm && !process.env.AUTH_TYPE || process.env.AUTH_TYPE === 'expiring') {
    options.expiresIn = process.env.EXPIRATION_TIME || '15m'; //30 seconds?
  }

  let payload = {
    id: this._id,
    role: this.role,
  };

  if (!perm && process.env.AUTH_TYPE === 'single-use') {
    payload.rand = (Math.random() * Number.MAX_VALUE) + 1;
  }

  if (perm) {
    payload.perm = true;
    console.log(`Generating new PERMANENT token...`);
  } else {
    console.log(`Generating new ${process.env.AUTH_TYPE} token...`);
  }

  console.log(`Using secret: ${this.generateSecret()}`);
  const encrypted = jwt.sign(payload, this.generateSecret(), options);
  console.log(`Encrypted: ${encrypted}`);
  if (!perm && process.env.AUTH_TYPE === 'single-use') {
    singleUses.push(encrypted);
  }
  return encrypted;
};

users.methods.generateSecret = function() {
  return (process.env.SECRET || 'changeit') + this.password;
};

module.exports = mongoose.model('users', users);
