'use strict';

process.env.SECRET='test';

const supergoose = require('../../supergoose.js');
const auth = require('../../../src/auth/middleware.js');
const Users = require('../../../src/auth/users-model.js');

const jwt = require('jsonwebtoken');

let users = {
  admin: {username: 'admin', password: 'password', role: 'admin'},
  editor: {username: 'editor', password: 'password', role: 'editor'},
  user: {username: 'user', password: 'password', role: 'user'},
};

beforeAll(async (done) => {
  const adminUser = await new Users(users.admin).save();
  const editorUser = await new Users(users.editor).save();
  const userUser = await new Users(users.user).save();
  done();
});


describe('Auth Middleware', () => {
  
  // admin:password: YWRtaW46cGFzc3dvcmQ=
  // admin:foo: YWRtaW46Zm9v
  
  let errorObject = 'Invalid User ID/Password';
  
  describe('user authentication', () => {
    
    let cachedToken;

    it('fails a login for a user (admin) with the incorrect basic credentials', () => {

      let req = {
        headers: {
          authorization: 'Basic YWRtaW46Zm9v',
        },
      };
      let res = {};
      let next = jest.fn();
      let middleware = auth;

      return middleware(req, res, next)
        .then(() => {
          expect(next).toHaveBeenCalledWith(errorObject);
        });

    }); // it()

    it('logs in an admin user with the right credentials', () => {

      let req = {
        headers: {
          authorization: 'Basic YWRtaW46cGFzc3dvcmQ=',
        },
      };
      let res = {};
      let next = jest.fn();
      let middleware = auth;

      return middleware(req,res,next)
        .then( () => {
          cachedToken = req.token;
          expect(next).toHaveBeenCalledWith();
        });

    }); // it()

    it('will create tokens with an expiration date if env.AUTH_TYPE is set to expiring', () => {
      process.env.AUTH_TYPE = 'expiring';
      let req = {
        headers: {
          authorization: 'Basic YWRtaW46cGFzc3dvcmQ=',
        },
      };
      let res = {};
      let next = jest.fn();
      let middleware = auth;

      return middleware(req,res,next)
        .then( () => {
          cachedToken = req.token;
          const token = jwt.decode(cachedToken);
          expect(token).toHaveProperty('exp');
        });
    });
    
  });

});
