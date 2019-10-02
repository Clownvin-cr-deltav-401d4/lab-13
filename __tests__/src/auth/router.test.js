'use strict';

process.env.SECRET='test';

const jwt = require('jsonwebtoken');

const server = require('../../../src/app.js').server;
const supergoose = require('../../supergoose.js');

const mockRequest = supergoose(server);

let users = {
  admin: {username: 'admin', password: 'password', role: 'admin'},
  editor: {username: 'editor', password: 'password', role: 'editor'},
  user: {username: 'user', password: 'password', role: 'user'},
};


describe('Auth Router', () => {
  
  Object.keys(users).forEach( userType => {
    
    describe(`${userType} users`, () => {
      
      let encodedToken;
      let id;
      let bearer;
      
      it('can create one', () => {
        return mockRequest.post('/signup')
          .send(users[userType])
          .expect(200)
          .then(results => {
            bearer = results.text;
            var token = jwt.decode(results.text);
            id = token.id;
            encodedToken = results.text;
            expect(token.id).toBeDefined();
          });
      });

      it('can signin with basic', () => {
        return mockRequest.post('/signin')
          .auth(users[userType].username, users[userType].password)
          .expect(200)
          .then(results => {
            bearer = results.text;
            var token = jwt.decode(results.text);
            expect(token.id).toEqual(id);
          });
      });

      it('can signin with bearer', () => {
        return mockRequest.post('/signin')
          .set('Authorization', `Bearer ${bearer}`)
          .expect(200)
          .then(results => {
            bearer = results.text;
            var token = jwt.decode(results.text);
            expect(token.id).toEqual(id);
          });
      });

      it('new tokens will expire if AUTH_TYPE is set to expiring', () => {
        process.env.AUTH_TYPE = 'expiring';
        process.env.EXPIRATION_TIME = '15m';
        return mockRequest.post('/signin')
          .set('Authorization', `Bearer ${bearer}`)
          .expect(200)
          .then(results => {
            bearer = results.text;
            var token = jwt.decode(results.text);
            console.log(token);
            expect(token.id).toEqual(id);
            expect(token).toHaveProperty('exp');
          });
      });

      it('can create a permanent token with /key', () => {
        return mockRequest.post('/key')
          .set('Authorization', `Bearer ${bearer}`)
          .expect(200)
          .then(results => {
            bearer = results.text.split(': ')[1];
            console.log(bearer);
            var token = jwt.decode(bearer);
            expect(token.id).toEqual(id);
            expect(token).toHaveProperty('perm');
          });
      });

      it('new tokens will be single-use if AUTH_TYPE is set to single-use', () => {
        process.env.AUTH_TYPE = 'single-use';
        return mockRequest.post('/signin')
          .auth(users[userType].username, users[userType].password)
          .expect(200)
          .then(async (results) => {
            bearer = results.text;
            console.log(jwt.decode(bearer));
            return mockRequest.post('/signin')
              .set('Authorization', `Bearer ${bearer}`)
              .expect(200)
              .then(results => {
                return mockRequest.post('/signin')
                  .set('Authorization', `Bearer ${bearer}`)
                  .expect(500);
            });
          });
      });
    });
    
  });
  
});
