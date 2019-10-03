# LAB - 13

## Bearer authentication, expiring and single use tokens, and permanent tokens

### Author: Calvin Hall

### Links and Resources
* [submission PR](https://github.com/Clownvin-cr-deltav-401d4/lab-13/pull/1)
* [travis](https://www.travis-ci.com/Clownvin-cr-deltav-401d4/lab-13)

## Modules
### Middleware
Exports a single function which will authenticate a request, and append a web token if it is authorized.

### Router
Handles /signup, /signin and /key post requests.

### users-model
Creates and exports a mongoose model for users. Handles most of the JWT token creation as well.

### 404
Handles 404s

### 500
Handles errors.

#### Running the app
* `npm start`
  
#### Tests
* `npm test`