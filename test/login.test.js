var fs = require('fs');

var json = fs.readFileSync(__dirname + '/login.test.json', 'utf8');
console.log(json);
