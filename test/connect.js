var connect = require('connect'),
	fbsdk = require('../lib/facebook');

var APP_ID = '117743971608120';
var SECRET = '943716006e74d9b9283d4d5d8ab93204';

connect()
	.use(fbsdk.facebook({
		appId: APP_ID,
		secret: SECRET
	}))
	.use(connect.router(function(app) {
		app.get('/', function(req, res, next) {
			console.log(req.facebook);
			res.end();
		});
	}))
	.listen(3000);


