[node.js Facebook SDK](https://github.com/tenorviol/node-facebook-sdk)
======================

This is a complete port of Facebook's [PHP SDK library](http://github.com/facebook/php-sdk).

> The [Facebook Platform](http://developers.facebook.com/) is
> a set of APIs that make your application more social. Read more about
> [integrating Facebook with your web site](http://developers.facebook.com/docs/guides/web)
> on the Facebook developer site.

The node.js Facebook SDK is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html),
as was the original library.

Install
-------

	npm install facebook-sdk

Usage
-----

Create a Facebook SDK object. The `request` lets the object retrieve the
user's session from the http header. The `response` lets the object write
the user a new session cookie. For more information on querying Facebook's
graph api, see [developers.facebook.com](http://developers.facebook.com/docs/reference/api/).


	var fbsdk = require('facebook-sdk'),
		http = require('http');
	
	http.createServer(function(request, response) {
		
		// create a facebook object
		var facebook = new fbsdk.Facebook({
			appId  : 'YOUR APP ID',
			secret : 'YOUR API SECRET',
			siteUrl: 'http://yoursite.com',
			request  : request,
			response : response
		});
		
		// logged in
		if (facebook.getSession()) {
			response.end('<a href="' + facebook.getLogoutUrl() + '">Logout</a>');
			
			// get my graph api information
			facebook.api('/me', function(me) {
				console.log(me);
			});
			
		// vs logged out
		} else {
			response.end('<a href="' + facebook.getLoginUrl() + '">Login</a>');
		}
		
	}).listen(80);

Usage as connect middleware
---------------------------

Using this as connect middleware, the following will attach a facebook object
to each incoming http request.

	var app = connect()
		.use(fbsdk.facebook({
			appId  : 'YOUR APP ID',
			secret : 'YOUR API SECRET',
			siteUrl: 'http://yoursite.com',
		})).
		use(connect.router(function(app) {
			
			app.get('/', function(req, res, next) {
				if (req.facebook.getSession()) {
					res.end('<a href="' + req.facebook.getLogoutUrl() + '">Logout</a>');
				} else {
					res.end('<a href="' + req.facebook.getLoginUrl() + '">Login</a>');
				}
			});
			
		}));

Open question about the above middleware
----------------------------------------

Creating an adhoc object is done with `new fbsdk.Facebook({...})`, and
creating middleware functions is `fbsdk.facebook({...})`. This strikes
me as an ugly over-use of case sensitivity. Anybody with a better idea
about this api, please message me.

Tests
-----

The tests have been ported to run using nodeunit. This was the easiest way to confirm
the new node.js library works as expected. Some new tests have been added to cover
edge cases, and others not relevant in the new environment have been removed.
