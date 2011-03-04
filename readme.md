[node.js Facebook SDK](https://github.com/tenorviol/node-facebook-sdk)
======================

This is a complete port of Facebook's [PHP SDK library](http://github.com/facebook/php-sdk).

> The [Facebook Platform](http://developers.facebook.com/) is
> a set of APIs that make your application more social. Read more about
> [integrating Facebook with your web site](http://developers.facebook.com/docs/guides/web)
> on the Facebook developer site.

The node.js Facebook SDK is licensed under the Apache License, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html), as was the original library.

Usage
-----

Create a Facebook SDK object. The `request` lets the object retrieve the
user's session from the http header. The `response` lets the object write
the user a new session cookie. For more information on querying Facebook's
graph api, see (https://developers.facebook.com/docs/reference/api/)


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


Tests
-----

The tests have been ported to run using nodeunit. This was the easiest way to confirm
the new node.js library works as expected. Some new tests have been added to cover
edge cases, and others not relevant in the new environment have been removed.
