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

First, create a Facebook SDK object. The http request and response objects are not
required for application graph requests or when setting the session manually. Otherwise
they are recommended, for reading and verification of of the session from the request
or cookie data, and for writing verified session data to the browser's cookie. 

	var fbsdk = require('facebook-sdk');
	
	var facebook = new fbsdk.Facebook({
		appId  : 'YOUR APP ID',
		secret : 'YOUR API SECRET',
		request  : request (http.ServerRequest),
		response : response (http.ServerResponse)
	});

To make [API][API] calls:

	facebook.api('/me', function(me) {
		if (me.error) {
			console.log(me);
			return;
		}
		
		// do something interesting
	});

Logged in vs Logged out:

	if (facebook.getSession()) {
		print('<a href="' + facebook.getLogoutUrl() + '">Logout</a>');
	} else {
		print('<a href="' + facebook.getLoginUrl() + '">Login</a>');
	}

[API]: http://developers.facebook.com/docs/api


Tests
-----

The tests have been ported to run using nodeunit. This was the easiest way to confirm
the new node.js library works as expected. Some new tests have been added to cover
edge cases, and others that are not relevant in the new environment have been removed.
