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

Use as connect middleware
-------------------------

The following will attach a new Facebook object to each incoming http request.
For more information on querying Facebook's graph api, see
[developers.facebook.com](http://developers.facebook.com/docs/reference/api/).

    var connect = require('connect'),
      fbsdk = require('facebook-sdk');
    
    connect()
      .use(connect.cookieParser())
      .use(connect.bodyParser())
      .use(fbsdk.facebook({
        appId  : 'YOUR APP ID',
        secret : 'YOUR API SECRET'
      }))
      .use(function(req, res, next) {
        
        if (req.facebook.getSession()) {
          res.end('<a href="' + req.facebook.getLogoutUrl() + '">Logout</a>');
          
          // get my graph api information
          req.facebook.api('/me', function(me) {
              console.log(me);
          });
          
        } else {
            res.end('<a href="' + req.facebook.getLoginUrl() + '">Login</a>');
        }
        
      })
      .listen(3000);

Stand alone usage
-----------------

    var fbsdk = require('facebook-sdk');
    
    var facebook = new fbsdk.Facebook({
      appId  : 'YOUR APP ID',
      secret : 'YOUR API SECRET'
    });
    
    facebook.api('/YOUR APP ID', function(data) {
      console.log(data);
    });

Tests
-----

The tests have been ported to run using nodeunit. This was the easiest way to confirm
the new node.js library works as expected. Some new tests have been added to cover
edge cases, and others not relevant in the new environment have been removed.
