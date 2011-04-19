node.js facebook-sdk API
========================

facebook.api
------------

### Setup

    var fbsdk = require('facebook-sdk');

A Facebook object with no specific user information,
the following can be used to perform application api
calls such as obtaining [Insites data](https://developers.facebook.com/docs/insights/).

    var facebook = new fbsdk.Facebook({
      appId: 'YOUR APP ID',
      secret:'YOUR APP SECRET'
    });

The Facebook object can take the request/response parameters from an http request,
allowing for more specific graph api interactions regarding the requesting user.

    http.createServer(function (req, res) {
      var facebook = new fbsdk.Facebook({
        appId: 'YOUR APP ID',
        secret:'YOUR APP SECRET',
        request: req,
        response:res
      })
    });

This can be accomplished more easily by using connect middleware. The body and
cookie parsers provide a more efficient/robust interaction with the http headers.

    connect()
      .use(connect.bodyParser())
      .use(connect.cookieParser())
      .use(fbsdk.facebook({
        appId: 'YOUR APP ID',
        secret:'YOUR APP SECRET',
      }))

### Simple api call

    facebook.api('/me', function(me) {
      console.log(me);
    });

### FQL api call

    facebook.api({
      method: 'fql.query',
      query: "SELECT name FROM user WHERE uid = me()"
    }, function(data) {
      console.log(data);
    });
