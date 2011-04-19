var connect = require('connect'),
    fbsdk = require('facebook-sdk');

var port = 3000;

connect()
  .use(connect.favicon())
  .use(connect.cookieParser())
  .use(connect.bodyParser())
  .use(fbsdk.facebook({
    appId  : '204017379608368',
    secret : '05670b3c6d771ab708f3d5089e581655'
  }))
  .use(function(req, res, next) {
    
    if (req.facebook.getSession()) {
      
      // get my graph api information
      req.facebook.api('/me', function(me) {
        console.log(me);
      });
      
      res.end('<a href="' + req.facebook.getLogoutUrl() + '">Logout</a>');
    } else {
      res.end('<a href="' + req.facebook.getLoginUrl() + '">Login</a>');
    }
    
  })
  .listen(port);

console.log('Listening for http requests on port ' + port);
