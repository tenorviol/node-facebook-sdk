var connect = require('connect'),
  http = require('http'),
  fbsdk = require('../lib/facebook');

var APP_ID = '117743971608120';
var SECRET = '943716006e74d9b9283d4d5d8ab93204';

var VALID_EXPIRED_SESSION = {
  access_token : '117743971608120|2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385|NF_2DDNxFBznj2CuwiwabHhTAHc.',
  expires      : '1281049200',
  secret       : 'u0QiRGAwaPCyQ7JE_hiz1w__',
  session_key  : '2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385',
  sig          : '7a9b063de0bef334637832166948dcad',
  uid          : '1677846385'
};

var UNESCAPED_SESSION_COOKIE = 'junk=foo; fbs_117743971608120="access_token=117743971608120%7C2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385%7CNF_2DDNxFBznj2CuwiwabHhTAHc.&expires=1281049200&secret=u0QiRGAwaPCyQ7JE_hiz1w__&session_key=2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385&sig=7a9b063de0bef334637832166948dcad&uid=1677846385"';


exports.testFacebookMiddleware = function(test) {
  var port = 3000;
  
  connect()
    .use(fbsdk.facebook({
      appId: APP_ID,
      secret: SECRET
    }))
    .use(function(req, res, next) {
      res.end();
      var facebook = req.facebook;
      test.equal(req, facebook.request);
      test.equal(res, facebook.response);
      test.deepEqual(VALID_EXPIRED_SESSION, facebook.getSession());
      test.done();
    })
    .listen(port, function() {
      http.request({
        host: 'localhost',
        port: port,
        path: '/',
        headers: {
          cookie: UNESCAPED_SESSION_COOKIE
        }
      }).end();
    });
};


