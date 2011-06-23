/**
 * Copyright 2011 Christopher Johnson <tenorviol@yahoo.com>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var fbsdk = require('../lib/facebook');
var Facebook = fbsdk.Facebook;
var connect = require('connect');
var crypto = require('crypto');
var fs = require('fs');
var http = require('http');
var https = require('https');
var qs = require('querystring');
var url = require('url');


var APP_ID = '117743971608120';
var SECRET = '943716006e74d9b9283d4d5d8ab93204';

var MIGRATED_APP_ID = '174236045938435';
var MIGRATED_SECRET = '0073dce2d95c4a5c2922d1827ea0cca6';

var kExpiredAccessToken = '206492729383450|2.N4RKywNPuHAey7CK56_wmg__.3600.1304560800.1-214707|6Q14AfpYi_XJB26aRQumouzJiGA';
var kValidSignedRequest = '1sxR88U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';
var kNonTosedSignedRequest = 'c0Ih6vYvauDwncv0n0pndr0hP0mvZaJPQDPt6Z43O0k.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiJ9';

exports.testConstructor = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET,
    fileUpload : true,
    accessToken : 'saltydog'
  });
  assert.equal(facebook.appId, APP_ID,
               'Expect the App ID to be set.');
  assert.equal(facebook.secret, SECRET,
               'Expect the API secret to be set.');
  assert.equal(facebook.fileUpload, true,
              'Expect file upload support to be on.');
  assert.equal(facebook.getAccessToken(), 'saltydog',
               'Expect access token to remain \'saltydog\'');
  assert.done();
};

exports.testSetAccessToken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  facebook.setAccessToken('saltydog');
  assert.equal(facebook.getAccessToken(), 'saltydog',
               'Expect installed access token to remain \'saltydog\'');
  assert.done();
};

[
  {
    path: '/unit-tests.php?one=one&two=two&three=three',
    expect: 'http://www.test.com/unit-tests.php?one=one&two=two&three=three'
  },
  
  // ensure structure of valueless GET params is retained (sometimes
  // an = sign was present, and sometimes it was not)
  // first test when equal signs are present
  {
    path: '/unit-tests.php?one=&two=&three=',
    expect: 'http://www.test.com/unit-tests.php?one=&two=&three='
  },
  
  // now confirm that
  {
    path: '/unit-tests.php?one&two&three',
    expect: 'http://www.test.com/unit-tests.php?one&two&three'
  }
].forEach(function (test) {
  
  exports['testGetCurrentURL ' + test.path] = function (assert) {
    var request = {
      path : test.path,
      headers : { host : 'www.test.com' }
    };
    httpServerTest(request, function (req, res) {
      var current_url = req.facebook._getCurrentUrl();
      assert.equal(
        test.expect,
        current_url,
        'getCurrentUrl function is changing the current URL');
      assert.done();
    });
  };
  
});

exports.testGetLoginURL = function (assert) {
  var request = {
    path : '/unit-tests.php',
    headers : { host : 'www.test.com' }
  };
  httpServerTest(request, function (req, res) {
    var login_url = url.parse(req.facebook.getLoginUrl(), true);
    assert.equal('https:',           login_url.protocol);
    assert.equal('www.facebook.com', login_url.host);
    assert.equal('/dialog/oauth',    login_url.pathname);
    var expected_login_params = { client_id : APP_ID,
                                  redirect_uri : 'http://www.test.com/unit-tests.php' };
    assertIsSubset.call(assert, expected_login_params, login_url.query);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    assert.equal(32, login_url.query.state.length);
    assert.done();
  });
};

exports.testGetLoginURLWithExtraParams = function (assert) {
  var request = {
    path : '/unit-tests.php',
    headers : { host : 'www.test.com' }
  };
  httpServerTest(request, function (req, res) {
    var extra_params = { scope : 'email, sms',
                         nonsense : 'nonsense' };
    var login_url = url.parse(req.facebook.getLoginUrl(extra_params), true);
    assert.equal('https:',           login_url.protocol);
    assert.equal('www.facebook.com', login_url.host);
    assert.equal('/dialog/oauth',    login_url.pathname);
    var expected_login_params = array_merge(
        { client_id : APP_ID,
          redirect_uri : 'http://www.test.com/unit-tests.php' },
        extra_params
    );
    assertIsSubset.call(assert, expected_login_params, login_url.query);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    assert.equal(32, login_url.query.state.length);
    assert.done();
  });
};

exports.testGetCodeWithValidCSRFState = function (assert) {
  httpServerTest(function (req, res) {
    // TODO : wtf is this test supposed to do?
    req.facebook._establishCSRFTokenState();
    var code = req.session.code = generateMD5HashOfRandomValue();
    req.session.state = req.facebook._getPersistentData('state');
    assert.equal(code,
                 req.facebook._getCode(),
                 'Expect code to be pulled from _REQUEST[\'code\']');
    assert.done();
  });
};

exports.testGetCodeWithInvalidCSRFState = function (assert) {
  httpServerTest(function (req, res) {
    req.facebook._establishCSRFTokenState();
    var code = req.session.code = generateMD5HashOfRandomValue();
    // TODO : is this right?
    req.session.state = req.facebook._getPersistentData('state') + 'forgery!!!';
    assert.ok(!req.facebook._getCode(),
              'Expect getCode to fail, CSRF state should not match.');
    assert.done();
  });
};

exports.testGetCodeWithMissingCSRFState = function (assert) {
  httpServerTest(function (req, res) {
    code = req.session.code = generateMD5HashOfRandomValue();
    // intentionally don't set CSRF token at all
    assert.ok(!req.facebook._getCode(),
              'Expect getCode to fail, CSRF state not sent back.');
    assert.done();
  });
};

exports.testGetUserFromSignedRequest = function (assert) {
  // TODO : use get as well
  var request = {
    post : { signed_request: kValidSignedRequest }
  };
  httpServerTest(request, function (req, res) {
    assert.equal('1677846385', req.facebook.getUser(),
                 'Failed to get user ID from a valid signed request.');
    assert.done();
  });
};

exports.testNonUserAccessToken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  // no cookies, and no request params, so no user or code,
  // so no user access token (even with cookie support)
  assert.equal(facebook._getApplicationAccessToken(),
               facebook.getAccessToken(),
               'Access token should be that for logged out users.');
  assert.done();
};

exports.testAPIForLoggedOutUsers = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });
  facebook.api({
    'method' : 'fql.query',
    'query' : 'SELECT name FROM user WHERE uid=4'
  }, function (err, response) {
    assert.equal(response.length, 1,
                 'Expect one row back.');
    assert.equal(response[0].name, 'Mark Zuckerberg',
                 'Expect the name back.');
    assert.done();
  });
};

exports.testAPIWithBogusAccessToken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  facebook.setAccessToken('this-is-not-really-an-access-token');
  // if we don't set an access token and there's no way to
  // get one, then the FQL query below works beautifully, handing
  // over Zuck's public data.  But if you specify a bogus access
  // token as I have right here, then the FQL query should fail.
  // We could return just Zuck's public data, but that wouldn't
  // advertise the issue that the access token is at worst broken
  // and at best expired.
  facebook.api({
    'method' : 'fql.query',
    'query' : 'SELECT name FROM profile WHERE id=4'
  }, function (err, result) {
    var result = err.getResult();
    assert.equal('object', typeof result, 'expect a result object');
    assert.equal('190', result.error_code, 'expect code');
    assert.done();
  });
};

exports.testAPIGraphPublicData = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  facebook.api('/jerry', function (err, response) {
    assert.equal(
      response.id, '214707', 'should get expected id.');
    assert.done();
  });
};

exports.testGraphAPIWithBogusAccessToken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  facebook.setAccessToken('this-is-not-really-an-access-token');
  facebook.api('/me', function (err, response) {
    // means the server got the access token and didn't like it
    var msg = 'OAuthException: Invalid OAuth access token.';
    assert.equal(msg, err.toString(),
                 'Expect the invalid OAuth token message.');
    assert.done();
  });
};

exports.testGraphAPIWithExpiredAccessToken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  facebook.setAccessToken(kExpiredAccessToken);
  facebook.api('/me', function (err, response) {
    // means the server got the access token and didn't like it
    var error_msg_start = 'OAuthException: Error validating access token:';
    assert.ok(err.toString().indexOf(error_msg_start) === 0,
              'Expect the token validation error message.');
    assert.done();
  });
};

exports.testGraphAPIMethod = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  // naitik being bold about deleting his entire record....
  // let's hope this never actually passes.
  facebook.api('/naitik', method = 'DELETE', function (err, response) {
    // ProfileDelete means the server understood the DELETE
    var msg =
      'OAuthException: An access token is required to request this resource.';
    assert.equal(msg, err.toString(),
                 'Expect the invalid session message.');
    assert.done();
  });
};

exports.testGraphAPIOAuthSpecError = function (assert) {
  var facebook = new Facebook({
    appId  : MIGRATED_APP_ID,
    secret : MIGRATED_SECRET
  });

  facebook.api(
    '/me',
    { 'client_id' : MIGRATED_APP_ID },
    function (err, response) {
      // means the server got the access token
      var msg = 'invalid_request: An active access token must be used '
              + 'to query information about the current user.';
      assert.equal(msg, err.toString(),
                   'Expect the invalid session message.');
      assert.done();
    }
  );
};

exports.testGraphAPIMethodOAuthSpecError = function (assert) {
  var facebook = new Facebook({
    appId  : MIGRATED_APP_ID,
    secret : MIGRATED_SECRET
  });

  facebook.api(
    '/daaku.shah',
    'DELETE',
    { 'client_id' : MIGRATED_APP_ID },
    function (err, response) {
      assert.equal(0, err.toString().indexOf('invalid_request'));
      assert.done();
    }
  );
};

exports.testCurlFailure = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET,
    timeout : 50  // we dont expect facebook will ever return in 1ms
  });

  facebook.api('/naitik', function (err, response) {
    assert.ok(err, 'no exception was thrown on timeout.');
    // TODO : fix this error message to be more node native
    assert.equal(28, err.code, 'expect timeout');
    assert.equal('CurlException', err.getType(), 'expect type');
    assert.done();
  });
};

//exports.testGraphAPIWithOnlyParams = function (assert) {
//  var facebook = new Facebook({
//    appId  : APP_ID,
//    secret : SECRET
//  });
//
//  facebook.api(
//    '/331218348435/feed',
//    { limit : 1, access_token : '' },
//    function (err, response) {
//      console.log(arguments);
//      assert.equal(1, response.data.length, 'should get one entry');
//      assert.ok(
//        response.paging.next.indexOf('limit=1') >= 0,
//        'expect the same limit back in the paging urls'
//      );
//      assert.done();
//    }
//  );
//};

exports.testLoginURLDefaults = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl = qs.escape('http://fbrell.com/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf(encodedUrl) >= 0,
              'Expect the current url to exist.');
    assert.done();
  });
};

exports.testLoginURLDefaultsDropStateQueryParam = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples?state=xx42xx'
  };
  httpServerTest(request, function (req, res) {
    var expectEncodedUrl = qs.escape('http://fbrell.com/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf(expectEncodedUrl) > -1,
              'Expect the current url to exist.');
    assert.ok(req.facebook.getLoginUrl().indexOf('xx42xx') === -1,
              'Expect the session param to be dropped.');
    assert.done();
  });
};

exports.testLoginURLDefaultsDropCodeQueryParam = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples?code=xx42xx'
  };
  httpServerTest(request, function (req, res) {
    var expectEncodedUrl = qs.escape('http://fbrell.com/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf(expectEncodedUrl) > -1,
              'Expect the current url to exist.');
    assert.ok(req.facebook.getLoginUrl().indexOf('xx42xx') === -1,
              'Expect the session param to be dropped.');
    assert.done();
  });
};

exports.testLoginURLDefaultsDropSignedRequestParamButNotOthers = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples?signed_request=xx42xx&do_not_drop=xx43xx'
  };
  httpServerTest(request, function (req, res) {
    var expectEncodedUrl = qs.escape('http://fbrell.com/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf('xx42xx') === -1,
              'Expect the session param to be dropped.');
    assert.ok(req.facebook.getLoginUrl().indexOf('xx43xx') > -1,
              'Expect the do_not_drop param to exist.');
    assert.done();
  });
};

exports.testLoginURLCustomNext = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var next = 'http://fbrell.com/custom';
    var loginUrl = req.facebook.getLoginUrl({
      redirect_uri : next,
      cancel_url : next
    });
    var currentEncodedUrl = qs.escape('http://fbrell.com/examples');
    var expectedEncodedUrl = qs.escape(next);
    assert.ok(loginUrl.indexOf(expectedEncodedUrl) >= 0,
              'Expect the custom url to exist.');
    assert.ok(loginUrl.indexOf(currentEncodedUrl) === -1,
              'Expect the current url to not exist.');
    assert.done();
  });
};

exports.testLogoutURLDefaults = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl = qs.escape('http://fbrell.com/examples');
    assert.ok(req.facebook.getLogoutUrl().indexOf(encodedUrl) >= 0,
              'Expect the current url to exist.');
    assert.done();
  });
};

exports.testLoginStatusURLDefaults = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl = qs.escape('http://fbrell.com/examples');
    assert.ok(req.facebook.getLoginStatusUrl().indexOf(encodedUrl) >= 0,
              'Expect the current url to exist.');
    assert.done();
  });
};

exports.testLoginStatusURLCustom = function (assert) {
  var request = {
    headers : { host : 'fbrell.com' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl1 = qs.escape('http://fbrell.com/examples');
    var okUrl = 'http://fbrell.com/here1';
    var encodedUrl2 = qs.escape(okUrl);
    var loginStatusUrl = req.facebook.getLoginStatusUrl({
      ok_session : okUrl
    });
    assert.ok(loginStatusUrl.indexOf(encodedUrl1) >= 0,
              'Expect the current url to exist.');
    assert.ok(loginStatusUrl.indexOf(encodedUrl2) >= 0,
              'Expect the custom url to exist.');
    assert.done();
  });
};

exports.testNonDefaultPort = function (assert) {
  var request = {
    headers : { host : 'fbrell.com:8080' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl = qs.escape('http://fbrell.com:8080/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf(encodedUrl) >- 0,
              'Expect the current url to exist.');
    assert.done();
  });
};

exports.testSecureCurrentUrl = function (assert) {
  var request = {
    https : true,
    headers : { host : 'fbrell.com' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl = qs.escape('https://fbrell.com/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf(encodedUrl) >= 0,
              'Expect the current url to exist.');
    assert.done();
  });
};

exports.testSecureCurrentUrlWithNonDefaultPort = function (assert) {
  var request = {
    https : true,
    headers : { host : 'fbrell.com:8080' },
    path : '/examples'
  };
  httpServerTest(request, function (req, res) {
    var encodedUrl = qs.escape('https://fbrell.com:8080/examples');
    assert.ok(req.facebook.getLoginUrl().indexOf(encodedUrl) >= 0,
              'Expect the current url to exist.');
    assert.done();
  });
};

exports.testAppSecretCall = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });

  proper_exception_thrown = false;
  facebook.api('/' + APP_ID + '/insights', function (err, response) {
    var proper_exception_thrown =
      err.toString()
        .indexOf('Requires session when calling from a desktop app') >= 0;
    assert.ok(proper_exception_thrown,
              'Incorrect exception type thrown when trying to gain '
              + 'insights for desktop app without a user access token.');
    assert.done();
  });
};

exports.testBase64UrlEncode = function (assert) {
  input = 'Facebook rocks';
  output = 'RmFjZWJvb2sgcm9ja3M';

  assert.equal(fbsdk._base64UrlDecode(output), input);
  assert.done();
};

exports.testSignedToken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });
  var payload = facebook._parseSignedRequest(kValidSignedRequest);
  assert.ok(payload, 'Expected token to parse');
  assert.equal(facebook.getSignedRequest(), null);
  var request = {
    post : { signed_request : kValidSignedRequest }
  };
  httpServerTest(request, function (req, res) {
    assert.deepEqual(req.facebook.getSignedRequest(), payload);
    assert.done();
  });
};

exports.testNonTossedSignedtoken = function (assert) {
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET
  });
  var payload = facebook._parseSignedRequest(kNonTosedSignedRequest);
  assert.ok(payload, 'Expected token to parse');
  assert.ok(!facebook.getSignedRequest());
  var request = {
    post : { signed_request : kNonTosedSignedRequest }
  };
  httpServerTest(request, function (req, res) {
    assert.deepEqual(req.facebook.getSignedRequest(),
      {'algorithm' : 'HMAC-SHA256'});
    assert.done();
  });
};

//exports.testBundledCACert = function (assert) {
//  var facebook = new Facebook({
//    appId  : APP_ID,
//    secret : SECRET
//  });
//
//    // use the bundled cert from the start
//  Facebook::CURL_OPTS[CURLOPT_CAINFO] =
//    dirname(__FILE__) . '/../src/fb_ca_chain_bundle.crt';
//  response = facebook.api('/naitik');
//
//  unset(Facebook::CURL_OPTS[CURLOPT_CAINFO]);
//  assert.equal(
//    response['id'], '5526183', 'should get expected id.');
//};

exports.testVideoUpload = function (assert) {
  var saved_url;
  var facebook = new Facebook({
    appId  : APP_ID,
    secret : SECRET,
    _oauthRequest : function (url, params, callback) {
      saved_url = url;
      callback(null, '{}');
    }
  });

  facebook.api({'method' : 'video.upload'}, function () {
    assert.ok(saved_url.indexOf('//api-video.') >= 0,
              'video.upload should go against api-video');
    assert.done();
  });
};

// TODO : test json decoder

exports.testGetUserAndAccessTokenFromSession = function (assert) {
  httpServerTest(function (req, res) {
    req.facebook._setPersistentData('access_token',
                                    kExpiredAccessToken);
    req.facebook._setPersistentData('user_id', 12345);
    assert.deepEqual(kExpiredAccessToken,
                     req.facebook.getAccessToken(),
                     'Get access token from persistent store.');
    assert.equal('12345',
                 req.facebook.getUser(),
                 'Get user id from persistent store.');
    assert.done();
  });
};

exports.testGetUserAndAccessTokenFromSignedRequestNotSession = function (assert) {
  var request = {
    post : { signed_request : kValidSignedRequest }
  };
  httpServerTest(request, function (req, res) {
    req.facebook._setPersistentData('user_id', 41572);
    req.facebook._setPersistentData('access_token',
                                    kExpiredAccessToken);
    assert.notEqual(41572, req.facebook.getUser(),
                    'Got user from session instead of signed request.');
    assert.equal(1677846385, req.facebook.getUser(),
                 'Failed to get correct user ID from signed request.');
    assert.notEqual(
      kExpiredAccessToken,
      req.facebook.getAccessToken(),
      'Got access token from session instead of signed request.');
    assert.ok(
      req.facebook.getAccessToken(),
      'Failed to extract an access token from the signed request.');
    assert.done();
  });
};

exports.testGetUserWithoutCodeOrSignedRequestOrSession = function (assert) {
  httpServerTest(function (req, res) {
    // deliberately leave _REQUEST and _SESSION empty
    //assert.Empty(_REQUEST,
    //             'GET, POST, and COOKIE params exist even though '.
    //             'they should.  Test cannot succeed unless all of '.
    //             '_REQUEST is empty.');
    assert.ok(!req.session.user_id,
              'Session is carrying state and should not be.');
    assert.ok(!req.facebook.getUser(),
              'Got a user id, even without a signed request, '
              + 'access token, or session variable.');
    assert.ok(!req.session.user_id,
              'Session superglobal incorrectly populated by getUser.');
    assert.done();
  });
};

function generateMD5HashOfRandomValue() {
  //return md5(uniqid(mt_rand(), true));
  return crypto.createHash('md5').update(Math.random() + Date.now).digest('hex');
}

/**
 * Checks that the correct args are a subset of the returned obj
 * @param  array correct The correct array values
 * @param  array actual  The values in practice
 * @param  string message to be shown on failure
 */
function assertIsSubset(correct, actual, msg) {
  for (var key in correct) {
    var value = correct[key];
    var actual_value = actual[key];
    var newMsg = (msg ? msg + ' ' : '') + 'Key: ' + key;
    this.equal(value, actual_value, newMsg);
  }
}

/**
 * Creates an http server using the 'test' handler function,
 * makes a request to the server using the options object,
 * and uses the 'result' handler function for testing the server response.
 */
function httpServerTest(options, test) {
  if (typeof options === 'function') {
    test = options;
    options = {};
  }

  options.host = 'localhost';
  options.port = 8889;
  options.path = options.path || '/';
  if (!options.method) {
    options.method = options.post ? 'POST' : 'GET';
  }

  var transport = http;
  if (options.https) {
    transport = https;
    delete options.https;

    var server = connect({
      key: fs.readFileSync(__dirname + '/test_key.pem'),
      cert: fs.readFileSync(__dirname + '/test_cert.pem')
    });
  } else {
    var server = connect();
  }

  server.use(connect.cookieParser());
  server.use(connect.session({ secret: 'area 51' }));
  server.use(connect.bodyParser());
  server.use(Facebook({
    appId  : APP_ID,
    secret : SECRET,
    _errorLog : function() {}
  }));

  server.use(function(req, res, next) {
    test(req, res);
    res.end();
    server.close();
  });

  server.listen(options.port, function() {
    var request = transport.request(options /*, response */ );
    if (options.post) {
      request.removeHeader('post');
      var post_data = qs.stringify(options.post);
      request.setHeader('Content-Type', 'application/x-www-form-urlencoded');
      request.setHeader('Content-Length', post_data.length);
      request.write(post_data);
    }
    request.end();
  });
}

// TODO : de-duplicate (it's in facebook.js too)
function array_merge(target) {
  for (var i = 1; i < arguments.length; i++) {
    var uber = arguments[i];
    for (var j in uber) {
      target[j] = uber[j];
    }
  }
  return target;
}
