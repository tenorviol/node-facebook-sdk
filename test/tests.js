var Facebook = require('../lib/facebook').Facebook;
var connect = require('connect');
var crypto = require('crypto');
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

//  exports.testConstructor = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    assert.equal(facebook.getAppId(), self::APP_ID,
//                        'Expect the App ID to be set.');
//    assert.equal(facebook.getApiSecret(), self::SECRET,
//                        'Expect the API secret to be set.');
//  };
//
//  exports.testConstructorWithFileUpload = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'      : self::APP_ID,
//      'secret'     : self::SECRET,
//      'fileUpload' : true,
//    ));
//    assert.equal(facebook.getAppId(), self::APP_ID,
//                        'Expect the App ID to be set.');
//    assert.equal(facebook.getApiSecret(), self::SECRET,
//                        'Expect the API secret to be set.');
//    assert.True(facebook.useFileUploadSupport(),
//                      'Expect file upload support to be on.');
//  };
//
//  exports.testSetAppId = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    facebook.setAppId('dummy');
//    assert.equal(facebook.getAppId(), 'dummy',
//                        'Expect the App ID to be dummy.');
//  };
//
//  exports.testSetAPISecret = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    facebook.setApiSecret('dummy');
//    assert.equal(facebook.getApiSecret(), 'dummy',
//                        'Expect the API secret to be dummy.');
//  };
//
//  exports.testSetAccessToken = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    facebook.setAccessToken('saltydog');
//    assert.equal(facebook.getAccessToken(), 'saltydog',
//                        'Expect installed access token to remain \'saltydog\'');
//  };
//
//  exports.testSetFileUploadSupport = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    assert.False(facebook.useFileUploadSupport(),
//                       'Expect file upload support to be off.');
//    facebook.setFileUploadSupport(true);
//    assert.True(facebook.useFileUploadSupport(),
//                      'Expect file upload support to be on.');
//  };

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
    assert.equal(APP_ID,             login_url.query.client_id);
    assert.equal('http://www.test.com/unit-tests.php', login_url.query.redirect_uri);
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
                         nonsense : 'nonsense'};
    var login_url = url.parse(req.facebook.getLoginUrl(extra_params), true);
    assert.equal('https:',           login_url.protocol);
    assert.equal('www.facebook.com', login_url.host);
    assert.equal('/dialog/oauth',    login_url.pathname);
    var expected_login_params = array_merge(
        { client_id : APP_ID,
          redirect_uri : 'http://www.test.com/unit-tests.php' },
        extra_params
    );
    for (var i in expected_login_params) {
      assert.equal(expected_login_params[i], login_url.query[i]);
    }
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

exports.testGetCodeWithInvalidCSRFState = function(assert) {
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

exports.testGetCodeWithMissingCSRFState = function(assert) {
  httpServerTest(function (req, res) {
    code = req.session.code = generateMD5HashOfRandomValue();
    // intentionally don't set CSRF token at all
    assert.ok(!req.facebook._getCode(),
              'Expect getCode to fail, CSRF state not sent back.');
    assert.done();
  });
};

exports.testGetUserFromSignedRequest = function(assert) {
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

exports.testNonUserAccessToken = function(assert) {
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

//  exports.testAPIForLoggedOutUsers = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    response = facebook.api(array(
//      'method' : 'fql.query',
//      'query' : 'SELECT name FROM user WHERE uid=4',
//    ));
//    assert.equal(count(response), 1,
//                        'Expect one row back.');
//    assert.equal(response[0]['name'], 'Mark Zuckerberg',
//                        'Expect the name back.');
//  };
//
//  exports.testAPIWithBogusAccessToken = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    facebook.setAccessToken('this-is-not-really-an-access-token');
//    // if we don't set an access token and there's no way to
//    // get one, then the FQL query below works beautifully, handing
//    // over Zuck's public data.  But if you specify a bogus access
//    // token as I have right here, then the FQL query should fail.
//    // We could return just Zuck's public data, but that wouldn't
//    // advertise the issue that the access token is at worst broken
//    // and at best expired.
//    try {
//      response = facebook.api(array(
//        'method' : 'fql.query',
//        'query' : 'SELECT name FROM profile WHERE id=4',
//      ));
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      result = e.getResult();
//      assert.True(is_array(result), 'expect a result object');
//      assert.equal('190', result['error_code'], 'expect code');
//    }
//  };
//
//  exports.testAPIGraphPublicData = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    response = facebook.api('/jerry');
//    assert.equal(
//      response['id'], '214707', 'should get expected id.');
//  };
//
//  exports.testGraphAPIWithBogusAccessToken = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    facebook.setAccessToken('this-is-not-really-an-access-token');
//    try {
//      response = facebook.api('/me');
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      // means the server got the access token and didn't like it
//      msg = 'OAuthException: Invalid OAuth access token.';
//      assert.equal(msg, (string) e,
//                          'Expect the invalid OAuth token message.');
//    }
//  };
//
//  exports.testGraphAPIWithExpiredAccessToken = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    facebook.setAccessToken(self::kExpiredAccessToken);
//    try {
//      response = facebook.api('/me');
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      // means the server got the access token and didn't like it
//      error_msg_start = 'OAuthException: Error validating access token:';
//      assert.True(strpos((string) e, error_msg_start) === 0,
//                        'Expect the token validation error message.');
//    }
//  };
//
//  exports.testGraphAPIMethod = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    try {
//      // naitik being bold about deleting his entire record....
//      // let's hope this never actually passes.
//      response = facebook.api('/naitik', method = 'DELETE');
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      // ProfileDelete means the server understood the DELETE
//      msg =
//        'OAuthException: An access token is required to request this resource.';
//      assert.equal(msg, (string) e,
//                          'Expect the invalid session message.');
//    }
//  };
//
//  exports.testGraphAPIOAuthSpecError = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::MIGRATED_APP_ID,
//      'secret' : self::MIGRATED_SECRET,
//    ));
//
//    try {
//      response = facebook.api('/me', array(
//        'client_id' : self::MIGRATED_APP_ID));
//
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      // means the server got the access token
//      msg = 'invalid_request: An active access token must be used '.
//             'to query information about the current user.';
//      assert.equal(msg, (string) e,
//                          'Expect the invalid session message.');
//    }
//  };
//
//  exports.testGraphAPIMethodOAuthSpecError = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::MIGRATED_APP_ID,
//      'secret' : self::MIGRATED_SECRET,
//    ));
//
//    try {
//      response = facebook.api('/daaku.shah', 'DELETE', array(
//        'client_id' : self::MIGRATED_APP_ID));
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      assert.equal(strpos(e, 'invalid_request'), 0);
//    }
//  };
//
//  exports.testCurlFailure = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    if (!defined('CURLOPT_TIMEOUT_MS')) {
//      // can't test it if we don't have millisecond timeouts
//      return;
//    }
//
//    exception = null;
//    try {
//      // we dont expect facebook will ever return in 1ms
//      Facebook::CURL_OPTS[CURLOPT_TIMEOUT_MS] = 50;
//      facebook.api('/naitik');
//    } catch(FacebookApiException e) {
//      exception = e;
//    }
//    unset(Facebook::CURL_OPTS[CURLOPT_TIMEOUT_MS]);
//    if (!exception) {
//      this.fail('no exception was thrown on timeout.');
//    }
//
//    assert.equal(
//      CURLE_OPERATION_TIMEOUTED, exception.getCode(), 'expect timeout');
//    assert.equal('CurlException', exception.getType(), 'expect type');
//  };
//
//  exports.testGraphAPIWithOnlyParams = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    response = facebook.api('/331218348435/feed',
//      array('limit' : 1, 'access_token' : ''));
//    assert.equal(1, count(response['data']), 'should get one entry');
//    assert.True(
//      strpos(response['paging']['next'], 'limit=1') !== false,
//      'expect the same limit back in the paging urls'
//    );
//  };
//
//  exports.testLoginURLDefaults = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl = rawurlencode('http://fbrell.com/examples');
//    assert.NotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//  };
//
//  exports.testLoginURLDefaultsDropStateQueryParam = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples?state=xx42xx';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    assert.True(strpos(facebook.getLoginUrl(), expectEncodedUrl) > -1,
//                      'Expect the current url to exist.');
//    assert.False(strpos(facebook.getLoginUrl(), 'xx42xx'),
//                       'Expect the session param to be dropped.');
//  };
//
//  exports.testLoginURLDefaultsDropCodeQueryParam = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples?code=xx42xx';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    assert.True(strpos(facebook.getLoginUrl(), expectEncodedUrl) > -1,
//                      'Expect the current url to exist.');
//    assert.False(strpos(facebook.getLoginUrl(), 'xx42xx'),
//                       'Expect the session param to be dropped.');
//  };
//
//  exports.testLoginURLDefaultsDropSignedRequestParamButNotOthers = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] =
//      '/examples?signed_request=xx42xx&do_not_drop=xx43xx';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    assert.False(strpos(facebook.getLoginUrl(), 'xx42xx'),
//                       'Expect the session param to be dropped.');
//    assert.True(strpos(facebook.getLoginUrl(), 'xx43xx') > -1,
//                      'Expect the do_not_drop param to exist.');
//  };
//
//  exports.testLoginURLCustomNext = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    next = 'http://fbrell.com/custom';
//    loginUrl = facebook.getLoginUrl(array(
//      'redirect_uri' : next,
//      'cancel_url' : next
//    ));
//    currentEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    expectedEncodedUrl = rawurlencode(next);
//    assert.NotNull(strpos(loginUrl, expectedEncodedUrl),
//                         'Expect the custom url to exist.');
//    assert.False(strpos(loginUrl, currentEncodedUrl),
//                      'Expect the current url to not exist.');
//  };
//
//  exports.testLogoutURLDefaults = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl = rawurlencode('http://fbrell.com/examples');
//    assert.NotNull(strpos(facebook.getLogoutUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//  };
//
//  exports.testLoginStatusURLDefaults = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl = rawurlencode('http://fbrell.com/examples');
//    assert.NotNull(strpos(facebook.getLoginStatusUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//  };
//
//  exports.testLoginStatusURLCustom = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl1 = rawurlencode('http://fbrell.com/examples');
//    okUrl = 'http://fbrell.com/here1';
//    encodedUrl2 = rawurlencode(okUrl);
//    loginStatusUrl = facebook.getLoginStatusUrl(array(
//      'ok_session' : okUrl,
//    ));
//    assert.NotNull(strpos(loginStatusUrl, encodedUrl1),
//                         'Expect the current url to exist.');
//    assert.NotNull(strpos(loginStatusUrl, encodedUrl2),
//                         'Expect the custom url to exist.');
//  };
//
//  exports.testNonDefaultPort = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com:8080';
//    _SERVER['REQUEST_URI'] = '/examples';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl = rawurlencode('http://fbrell.com:8080/examples');
//    assert.NotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//  };
//
//  exports.testSecureCurrentUrl = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    _SERVER['HTTPS'] = 'on';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl = rawurlencode('https://fbrell.com/examples');
//    assert.NotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//  };
//
//  exports.testSecureCurrentUrlWithNonDefaultPort = function(assert) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com:8080';
//    _SERVER['REQUEST_URI'] = '/examples';
//    _SERVER['HTTPS'] = 'on';
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//    encodedUrl = rawurlencode('https://fbrell.com:8080/examples');
//    assert.NotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//  };
//
//  exports.testAppSecretCall = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET,
//    ));
//
//    proper_exception_thrown = false;
//    try {
//      response = facebook.api('/' . self::APP_ID . '/insights');
//      this.fail('Desktop applications need a user token for insights.');
//    } catch (FacebookApiException e) {
//      proper_exception_thrown =
//        strpos(e.getMessage(),
//               'Requires session when calling from a desktop app') !== false;
//    } catch (Exception e) {}
//
//    assert.True(proper_exception_thrown,
//                      'Incorrect exception type thrown when trying to gain '.
//                      'insights for desktop app without a user access token.');
//  };
//
//  exports.testBase64UrlEncode = function(assert) {
//    input = 'Facebook rocks';
//    output = 'RmFjZWJvb2sgcm9ja3M';
//
//    assert.equal(FBPublic::publicBase64UrlDecode(output), input);
//  };
//
//  exports.testSignedToken = function(assert) {
//    facebook = new FBPublic(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET
//    ));
//    payload = facebook.publicParseSignedRequest(self::kValidSignedRequest);
//    assert.NotNull(payload, 'Expected token to parse');
//    assert.equal(facebook.getSignedRequest(), null);
//    _REQUEST['signed_request'] = self::kValidSignedRequest;
//    assert.equal(facebook.getSignedRequest(), payload);
//  };
//
//  exports.testNonTossedSignedtoken = function(assert) {
//    facebook = new FBPublic(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET
//    ));
//    payload = facebook.publicParseSignedRequest(
//      self::kNonTosedSignedRequest);
//    assert.NotNull(payload, 'Expected token to parse');
//    assert.Null(facebook.getSignedRequest());
//    _REQUEST['signed_request'] = self::kNonTosedSignedRequest;
//    assert.equal(facebook.getSignedRequest(),
//      array('algorithm' : 'HMAC-SHA256'));
//  };
//
//  exports.testBundledCACert = function(assert) {
//    facebook = new TransientFacebook(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET
//    ));
//
//      // use the bundled cert from the start
//    Facebook::CURL_OPTS[CURLOPT_CAINFO] =
//      dirname(__FILE__) . '/../src/fb_ca_chain_bundle.crt';
//    response = facebook.api('/naitik');
//
//    unset(Facebook::CURL_OPTS[CURLOPT_CAINFO]);
//    assert.equal(
//      response['id'], '5526183', 'should get expected id.');
//  };
//
//  exports.testVideoUpload = function(assert) {
//    facebook = new FBRecordURL(array(
//      'appId'  : self::APP_ID,
//      'secret' : self::SECRET
//    ));
//
//    facebook.api(array('method' : 'video.upload'));
//    assert.Contains('//api-video.', facebook.getRequestedURL(),
//                          'video.upload should go against api-video');
//  };
//
//  exports.testGetUserAndAccessTokenFromSession = function(assert) {
//    facebook = new PersistentFBPublic(array(
//                                         'appId'  : self::APP_ID,
//                                         'secret' : self::SECRET
//                                       ));
//
//    facebook.publicSetPersistentData('access_token',
//                                       self::kExpiredAccessToken);
//    facebook.publicSetPersistentData('user_id', 12345);
//    assert.equal(self::kExpiredAccessToken,
//                        facebook.getAccessToken(),
//                        'Get access token from persistent store.');
//    assert.equal('12345',
//                        facebook.getUser(),
//                        'Get user id from persistent store.');
//  };
//
//  exports.testGetUserAndAccessTokenFromSignedRequestNotSession = function(assert) {
//    facebook = new PersistentFBPublic(array(
//                                         'appId'  : self::APP_ID,
//                                         'secret' : self::SECRET
//                                       ));
//
//    _REQUEST['signed_request'] = self::kValidSignedRequest;
//    facebook.publicSetPersistentData('user_id', 41572);
//    facebook.publicSetPersistentData('access_token',
//                                       self::kExpiredAccessToken);
//    assert.notEqual('41572', facebook.getUser(),
//                           'Got user from session instead of signed request.');
//    assert.equal('1677846385', facebook.getUser(),
//                        'Failed to get correct user ID from signed request.');
//    assert.notEqual(
//      self::kExpiredAccessToken,
//      facebook.getAccessToken(),
//      'Got access token from session instead of signed request.');
//    assert.NotEmpty(
//      facebook.getAccessToken(),
//      'Failed to extract an access token from the signed request.');
//  };
//
//  exports.testGetUserWithoutCodeOrSignedRequestOrSession = function(assert) {
//    facebook = new PersistentFBPublic(array(
//                                         'appId'  : self::APP_ID,
//                                         'secret' : self::SECRET
//                                       ));
//
//    // deliberately leave _REQUEST and _SESSION empty
//    assert.Empty(_REQUEST,
//                       'GET, POST, and COOKIE params exist even though '.
//                       'they should.  Test cannot succeed unless all of '.
//                       '_REQUEST is empty.');
//    assert.Empty(_SESSION,
//                       'Session is carrying state and should not be.');
//    assert.Empty(facebook.getUser(),
//                       'Got a user id, even without a signed request, '.
//                       'access token, or session variable.');
//    assert.Empty(_SESSION,
//                       'Session superglobal incorrectly populated by getUser.');
//  };

function generateMD5HashOfRandomValue() {
  //return md5(uniqid(mt_rand(), true));
  return crypto.createHash('md5').update(Math.random() + Date.now).digest('hex');
}

//  protected function setUp() {
//    parent::setUp();
//  }
//
//  protected function tearDown() {
//    this.clearSuperGlobals();
//    parent::tearDown();
//  }
//
//  protected function clearSuperGlobals() {
//    unset(_SERVER['HTTPS']);
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//    _SESSION = array();
//    _COOKIE = array();
//    _REQUEST = array();
//    _POST = array();
//    _GET = array();
//    if (session_id()) {
//      session_destroy();
//    }
//  }
//
//  /**
//   * Checks that the correct args are a subset of the returned obj
//   * @param  array correct The correct array values
//   * @param  array actual  The values in practice
//   * @param  string message to be shown on failure
//   */
//  protected function assertIsSubset(correct, actual, msg='') {
//    foreach (correct as key : value) {
//      actual_value = actual[key];
//      newMsg = (strlen(msg) ? (msg.' ') : '').'Key: '.key;
//      assert.equal(value, actual_value, newMsg);
//    }
//  }
//}
//
//class TransientFacebook extends BaseFacebook {
//  protected function setPersistentData(key, value) {}
//  protected function getPersistentData(key, default = false) {
//    return default;
//  }
//  protected function clearPersistentData(key) {}
//  protected function clearAllPersistentData() {}
//}
//
//class FBRecordURL extends TransientFacebook {
//  private url;
//
//  protected function _oauthRequest(url, params) {
//    this.url = url;
//  }
//
//  public function getRequestedURL() {
//    return this.url;
//  }
//}
//
//class FBPublic extends TransientFacebook {
//  public static function publicBase64UrlDecode(input) {
//    return self::base64UrlDecode(input);
//  }
//  public function publicParseSignedRequest(input) {
//    return this.parseSignedRequest(input);
//  }
//}
//
//class PersistentFBPublic extends Facebook {
//  public function publicParseSignedRequest(input) {
//    return this.parseSignedRequest(input);
//  }
//
//  public function publicSetPersistentData(key, value) {
//    this.setPersistentData(key, value);
//  }
//}
//
//class FBCode extends Facebook {
//  public function publicGetCode() {
//    return this.getCode();
//  }
//
//  public function setCSRFStateToken() {
//    this.establishCSRFTokenState();
//  }
//
//  public function getCSRFStateToken() {
//    return this.getPersistentData('state');
//  }
//}
//
//class FBAccessToken extends TransientFacebook {
//  public function publicGetApplicationAccessToken() {
//    return this.getApplicationAccessToken();
//  }
//}
//
//class FBGetCurrentURLFacebook extends TransientFacebook {
//  public function publicGetCurrentUrl() {
//    return this.getCurrentUrl();
//  }
//}

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
  
  var transport = http;
  if (options.https) {
    transport = https;
    delete options.https;
  }
  
  options.host = 'localhost';
  options.port = 8889;
  options.path = options.path || '/';
  if (!options.method) {
    options.method = options.post ? 'POST' : 'GET';
  }
  
  if (options.https) {
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
