var fbsdk = require('./facebook');

var APP_ID = '117743971608120';
var SECRET = '943716006e74d9b9283d4d5d8ab93204';

//  const MIGRATED_APP_ID = '174236045938435';
//  const MIGRATED_SECRET = '0073dce2d95c4a5c2922d1827ea0cca6';

var VALID_EXPIRED_SESSION = {
  'access_token' : '117743971608120|2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385|NF_2DDNxFBznj2CuwiwabHhTAHc.',
  'expires'      : '1281049200',
  'secret'       : 'u0QiRGAwaPCyQ7JE_hiz1w__',
  'session_key'  : '2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385',
  'sig'          : '7a9b063de0bef334637832166948dcad',
  'uid'          : '1677846385'
};

//  private static VALID_SIGNED_REQUEST = '1sxR88U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';
//  private static NON_TOSSED_SIGNED_REQUEST = 'c0Ih6vYvauDwncv0n0pndr0hP0mvZaJPQDPt6Z43O0k.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiJ9';

exports.testConstructor = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  test.equal(facebook.appId, APP_ID,
                      'Expect the App ID to be set.');
  test.equal(facebook.apiSecret, SECRET,
                      'Expect the API secret to be set.');
  test.ok(!facebook.cookieSupport,
                     'Expect Cookie support to be off.');
  test.done();
};

exports.testConstructorWithCookie = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET,
    'cookie' : true
  });
  test.equal(facebook.appId, APP_ID,
                      'Expect the App ID to be set.');
  test.equal(facebook.apiSecret, SECRET,
                      'Expect the API secret to be set.');
  test.ok(facebook.cookieSupport,
                    'Expect Cookie support to be on.');
  test.done();
};

exports.testConstructorWithFileUpload = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'      : APP_ID,
    'secret'     : SECRET,
    'fileUpload' : true
  });
  test.equal(facebook.appId, APP_ID,
                      'Expect the App ID to be set.');
  test.equal(facebook.apiSecret, SECRET,
                      'Expect the API secret to be set.');
  test.ok(facebook.fileUploadSupport,
                    'Expect file upload support to be on.');
  test.done();
};

exports.testSetAppId = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  facebook.appId = 'dummy';
  test.equal(facebook.appId, 'dummy',
                      'Expect the App ID to be dummy.');
  test.done();
};

exports.testSetAPISecret = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  facebook.apiSecret = 'dummy';
  test.equal(facebook.apiSecret, 'dummy',
                      'Expect the API secret to be dummy.');
  test.done();
};

exports.testDefaultBaseDomain = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET,
    'domain' : 'fbrell.com'
  });
  test.equal(facebook.baseDomain, 'fbrell.com');
  test.done();
};

exports.testSetCookieSupport = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  test.ok(!facebook.cookieSupport,
                     'Expect Cookie support to be off.');
  facebook.cookieSupport = true;
  test.ok(facebook.cookieSupport,
                    'Expect Cookie support to be on.');
  test.done();
};

//  exports.testIgnoreDeleteSetCookie = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//      'cookie' : true,
//    });
//    cookieName = 'fbs_' . APP_ID;
//    test.ok(!isset(_COOKIE[cookieName]),
//                       'Expect Cookie to not exist.');
//    facebook.setSession(null);
//    test.ok(!isset(_COOKIE[cookieName]),
//                       'Expect Cookie to not exist.');
//  }

exports.testSetFileUploadSupport = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  test.ok(!facebook.fileUploadSupport,
                     'Expect file upload support to be off.');
  facebook.fileUploadSupport = true;
  test.ok(facebook.fileUploadSupport,
                    'Expect file upload support to be on.');
  test.done();
};

exports.testSetNullSession = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  facebook.setSession(null);
  test.ok(facebook.getSession() === null,
                    'Expect null session back.');
  test.done();
};

exports.testNonUserAccessToken = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET,
    'cookie' : true
  });
  test.ok(facebook.getAccessToken() ==
                    APP_ID+'|'+SECRET,
                    'Expect appId|secret.');
  test.done();
};

exports.testSetSession = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET,
    'cookie' : true
  });
  facebook.setSession(VALID_EXPIRED_SESSION);
  test.ok(facebook.getUser() ==
                    VALID_EXPIRED_SESSION['uid'],
                    'Expect uid back.');
  test.ok(facebook.getAccessToken() ==
                    VALID_EXPIRED_SESSION['access_token'],
                    'Expect access token back.');
  test.done();
};

//  exports.testGetSessionFromCookie = function(test) {
//    cookieName = 'fbs_' . APP_ID;
//    session = VALID_EXPIRED_SESSION;
//    _COOKIE[cookieName] = '"' . http_build_query(session) . '"';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//      'cookie' : true,
//    });
//
//    // since we're serializing and deserializing the array, we cannot rely on
//    // positions being the same, so we do a ksort before comparison
//    loaded_session = facebook.getSession();
//    ksort(loaded_session);
//    ksort(session);
//    test.equal(loaded_session, session,
//                        'Expect session back.');
//    unset(_COOKIE[cookieName]);
//  }
//
//  exports.testInvalidGetSessionFromCookie = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//      'cookie' : true,
//    });
//    cookieName = 'fbs_' . APP_ID;
//    session = VALID_EXPIRED_SESSION;
//    session['uid'] = 'make me invalid';
//    _COOKIE[cookieName] = http_build_query(session);
//
//    test.ok(facebook.getSession() === null,
//                      'Expect no session back.');
//    unset(_COOKIE[cookieName]);
//  }
//
//  exports.testSessionFromQueryString = function(test) {
//    // @style-override allow json_encode call
//    _REQUEST['session'] = json_encode(VALID_EXPIRED_SESSION);
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//
//    test.equal(facebook.getUser(),
//                        VALID_EXPIRED_SESSION['uid'],
//                        'Expect uid back.');
//    unset(_REQUEST['session']);
//  }
//
//  exports.testInvalidSessionFromQueryString = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//
//    params = {
//      'fb_sig_in_iframe' : 1,
//      'fb_sig_user' : '1677846385',
//      'fb_sig_session_key' :
//        '2.NdKHtYIuB0EcNSHOvqAKHg__.86400.1258092000-1677846385',
//      'fb_sig_ss' : 'AdCOu5nhDiexxRDLwZfqnA__',
//      'fb_sig' : '1949f256171f37ecebe00685ce33bf17',
//    );
//    foreach(params as key : value) {
//      _GET[key] = value;
//    }
//
//    test.equal(facebook.getUser(), null,
//                        'Expect uid back.');
//    foreach(params as key : value) {
//      unset(_GET[key]);
//    }
//  }

exports.testGetUID = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  var session = VALID_EXPIRED_SESSION;
  facebook.setSession(session);
  test.equal(facebook.getUser(), session['uid'],
                      'Expect dummy uid back.');
  test.done();
};

exports.testAPIWithoutSession = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  facebook.api({
    'method' : 'fql.query',
    'query' : 'SELECT name FROM user WHERE uid=4'
  }, function(response) {
    test.equal(response.length, 1,
                        'Expect one row back.');
    test.equal(response[0]['name'], 'Mark Zuckerberg',
                        'Expect the name back.');
    test.done();
  });
};

exports.testAPIWithSession = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });
  facebook.setSession(VALID_EXPIRED_SESSION);

  // this is strange in that we are expecting a session invalid error vs a
  // signature invalid error. basically we're just making sure session based
  // signing is working, not that the api call is returning data.
  response = facebook.api({
    'method' : 'fql.query',
    'query' : 'SELECT name FROM profile WHERE id=4'
  }, function(response) {
    this.fail('Should not get here.');
  }, function(error) {
    test.ok(typeof error == 'object');
    test.equal(error.error_msg, 'Invalid OAuth 2.0 Access Token',
                       'Expect the invalid session message.');
    test.equal(error.error_code, 190,
                       'expect code');
    test.done();
  });
};

exports.testAPIGraphPublicData = function(test) {
  var facebook = new fbsdk.Facebook({
    'appId'  : APP_ID,
    'secret' : SECRET
  });

  response = facebook.api('/naitik', function(response) {
    test.equal(response['id'], '5526183', 'should get expected id.');
    test.done();
  });
};

// TODO: this triggers a problem in restler
//exports.testGraphAPIWithSession = function(test) {
//  var facebook = new fbsdk.Facebook({
//    'appId'  : APP_ID,
//    'secret' : SECRET
//  });
//  facebook.setSession(VALID_EXPIRED_SESSION);
//
//  response = facebook.api('/me', function() {
//    this.fail('Should not get here.');
//  }, function(error) {
//    // means the server got the access token
//    msg = 'OAuthException: Error validating access token.';
//    test.equal(msg, e,
//                        'Expect the invalid session message.');
//    // also ensure the session was reset since it was invalid
//    test.equal(facebook.getSession(), null,
//                        'Expect the session to be reset.');
//  });
//};
//
// TODO: same restler problem
//exports.testGraphAPIMethod = function(test) {
//  var facebook = new fbsdk.Facebook({
//    'appId'  : APP_ID,
//    'secret' : SECRET,
//  });
//
//  response = facebook.api('/naitik', { method:'DELETE' }, function() {
//    this.fail('Should not get here.');
//  }, function(error) {
//    console.log(error);
//    // ProfileDelete means the server understood the DELETE
//    msg = 'OAuthException: An access token is required to request this resource.';
//    test.equal(msg, e,
//                        'Expect the invalid session message.');
//  });
//}
//
//  exports.testGraphAPIOAuthSpecError = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : MIGRATED_APP_ID,
//      'secret' : MIGRATED_SECRET,
//    });
//
//    try {
//      response = facebook.api('/me', {
//        'client_id' : MIGRATED_APP_ID});
//
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      // means the server got the access token
//      msg = 'invalid_request: An active access token must be used '.
//             'to query information about the current user.';
//      test.equal(msg, (string) e,
//                          'Expect the invalid session message.');
//      // also ensure the session was reset since it was invalid
//      test.equal(facebook.getSession(), null,
//                          'Expect the session to be reset.');
//    }
//  }
//
//  exports.testGraphAPIMethodOAuthSpecError = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : MIGRATED_APP_ID,
//      'secret' : MIGRATED_SECRET,
//    });
//
//    try {
//      response = facebook.api('/daaku.shah', 'DELETE', {
//        'client_id' : MIGRATED_APP_ID});
//      this.fail('Should not get here.');
//    } catch(FacebookApiException e) {
//      // ProfileDelete means the server understood the DELETE
//      msg = 'invalid_request: Test account not associated with application: '.
//        'The test account is not associated with this application.';
//      test.equal(msg, (string) e,
//                          'Expect the invalid session message.');
//    }
//  }
//
//  exports.testCurlFailure = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//
//    if (!defined('CURLOPT_TIMEOUT_MS')) {
//      // can't test it if we don't have millisecond timeouts
//      return;
//    }
//
//    try {
//      // we dont expect facebook will ever return in 1ms
//      Facebook::CURL_OPTS[CURLOPT_TIMEOUT_MS] = 1;
//      facebook.api('/naitik');
//    } catch(FacebookApiException e) {
//      unset(Facebook::CURL_OPTS[CURLOPT_TIMEOUT_MS]);
//      test.equal(
//        CURLE_OPERATION_TIMEOUTED, e.getCode(), 'expect timeout');
//      test.equal('CurlException', e.getType(), 'expect type');
//      return;
//    }
//
//    this.fail('Should not get here.');
//  }
//
//  exports.testGraphAPIWithOnlyParams = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//
//    response = facebook.api('/331218348435/feed',
//      {'limit' : 1, 'access_token' : ''});
//    test.equal(1, count(response['data']), 'should get one entry');
//    test.ok(
//      strstr(response['paging']['next'], 'limit=1') !== false,
//      'expect the same limit back in the paging urls'
//    );
//  }
//
//  exports.testLoginURLDefaults = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl = rawurlencode('http://fbrell.com/examples');
//    this.assertNotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testLoginURLDefaultsDropSessionQueryParam = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples?session=xx42xx';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    test.ok(strpos(facebook.getLoginUrl(), expectEncodedUrl) > -1,
//                      'Expect the current url to exist.');
//    test.ok(!strpos(facebook.getLoginUrl(), 'xx42xx'),
//                       'Expect the session param to be dropped.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testLoginURLDefaultsDropSessionQueryParamButNotOthers = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples?session=xx42xx&do_not_drop=xx43xx';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    test.ok(!strpos(facebook.getLoginUrl(), 'xx42xx'),
//                       'Expect the session param to be dropped.');
//    test.ok(strpos(facebook.getLoginUrl(), 'xx43xx') > -1,
//                      'Expect the do_not_drop param to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testLoginURLCustomNext = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    next = 'http://fbrell.com/custom';
//    loginUrl = facebook.getLoginUrl({
//      'next' : next,
//      'cancel_url' : next
//    });
//    currentEncodedUrl = rawurlencode('http://fbrell.com/examples');
//    expectedEncodedUrl = rawurlencode(next);
//    this.assertNotNull(strpos(loginUrl, expectedEncodedUrl),
//                         'Expect the custom url to exist.');
//    test.ok(!strpos(loginUrl, currentEncodedUrl),
//                      'Expect the current url to not exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testLogoutURLDefaults = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl = rawurlencode('http://fbrell.com/examples');
//    this.assertNotNull(strpos(facebook.getLogoutUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testLoginStatusURLDefaults = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl = rawurlencode('http://fbrell.com/examples');
//    this.assertNotNull(strpos(facebook.getLoginStatusUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testLoginStatusURLCustom = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl1 = rawurlencode('http://fbrell.com/examples');
//    okUrl = 'http://fbrell.com/here1';
//    encodedUrl2 = rawurlencode(okUrl);
//    loginStatusUrl = facebook.getLoginStatusUrl({
//      'ok_session' : okUrl,
//    });
//    this.assertNotNull(strpos(loginStatusUrl, encodedUrl1),
//                         'Expect the current url to exist.');
//    this.assertNotNull(strpos(loginStatusUrl, encodedUrl2),
//                         'Expect the custom url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testMagicQuotesQueryString = function(test) {
//    if (!get_magic_quotes_gpc()) {
//      // this test cannot run without get_magic_quotes_gpc(), and the setting
//      // cannot be modified at runtime, so we're shit out of luck. thanks php.
//      return;
//    }
//
//    // @style-override allow json_encode call
//    _REQUEST['session'] = addslashes(
//      json_encode(VALID_EXPIRED_SESSION));
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//
//    test.equal(facebook.getUser(),
//                        VALID_EXPIRED_SESSION['uid'],
//                        'Expect uid back.');
//    unset(_REQUEST['session']);
//  }
//
//  exports.testMagicQuotesCookie = function(test) {
//    if (!get_magic_quotes_gpc()) {
//      // this test cannot run without get_magic_quotes_gpc(), and the setting
//      // cannot be modified at runtime, so we're shit out of luck. thanks php.
//      return;
//    }
//
//    cookieName = 'fbs_' . APP_ID;
//    session = VALID_EXPIRED_SESSION;
//    _COOKIE[cookieName] = addslashes('"' . http_build_query(session) . '"');
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//      'cookie' : true,
//    });
//
//    // since we're serializing and deserializing the array, we cannot rely on
//    // positions being the same, so we do a ksort before comparison
//    loaded_session = facebook.getSession();
//    ksort(loaded_session);
//    ksort(session);
//    test.equal(loaded_session, session,
//                        'Expect session back.');
//    unset(_COOKIE[cookieName]);
//  }
//
//  exports.testNonDefaultPort = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com:8080';
//    _SERVER['REQUEST_URI'] = '/examples';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl = rawurlencode('http://fbrell.com:8080/examples');
//    this.assertNotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//  }
//
//  exports.testSecureCurrentUrl = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com';
//    _SERVER['REQUEST_URI'] = '/examples';
//    _SERVER['HTTPS'] = 'on';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl = rawurlencode('https://fbrell.com/examples');
//    this.assertNotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//    unset(_SERVER['HTTPS']);
//  }
//
//  exports.testSecureCurrentUrlWithNonDefaultPort = function(test) {
//    _SERVER['HTTP_HOST'] = 'fbrell.com:8080';
//    _SERVER['REQUEST_URI'] = '/examples';
//    _SERVER['HTTPS'] = 'on';
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    encodedUrl = rawurlencode('https://fbrell.com:8080/examples');
//    this.assertNotNull(strpos(facebook.getLoginUrl(), encodedUrl),
//                         'Expect the current url to exist.');
//    unset(_SERVER['HTTP_HOST']);
//    unset(_SERVER['REQUEST_URI']);
//    unset(_SERVER['HTTPS']);
//  }
//
//  exports.testIgnoreArgSeparatorForCookie = function(test) {
//    cookieName = 'fbs_' . APP_ID;
//    session = VALID_EXPIRED_SESSION;
//    _COOKIE[cookieName] = '"' . http_build_query(session) . '"';
//    ini_set('arg_separator.output', '&amp;');
//    // ensure we're testing what we expect
//    test.equal(http_build_query({'a' : 1, 'b' : 2)),
//                        'a=1&amp;b=2');
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//      'cookie' : true,
//    });
//
//    // since we're serializing and deserializing the array, we cannot rely on
//    // positions being the same, so we do a ksort before comparison
//    loaded_session = facebook.getSession();
//    ksort(loaded_session);
//    ksort(session);
//    test.equal(loaded_session, session,
//                        'Expect session back.');
//    unset(_COOKIE[cookieName]);
//    ini_set('arg_separator.output', '&');
//  }
//
//  exports.testAppSecretCall = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    response = facebook.api('/' . APP_ID . '/insights');
//    test.ok(count(response['data']) > 0,
//                      'Expect some data back.');
//  }
//
//  exports.testBase64UrlEncode = function(test) {
//    input = 'Facebook rocks';
//    output = 'RmFjZWJvb2sgcm9ja3M';
//
//    test.equal(FBPublic::publicBase64UrlDecode(output), input);
//  }
//
//  exports.testSignedToken = function(test) {
//    facebook = new FBPublic({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    payload = facebook.publicParseSignedRequest(VALID_SIGNED_REQUEST);
//    this.assertNotNull(payload, 'Expected token to parse');
//    session = facebook.publicCreateSessionFromSignedRequest(payload);
//    test.equal(session['uid'], VALID_EXPIRED_SESSION['uid']);
//    test.equal(facebook.getSignedRequest(), null);
//    _REQUEST['signed_request'] = VALID_SIGNED_REQUEST;
//    test.equal(facebook.getSignedRequest(), payload);
//    unset(_REQUEST['signed_request']);
//  }
//
//  exports.testSignedTokenInQuery = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    _REQUEST['signed_request'] = VALID_SIGNED_REQUEST;
//    this.assertNotNull(facebook.getSession());
//    unset(_REQUEST['signed_request']);
//  }
//
//  exports.testNonTossedSignedtoken = function(test) {
//    facebook = new FBPublic({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//    payload = facebook.publicParseSignedRequest(
//      NON_TOSSED_SIGNED_REQUEST);
//    this.assertNotNull(payload, 'Expected token to parse');
//    session = facebook.publicCreateSessionFromSignedRequest(payload);
//    this.assertNull(session);
//    this.assertNull(facebook.getSignedRequest());
//    _REQUEST['signed_request'] = NON_TOSSED_SIGNED_REQUEST;
//    test.equal(facebook.getSignedRequest(),
//      {'algorithm' : 'HMAC-SHA256'});
//    unset(_REQUEST['signed_request']);
//  }
//
//  exports.testBundledCACert = function(test) {
//    var facebook = new fbsdk.Facebook({
//      'appId'  : APP_ID,
//      'secret' : SECRET,
//    });
//
//    // use the bundled cert from the start
//    Facebook::CURL_OPTS[CURLOPT_CAINFO] = dirname(__FILE__) . '/../src/fb_ca_chain_bundle.crt';
//    response = facebook.api('/naitik');
//
//    unset(Facebook::CURL_OPTS[CURLOPT_CAINFO]);
//    test.equal(
//      response['id'], '5526183', 'should get expected id.');
//  }
//
//}
//
//class FBPublic extends Facebook {
//  public static function publicBase64UrlDecode(input) {
//    return base64UrlDecode(input);
//  }
//  public function publicParseSignedRequest(intput) {
//    return this.parseSignedRequest(intput);
//  }
//  public function publicCreateSessionFromSignedRequest(payload) {
//    return this.createSessionFromSignedRequest(payload);
//  }
//}