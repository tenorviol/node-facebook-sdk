/**
 * Copyright 2011 Christopher Johnson
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

var crypto = require('crypto');
var http = require('http');
var https = require('https');
var qs = require('querystring');
var _url = require('url');

exports.Facebook = Facebook;

/**
 * Thrown when an API call returns an exception.
 *
 * @param array result The result from the API server
 */
var FacebookApiException = function (result) {
  // The result from the API server that represents the exception information.
  this.result = result;

  this.code = result.error_code || 0;

  if (result.error_description) {
    // OAuth 2.0 Draft 10 style
    this.message = result.error_description;
  } else if (result.error && result.error.message) {
    // OAuth 2.0 Draft 00 style
    this.message = result.error.message;
  } else if (result.error_msg) {
    // Rest server style
    this.message = result.error_msg;
  } else {
    this.message = 'Unknown Error. Check getResult()';
  }
};

FacebookApiException.prototype = {
  /**
   * Return the associated result object returned by the API server.
   *
   * @return {Object} the result from the API server
   */
  getResult: function() {
    return this.result;
  },

  /**
   * Returns the associated type for the error. This will default to
   * 'Exception' when a type is not available.
   *
   * @return {String}
   */
  getType: function() {
    if (this.result.error) {
      var error = this.result.error;
      if (typeof error == 'string') {
        // OAuth 2.0 Draft 10 style
        return error;
      } else if (error.type) {
        // OAuth 2.0 Draft 00 style
        return error.type;
      }
    }

    return 'Exception';
  },

  /**
   * To make debugging easier.
   *
   * @return {String} the string representation of the error
   */
  toString: function() {
    var str = this.getType() + ': ';
    if (this.code != 0) {
      str += this.code + ': ';
    }
    return str + this.message;
  }
};

/**
 * Provides access to the Facebook Platform.  This class provides
 * a majority of the functionality needed, but the class is abstract
 * because it is designed to be sub-classed.  The subclass must
 * implement the three abstract methods listed at the bottom of
 * the file.
 */

/**
 * Initialize a Facebook Application.
 *
 * The configuration:
 * - appId: the application ID
 * - secret: the application secret
 * - fileUpload: (optional) boolean indicating if file uploads are enabled
 *
 * @param array config The application configuration
 */
function Facebook(config) {
  var facebook;
  if (this instanceof Facebook) {
    facebook = this;
  } else {
    facebook = function (req, res, next) {
      req.facebook = new Facebook(config);
      req.facebook.request = req;
      req.facebook.response = res;
      next();
    };
  }
  for (var i in config) {
    facebook[i] = config[i];
  }
  return facebook;
}
//  public function __construct(config) {
//    this.setAppId(config['appId']);
//    this.setApiSecret(config['secret']);
//    if (isset(config['fileUpload'])) {
//      this.setFileUploadSupport(config['fileUpload']);
//    }
//
//    state = this.getPersistentData('state');
//    if (!empty(state)) {
//      this.state = this.getPersistentData('state');
//    }
//  }

Facebook.prototype = {

  VERSION : '3.0.0',
//
//  /**
//   * Default options for curl.
//   */
//  public static CURL_OPTS = array(
//    CURLOPT_CONNECTTIMEOUT : 10,
//    CURLOPT_RETURNTRANSFER : true,
//    CURLOPT_TIMEOUT        : 60,
//    CURLOPT_USERAGENT      : 'facebook-php-3.0',
//  );

  /**
   * List of query parameters that get automatically dropped when rebuilding
   * the current URL.
   */
  DROP_QUERY_PARAMS : [
    'code',
    'state',
    'signed_request'
  ],

  /**
   * Maps aliases to Facebook domains.
   */
  DOMAIN_MAP : {
    api       : 'https://api.facebook.com/',
    api_video : 'https://api-video.facebook.com/',
    api_read  : 'https://api-read.facebook.com/',
    graph     : 'https://graph.facebook.com/',
    www       : 'https://www.facebook.com/'
  },

//  /**
//   * The ID of the Facebook user, or 0 if the user is logged out.
//   *
//   * @var integer
//   */
//  protected user;
//
//  /**
//   * The data from the signed_request token.
//   */
//  protected signedRequest;
//
//  /**
//   * A CSRF state variable to assist in the defense against CSRF attacks.
//   */
//  protected state;
//
//  /**
//   * The OAuth access token received in exchange for a valid authorization
//   * code.  null means the access token has yet to be determined.
//   *
//   * @var string
//   */
//  protected accessToken = null;

  /**
   * Sets the access token for api calls.  Use this if you get
   * your access token by other means and just want the SDK
   * to use it.
   *
   * @param string access_token an access token.
   * @return BaseFacebook
   */
  setAccessToken : function (access_token) {
    this.accessToken = access_token;
    return this;
  },

  /**
   * Determines the access token that should be used for API calls.
   * The first time this is called, this.accessToken is set equal
   * to either a valid user access token, or it's set to the application
   * access token if a valid user access token wasn't available.  Subsequent
   * calls return whatever the first call returned.
   *
   * @return string The access token
   */
  getAccessToken : function () {
    if (this.accessToken) {
      // we've done this already and cached it.  Just return.
      return this.accessToken;
    }

    // first establish access token to be the application
    // access token, in case we navigate to the /oauth/access_token
    // endpoint, where SOME access token is required.
    this.setAccessToken(this._getApplicationAccessToken());
    var user_access_token = this._getUserAccessToken();
    if (user_access_token) {
      this.setAccessToken(user_access_token);
    }

    return this.accessToken;
  },

  /**
   * Determines and returns the user access token, first using
   * the signed request if present, and then falling back on
   * the authorization code if present.  The intent is to
   * return a valid user access token, or false if one is determined
   * to not be available.
   *
   * @return string A valid user access token, or false if one
   *                could not be determined.
   */
  _getUserAccessToken : function () {
    // first, consider a signed request if it's supplied.
    // if there is a signed request, then it alone determines
    // the access token.
    var signed_request = this.getSignedRequest();
    if (signed_request) {
      if (signed_request.oauth_token !== undefined) {
        var access_token = signed_request.oauth_token;
        this._setPersistentData('access_token', access_token);
        return access_token;
      }

      // signed request states there's no access token, so anything
      // stored should be cleared.
      this._clearAllPersistentData();
      return false; // respect the signed request's data, even
                    // if there's an authorization code or something else
    }

    var code = this._getCode();
    if (code && code != this._getPersistentData('code')) {
      var access_token = this.getAccessTokenFromCode(code);
      if (access_token) {
        this._setPersistentData('code', code);
        this._setPersistentData('access_token', access_token);
        return access_token;
      }

      // code was bogus, so everything based on it should be invalidated.
      this._clearAllPersistentData();
      return false;
    }

    // as a fallback, just return whatever is in the persistent
    // store, knowing nothing explicit (signed request, authorization
    // code, etc.) was present to shadow it (or we saw a code in _REQUEST,
    // but it's the same as what's in the persistent store)
    return this._getPersistentData('access_token');
  },

  /**
   * Get the data from a signed_request token.
   *
   * @return string The base domain
   */
  getSignedRequest : function () {
    if (!this.signedRequest) {
      var signed_request = this._getRequest('signed_request');
      if (signed_request) {
        this.signedRequest = this._parseSignedRequest(signed_request);
      }
    }
    return this.signedRequest;
  },

  _getRequest : function (key) {
    if (!this.request) {
      return null;
    }
    var value = this.request.body && this.request.body[key];
    if (!value) {
      // TODO : GET
    }
    return value;
  },

  /**
   * Get the UID of the connected user, or 0
   * if the Facebook user is not connected.
   *
   * @return string the UID if available.
   */
  getUser : function () {
    if (this.user) {
      // we've already determined this and cached the value.
      return this.user;
    }

    return this.user = this._getUserFromAvailableData();
  },

  /**
   * Determines the connected user by first examining any signed
   * requests, then considering an authorization code, and then
   * falling back to any persistent store storing the user.
   *
   * @return integer The id of the connected Facebook user,
   *                 or 0 if no such user exists.
   */
  _getUserFromAvailableData : function () {
    // if a signed request is supplied, then it solely determines
    // who the user is.
    var signed_request = this.getSignedRequest();
    if (signed_request) {
      if (signed_request.user_id !== undefined) {
        var user = signed_request.user_id;
        this._setPersistentData('user_id', user);
        return user;
      }

      // if the signed request didn't present a user id, then invalidate
      // all entries in any persistent store.
      this._clearAllPersistentData();
      return 0;
    }

    var user = this._getPersistentData('user_id', 0);
    var persisted_access_token = this._getPersistentData('access_token');

    // use access_token to fetch user id if we have a user access_token, or if
    // the cached access token has changed.
    //var access_token = this.getAccessToken();
    //if (access_token &&
    //    access_token != this.getApplicationAccessToken() &&
    //    !(user && persisted_access_token == access_token)) {
    //  user = this.getUserFromAccessToken();
    //  if (user) {
    //    this.setPersistentData('user_id', user);
    //  } else {
    //    this._clearAllPersistentData();
    //  }
    //}

    return user;
  },

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the params.
   *
   * The parameters:
   * - redirect_uri: the url to go to after a successful login
   * - scope: comma separated list of requested extended perms
   *
   * @param array params Provide custom parameters
   * @return string The URL for the login flow
   */
  getLoginUrl : function (params) {
    this._establishCSRFTokenState();
    var currentUrl = this._getCurrentUrl();
    return this._getUrl(
      'www',
      'dialog/oauth',
      array_merge({
                    client_id : this.appId,
                    redirect_uri : currentUrl, // possibly overwritten
                    'state' : this.state
                  }, params));
  },

//  /**
//   * Get a Logout URL suitable for use with redirects.
//   *
//   * The parameters:
//   * - next: the url to go to after a successful logout
//   *
//   * @param array params Provide custom parameters
//   * @return string The URL for the logout flow
//   */
//  public function getLogoutUrl(params=array()) {
//    return this._getUrl(
//      'www',
//      'logout.php',
//      array_merge(array(
//        'next' : this.getCurrentUrl(),
//        'access_token' : this.getAccessToken(),
//      ), params)
//    );
//  }
//
//  /**
//   * Get a login status URL to fetch the status from Facebook.
//   *
//   * The parameters:
//   * - ok_session: the URL to go to if a session is found
//   * - no_session: the URL to go to if the user is not connected
//   * - no_user: the URL to go to if the user is not signed into facebook
//   *
//   * @param array params Provide custom parameters
//   * @return string The URL for the logout flow
//   */
//  public function getLoginStatusUrl(params=array()) {
//    return this._getUrl(
//      'www',
//      'extern/login_status.php',
//      array_merge(array(
//        'api_key' : this.getAppId(),
//        'no_session' : this.getCurrentUrl(),
//        'no_user' : this.getCurrentUrl(),
//        'ok_session' : this.getCurrentUrl(),
//        'session_version' : 3,
//      ), params)
//    );
//  }

  /**
   * Make an API call.
   *
   * @return mixed The decoded response
   */
  api : function (/* polymorphic */) {
    if (typeof arguments[0] == 'object') {
      this._restserver.apply(this, arguments);
    } else {
      this._graph.apply(this, arguments);
    }
  },

  /**
   * Get the authorization code from the query parameters, if it exists,
   * and otherwise return false to signal no authorization code was
   * discoverable.
   *
   * @return mixed The authorization code, or false if the authorization
   *               code could not be determined.
   */
  _getCode : function () {
    if (!this.request || !this.request.session) {
      return false;
    }
    if (this.request.session.code) {
      if (this.state &&
          this.request.session.state === this.state) {

        // CSRF state has done its job, so clear it
        this.state = null;
        this._clearPersistentData('state');
        return this.request.session.code;
      } else {
        this._errorLog('CSRF state token does not match one provided.');
        return false;
      }
    }

    return false;
  },

//  /**
//   * Retrieves the UID with the understanding that
//   * this.accessToken has already been set and is
//   * seemingly legitimate.  It relies on Facebook's Graph API
//   * to retrieve user information and then extract
//   * the user ID.
//   *
//   * @return integer Returns the UID of the Facebook user, or 0
//   *                 if the Facebook user could not be determined.
//   */
//  _getUserFromAccessToken : function () {
//    try {
//      user_info = this.api('/me');
//      return user_info['id'];
//    } catch (FacebookApiException e) {
//      return 0;
//    }
//  }

  /**
   * Returns the access token that should be used for logged out
   * users when no authorization code is available.
   *
   * @return string The application access token, useful for gathering
   *                public information about users and applications.
   */
  _getApplicationAccessToken : function () {
    return this.appId + '|' + this.secret;
  },

  /**
   * Lays down a CSRF state token for this process.
   *
   * @return void
   */
  _establishCSRFTokenState : function () {
    if (!this.state) {
      // TODO: audit against original (check sufficient randomness) this.state = md5(uniqid(mt_rand(), true));
      this.state = crypto.createHash('md5').update(Math.random() + Date.now).digest('hex');
      this._setPersistentData('state', this.state);
    }
  },

//  /**
//   * Retrieves an access token for the given authorization code
//   * (previously generated from www.facebook.com on behalf of
//   * a specific user).  The authorization code is sent to graph.facebook.com
//   * and a legitimate access token is generated provided the access token
//   * and the user for which it was generated all match, and the user is
//   * either logged in to Facebook or has granted an offline access permission.
//   *
//   * @param string code An authorization code.
//   * @return mixed An access token exchanged for the authorization code, or
//   *               false if an access token could not be generated.
//   */
//  _getAccessTokenFromCode : function (code) {
//    if (empty(code)) {
//      return false;
//    }
//
//    try {
//      // need to circumvent json_decode by calling _oauthRequest
//      // directly, since response isn't JSON format.
//      access_token_response =
//        this._oauthRequest(
//          this._getUrl('graph', '/oauth/access_token'),
//          params = array('client_id' : this.getAppId(),
//                          'client_secret' : this.getApiSecret(),
//                          'redirect_uri' : this.getCurrentUrl(),
//                          'code' : code));
//    } catch (FacebookApiException e) {
//      // most likely that user very recently revoked authorization.
//      // In any event, we don't have an access token, so say so.
//      return false;
//    }
//
//    if (empty(access_token_response)) {
//      return false;
//    }
//
//    response_params = array();
//    parse_str(access_token_response, response_params);
//    if (!isset(response_params['access_token'])) {
//      return false;
//    }
//
//    return response_params['access_token'];
//  }

  /**
   * Invoke the old restserver.php endpoint.
   *
   * @param array params Method call object
   *
   * @return mixed The decoded response object
   * @throws FacebookApiException
   */
  _restserver : function (params, callback) {
    // generic application level parameters
    params.api_key = this.appId;
    params.format = 'json-strings';

    this._oauthRequest(
      this._getApiUrl(params.method),
      params,
      function (err, result) {
        if (err) return callback(err);
        result = JSON.parse(result);
        if (result && result.error_code) {
          callback(new FacebookApiException(result));
        } else {
          callback(null, result);
        }
      }
    );
  },

  /**
   * Invoke the Graph API.
   *
   * @param string path The path (required)
   * @param string method The http method (default 'GET')
   * @param array params The query/post data
   *
   * @return mixed The decoded response object
   * @throws FacebookApiException
   */
  _graph : function (path, method, params, callback) {
    if (typeof method !== 'string') {
      callback = params;
      params = method || {};
      method = params.method || 'GET';
    }
    if (typeof params === 'function') {
      callback = params;
      params = {};
    }
    params.method = method; // method override as we always do a POST

    this._oauthRequest(
      this._getUrl('graph', path),
      params,
      function (err, result) {
        if (err) return callback(err);
        result = JSON.parse(result);
        if (result && result.error) {
          callback(new FacebookApiException(result));
        }
        callback(null, result);
      }
    );
  },

  /**
   * Make a OAuth Request.
   *
   * @param string url The path (required)
   * @param array params The query/post data
   *
   * @return string The decoded response object
   * @throws FacebookApiException
   */
  _oauthRequest : function (url, params, callback) {
    if (!params.access_token) {
      params.access_token = this.getAccessToken();
    }

    // json encode all params values that are not strings
    // TODO : untested
    for (var key in params) {
      if (typeof params[key] !== 'string') {
        params[key] = JSON.stringify(params[key]);
      }
    }

    this._makeRequest(url, params, callback);
  },

  /**
   * Makes an HTTP request. This method can be overridden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param string url The URL to make the request to
   * @param array params The parameters to use for the POST body
   * @param CurlHandler ch Initialized curl handle
   *
   * @return string The response text
   */
  _makeRequest : function (url, params, callback) {
    var parse = _url.parse(url);
    
    var transport = http;
    if (parse.protocol == 'https:') {
      transport = https;
    }
    
    var options = {
      host: parse.hostname,
      path: parse.pathname,
      method: 'POST',
      agent: false
    };
    if (parse.port) {
      options.port = parse.port;
    }
    
    // TODO: header 'Expect: 100-continue'? This was a part of the original curl makeRequest
    
    var request = transport.request(options, function (result) {
      result.setEncoding('utf8');
    
      var body = '';
      result.on('data', function(chunk) {
        body += chunk;
      });
    
      result.on('end', function() {
        //clearTimeout(timeout);
        callback(null, body);
      });
    });
    
    // TODO?
    // if (this.useFileUploadSupport()) {
    //   opts[CURLOPT_POSTFIELDS] = params;
    // } else {
    //   opts[CURLOPT_POSTFIELDS] = http_build_query(params, null, '&');
    // }
    
    request.write(qs.stringify(params));
    request.end();
    
    // TODO
    //var timeout = setTimeout(function () {
    //  request.abort();
    //  var e = new FacebookApiException({
    //    error_code : 28 /* CURLE_OPERATION_TIMEDOUT */,
    //    error      : {
    //      message : 'timeout',
    //      type    : 'CurlException'
    //    }
    //  });
    //  callback(e);
    //}, this.timeout);
    
    //if (!ch) {
    //  ch = curl_init();
    //}
    //
    //opts = self::CURL_OPTS;
    //if (this.useFileUploadSupport()) {
    //  opts[CURLOPT_POSTFIELDS] = params;
    //} else {
    //  opts[CURLOPT_POSTFIELDS] = http_build_query(params, null, '&');
    //}
    //opts[CURLOPT_URL] = url;
    //
    //// disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
    //// for 2 seconds if the server does not support this header.
    //if (isset(opts[CURLOPT_HTTPHEADER])) {
    //  existing_headers = opts[CURLOPT_HTTPHEADER];
    //  existing_headers[] = 'Expect:';
    //  opts[CURLOPT_HTTPHEADER] = existing_headers;
    //} else {
    //  opts[CURLOPT_HTTPHEADER] = array('Expect:');
    //}
    //
    //curl_setopt_array(ch, opts);
    //result = curl_exec(ch);
    //
    //if (curl_errno(ch) == 60) { // CURLE_SSL_CACERT
    //  this._errorLog('Invalid or no certificate authority found, '.
    //                 'using bundled information');
    //  curl_setopt(ch, CURLOPT_CAINFO,
    //              dirname(__FILE__) . '/fb_ca_chain_bundle.crt');
    //  result = curl_exec(ch);
    //}
    //
    //if (result === false) {
    //  e = new FacebookApiException(array(
    //    'error_code' : curl_errno(ch),
    //    'error' : array(
    //    'message' : curl_error(ch),
    //    'type' : 'CurlException',
    //    ),
    //  ));
    //  curl_close(ch);
    //  throw e;
    //}
    //curl_close(ch);
    //return result;
  },

  /**
   * Parses a signed_request and validates the signature.
   *
   * @param string signed_request A signed token
   * @return array The payload inside it or null if the sig is wrong
   */
  _parseSignedRequest : function (signed_request) {
    var explosion = signed_request.split('.', 2);
    var encoded_sig = explosion[0];
    var payload = explosion[1];

    // decode the data
    var sig = this._base64UrlDecode(encoded_sig);
    var data = JSON.parse(this._base64UrlDecode(payload));

    if (data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
      this._errorLog('Unknown algorithm. Expected HMAC-SHA256');
      return null;
    }

    // check sig
    var hmac = crypto.createHmac('sha256', this.secret);
    hmac.update(payload);
    var expected_sig = hmac.digest();
    if (sig !== expected_sig) {
      this._errorLog('Bad Signed JSON signature!');
      return null;
    }

    return data;
  },

  /**
   * Build the URL for api given parameters.
   *
   * @param method String the method name.
   * @return string The URL for the given parameters
   */
  _getApiUrl : function (method) {
    var READ_ONLY_CALLS = {
            'admin.getallocation' : 1,
            'admin.getappproperties' : 1,
            'admin.getbannedusers' : 1,
            'admin.getlivestreamvialink' : 1,
            'admin.getmetrics' : 1,
            'admin.getrestrictioninfo' : 1,
            'application.getpublicinfo' : 1,
            'auth.getapppublickey' : 1,
            'auth.getsession' : 1,
            'auth.getsignedpublicsessiondata' : 1,
            'comments.get' : 1,
            'connect.getunconnectedfriendscount' : 1,
            'dashboard.getactivity' : 1,
            'dashboard.getcount' : 1,
            'dashboard.getglobalnews' : 1,
            'dashboard.getnews' : 1,
            'dashboard.multigetcount' : 1,
            'dashboard.multigetnews' : 1,
            'data.getcookies' : 1,
            'events.get' : 1,
            'events.getmembers' : 1,
            'fbml.getcustomtags' : 1,
            'feed.getappfriendstories' : 1,
            'feed.getregisteredtemplatebundlebyid' : 1,
            'feed.getregisteredtemplatebundles' : 1,
            'fql.multiquery' : 1,
            'fql.query' : 1,
            'friends.arefriends' : 1,
            'friends.get' : 1,
            'friends.getappusers' : 1,
            'friends.getlists' : 1,
            'friends.getmutualfriends' : 1,
            'gifts.get' : 1,
            'groups.get' : 1,
            'groups.getmembers' : 1,
            'intl.gettranslations' : 1,
            'links.get' : 1,
            'notes.get' : 1,
            'notifications.get' : 1,
            'pages.getinfo' : 1,
            'pages.isadmin' : 1,
            'pages.isappadded' : 1,
            'pages.isfan' : 1,
            'permissions.checkavailableapiaccess' : 1,
            'permissions.checkgrantedapiaccess' : 1,
            'photos.get' : 1,
            'photos.getalbums' : 1,
            'photos.gettags' : 1,
            'profile.getinfo' : 1,
            'profile.getinfooptions' : 1,
            'stream.get' : 1,
            'stream.getcomments' : 1,
            'stream.getfilters' : 1,
            'users.getinfo' : 1,
            'users.getloggedinuser' : 1,
            'users.getstandardinfo' : 1,
            'users.hasapppermission' : 1,
            'users.isappuser' : 1,
            'users.isverified' : 1,
            'video.getuploadlimits' : 1
          };
    var name = 'api';
    if (READ_ONLY_CALLS[method.toLowerCase()]) {
      name = 'api_read';
    } else if (method.toLowerCase() === 'video.upload') {
      name = 'api_video';
    }
    return this._getUrl(name, 'restserver.php');
  },

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param name string The name of the domain
   * @param path string Optional path (without a leading slash)
   * @param params array Optional query parameters
   *
   * @return string The URL for the given parameters
   */
  _getUrl : function (name, path, params) {
    var url = this.DOMAIN_MAP[name];
    if (path) {
      if (path[0] === '/') {
        path = path.substr(1);
      }
      url += path;
    }
    if (params) {
      url += '?' + qs.stringify(params);
    }

    return url;
  },

  /**
   * Returns the Current URL, stripping it of known FB parameters that should
   * not persist.
   *
   * @return string The current URL
   */
  _getCurrentUrl : function () {
    if (this.request && this.request.headers.host) {
      var protocol = this.request.connection.encrypted ? 'https://' : 'http://';
      var host = this.request.headers.host;
    } else {
      throw new Error('No request host available');
    }

    var parts = _url.parse(this.request.url);

    var query = '';
    if (parts.query) {
      // drop known fb params
      var params = parts.query.split('&');
      var retained_params = [];
      for (var i in params) {
        var param = params[i];
        if (this._shouldRetainParam(param)) {
          retained_params.push(param);
        }
      }
      
      if (retained_params.length) {
        query = '?' + retained_params.join('&');
      }
    }

    // use port if non default
    //var port =
    //  parts.port &&
    //  ((protocol === 'http:' && parts.port !== 80) ||
    //   (protocol === 'https:' && parts.port !== 433))
    //  ? ':' + parts.port : '';

    // rebuild
    return protocol + host + parts.pathname + query;
  },

  /**
   * Returns true if and only if the key or key/value pair should
   * be retained as part of the query string.  This amounts to
   * a brute-force search of the very small list of Facebook-specific
   * params that should be stripped out.
   *
   * @param string param A key or key/value pair within a URL's query (e.g.
   *                     'foo=a', 'foo=', or 'foo'.
   *
   * @return boolean
   */
  _shouldRetainParam : function (param) {
    for (var i in this.DROP_QUERY_PARAMS) {
      var drop_query_param = this.DROP_QUERY_PARAMS[i];
      if (param.indexOf(drop_query_param + '=') === 0) {
        return false;
      }
    }
    return true;
  },

//  /**
//   * Analyzes the supplied result to see if it was thrown
//   * because the access token is no longer valid.  If that is
//   * the case, then the persistent store is cleared.
//   *
//   * @param result array A record storing the error message returned
//   *                      by a failed API call.
//   */
//  _throwAPIException : function (result) {
//    e = new FacebookApiException(result);
//    switch (e.getType()) {
//      // OAuth 2.0 Draft 00 style
//      case 'OAuthException':
//        // OAuth 2.0 Draft 10 style
//      case 'invalid_token':
//        message = e.getMessage();
//      if ((strpos(message, 'Error validating access token') !== false) ||
//          (strpos(message, 'Invalid OAuth access token') !== false)) {
//        this.setAccessToken(null);
//        this.user = 0;
//        this._clearAllPersistentData();
//      }
//    }
//
//    throw e;
//  }


  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param string msg Log message
   */
  _errorLog : function (msg) {
    var err = new Error(msg);
    console.log(err.stack);
  },

  /**
   * Base64 encoding that doesn't need to be urlencode()ed.
   * Exactly the same as base64_encode except it uses
   *   - instead of +
   *   _ instead of /
   *
   * @param string input base64UrlEncoded string
   * @return string
   */
  _base64UrlDecode : function (input) {
    return new Buffer(input.replace('-', '+').replace('_', '/'), 'base64').toString('binary');
  },

  /**
   * Each of the following four methods should be overridden in
   * a concrete subclass, as they are in the provided Facebook class.
   * The Facebook class uses PHP sessions to provide a primitive
   * persistent store, but another subclass--one that you implement--
   * might use a database, memcache, or an in-memory cache.
   *
   * @see Facebook
   */

//  /**
//   * Stores the given (key, value) pair, so that future calls to
//   * getPersistentData(key) return value. This call may be in another request.
//   *
//   * @param string key
//   * @param array value
//   *
//   * @return void
//   */
//  abstract protected function setPersistentData(key, value);
//
//  /**
//   * Get the data for key, persisted by BaseFacebook::setPersistentData()
//   *
//   * @param string key The key of the data to retrieve
//   * @param boolean default The default value to return if key is not found
//   *
//   * @return mixed
//   */
//  abstract protected function getPersistentData(key, default = false);
//
//  /**
//   * Clear the data with key from the persistent storage
//   *
//   * @param string key
//   * @return void
//   */
//  abstract protected function clearPersistentData(key);
//
//  /**
//   * Clear all data from the persistent storage
//   *
//   * @return void
//   */
//  abstract protected function _clearAllPersistentData();

  _kSupportedKeys : {
    state : true,
    code : true,
    access_token : true,
    user_id : true
  },
  
  /**
   * Provides the implementations of the inherited abstract
   * methods.  The implementation uses PHP sessions to maintain
   * a store for authorization codes, user ids, CSRF states, and
   * access tokens.
   */
  _setPersistentData : function (key, value) {
    if (!this._kSupportedKeys[key]) {
      this._errorLog('Unsupported key passed to setPersistentData.');
      return;
    }
  
    var session_var_name = this._constructSessionVariableName(key);
    this.request.session[session_var_name] = value;
  },
  
  _getPersistentData : function (key, fallback) {
    if (!this.request || !this.request.session) {
      return false;
    }
    if (!this._kSupportedKeys[key]) {
      this._errorLog('Unsupported key passed to getPersistentData.');
      return fallback;
    }
  
    var session_var_name = this._constructSessionVariableName(key);
    return this.request.session[session_var_name] || fallback;
  },
  
  _clearPersistentData : function (key) {
    if (!this._kSupportedKeys[key]) {
      this._errorLog('Unsupported key passed to _clearPersistentData.');
      return;
    }
  
    var session_var_name = this._constructSessionVariableName(key);
    delete this.request.session[session_var_name];
  },
  
  _clearAllPersistentData : function () {
    for (var key in this.kSupportedKeys) {
      this._clearPersistentData(key);
    }
  },

  _constructSessionVariableName : function (key) {
    return 'fb_' + this.appId + '_' + key;
  }
};

function array_merge(target) {
  for (var i = 1; i < arguments.length; i++) {
    var uber = arguments[i];
    for (var j in uber) {
      target[j] = uber[j];
    }
  }
  return target;
}
