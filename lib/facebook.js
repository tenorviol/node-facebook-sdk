/**
 * Copyright 2011 Facebook, Inc.
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

var crypto = require('crypto'),
    http = require('http'),
    https = require('https'),
    querystring = require('querystring'),
    URL = require('url'),
    util = require('util');

/**
 * Thrown when an API call returns an exception.
 */
var FacebookApiException = function(result) {
  this.result = result;

  this.error = true;
  this.code = result.error_code ? result.error_code : 0;

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
  // The result from the API server that represents the exception information.
  result: null,

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
      error = this.result.error;
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
    str = this.getType() + ': ';
    if (this.code != 0) {
      str += this.code + ': ';
    }
    return str + this.message;
  }
};

/**
 * Initialize the Facebook Application, providing access to the Facebook platform API.
 *
 * The configuration:
 * - appId: the application ID
 * - secret: the application secret
 * - request: (optional) http.ServerRequest for reclaiming sessions
 * - response: (optional) http.ServerResponse for writing the cookie to
 * - domain: (optional) domain for the cookie
 * TODO:
 * - fileUpload: (optional) boolean indicating if file uploads are enabled
 *
 * @param {Object} config the application configuration
 */
var Facebook = exports.facebook = exports.Facebook = function(config) {
  var facebook;
  if (this instanceof Facebook) {
    // instantiation using the 'new' operator
    facebook = this;
  } else {
    // connect style middleware function
    // TODO: this should also function as a Facebook object, add prototype
    facebook = function(req, res, next) {
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
};

Facebook.prototype = {

  // The Application ID.
  appId: null,

  // The Application API Secret.
  secret: null,

  // http.ServerRequest for initializing the session
  request: null,

  // http.ServerResponse for writing the session cookie
  response: null,

  // Base domain for the Cookie.
  domain: '',

  // Indicates if the CURL based @ syntax for file uploads is enabled.
  fileUpload: false,

  // Milliseconds for connection with Facebook's servers to be established
  // TODO: connectTimeout: 10000,
  
  // Milliseconds for transmition of data from Facebook to complete
  timeout: 60000,

  // The active user session, if one is available.
  _session: null,

  // The data from the signed_request token.
  _signedRequest: null,

  // Indicates that we already loaded the session as best as we could.
  _sessionLoaded: false,


  // List of query parameters that get automatically dropped when rebuilding the current URL
  DROP_QUERY_PARAMS: [
    'session',
    'signed_request'
  ],

  // Map of aliases to Facebook domains
  DOMAIN_MAP: {
    api      : 'https://api.facebook.com/',
    api_video: 'https://api-video.facebook.com/',
    api_read : 'https://api-read.facebook.com/',
    graph    : 'https://graph.facebook.com/',
    www      : 'https://www.facebook.com/'
  },

  /**
   * Get the data from a signed_request token
   *
   * @return {Object}
   */
  getSignedRequest: function() {
    if (!this._signedRequest && this.request) {
      var signed_request = this.request.body && this.request.body.signed_request;
      signed_request = signed_request || URL.parse(this.request.url, true).query.signed_request;
      if (signed_request) {
        this._signedRequest = this._parseSignedRequest(signed_request);
      }
    }
    return this._signedRequest;
  },

  /**
   * Set the Session.
   *
   * @param {Object} session the session
   * @param {boolean} write_cookie indicate if a cookie should be written. ignored if no response object.
   */
  setSession: function(session, write_cookie) {
    write_cookie = write_cookie === undefined ? true : write_cookie;
    session = this._validateSessionObject(session);
    this._sessionLoaded = true;
    this._session = session;
    if (write_cookie) {
      this._setCookieFromSession(session);
    }
    return this;
  },

  /**
   * Get the session object. This will automatically look for a signed session
   * sent via the signed_request, Cookie or Query Parameters if needed.
   *
   * @return {Object} the session
   */
  getSession: function() {
    if (!this._sessionLoaded) {
      var session = null;
      var write_cookie = true;

      // try loading session from signed_request in request
      signedRequest = this.getSignedRequest();
      if (signedRequest) {
        // sig is good, use the signedRequest
        session = this._createSessionFromSignedRequest(signedRequest);
      }

      // try loading session from request
      if (!session && this.request) {
        session = this.request.body && this.request.body.session;
        if (!session) {
          session = URL.parse(this.request.url, true).query.session;
        }
        if (session) {
          session = JSON.parse(session);
          session = this._validateSessionObject(session);
        }
      }

      // try loading session from cookie if necessary
      if (!session && this.request) {
        var cookie = this._getSessionCookie();
        if (cookie) {
          var cookie = cookie.replace(/^"*|"*$/g, '');
          session = querystring.parse(cookie);
          session = this._validateSessionObject(session);
          // write only if we need to delete a invalid session cookie
          write_cookie = !session;
        }
      }

      this.setSession(session, write_cookie);
    }

    return this._session;
  },

  _getSessionCookie: function() {
    if (!this.request.cookies) {
      return;
    }
    var cookieName = this._getSessionCookieName();
    return this.request.cookies[cookieName];
  },

  /**
   * Get the UID from the session.
   *
   * @return {String} the UID if available
   */
  getUser: function() {
    session = this.getSession();
    return session ? session.uid : null;
  },

  /**
   * Gets a OAuth access token.
   *
   * @return {String} the access token
   */
  getAccessToken: function() {
    session = this.getSession();
    // either user session signed, or app signed
    if (session) {
      return session.access_token;
    } else {
      return this.appId +'|'+ this.secret;
    }
  },

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the params.
   *
   * The parameters (optional):
   * - next: the url to go to after a successful login
   * - cancel_url: the url to go to after the user cancels
   * - req_perms: comma separated list of requested extended perms
   * - display: can be "page" (default, full page) or "popup"
   *
   * @param {Object} params provide custom parameters
   * @return {String} the URL for the login flow
   */
  getLoginUrl: function(params) {
    params = params || {};
    currentUrl = this._getCurrentUrl();

    var defaults = {
      api_key         : this.appId,
      cancel_url      : currentUrl,
      display         : 'page',
      fbconnect       : 1,
      next            : currentUrl,
      return_session  : 1,
      session_version : 3,
      v               : '1.0'
    };
    for (var i in defaults) {
      params[i] = params[i] || defaults[i];
    }

    return this._getUrl('www', 'login.php', params);
  },

  /**
   * Get a Logout URL suitable for use with redirects.
   *
   * The parameters:
   * - next: the url to go to after a successful logout
   *
   * @param {Object} params provide custom parameters
   * @return {String} the URL for the logout flow
   */
  getLogoutUrl: function(params) {
    params = params || {};

    var defaults = {
      next         : this._getCurrentUrl(),
      access_token : this.getAccessToken()
    };
    for (var i in defaults) {
      params[i] = params[i] || defaults[i];
    }

    return this._getUrl('www', 'logout.php', params);
  },

  /**
   * Get a login status URL to fetch the status from facebook.
   *
   * The parameters:
   * - ok_session: the URL to go to if a session is found
   * - no_session: the URL to go to if the user is not connected
   * - no_user: the URL to go to if the user is not signed into facebook
   *
   * @param {Object} params provide custom parameters
   * @return {String} the URL for the logout flow
   */
  getLoginStatusUrl: function(params) {
    params = params || {};

    var defaults = {
      api_key         : this.appId,
      no_session      : this._getCurrentUrl(),
      no_user         : this._getCurrentUrl(),
      ok_session      : this._getCurrentUrl(),
      session_version : 3
    };
    for (var i in defaults) {
      params[i] = params[i] || defaults[i];
    }

    return this._getUrl('www', 'extern/login_status.php', params);
  },

  /**
   * Make an API call.
   */
  api: function(/* polymorphic */) {
    if (typeof arguments[0] == 'object') {
      this._restserver.apply(this, arguments);
    } else {
      this._graph.apply(this, arguments);
    }
  },

  /**
   * Invoke the old restserver.php endpoint.
   *
   * @param {Object} params method call object
   * @param {Function( object )} callback to send the decoded response object
   */
  _restserver: function(params, callback) {
    // generic application level parameters
    params.api_key = this.appId;
    params.format = 'json-strings';

    this._oauthRequest(
      this._getApiUrl(params.method),
      params,
      function(result) {
        result = JSON.parse(result);
        if (result && result.error_code) {
          result = new FacebookApiException(result);
        }
        callback(result);
      },
      callback
    );
  },

  /**
   * Invoke the Graph API.
   *
   * @param {String} path the path (required)
   * @param {String} method the http method (default 'GET')
   * @param {Object} params the query/post data
   * @param {Function( object )} callback to send the decoded response object
   */
  _graph: function(path, method, params, callback) {
    var self = this;

    if (typeof method != 'string') {
      callback = params;
      params = method || {};
      method = params.method || 'GET';
    }
    if (typeof params == 'function') {
      callback = params;
      params = {};
    }
    params.method = method;

    this._oauthRequest(
      this._getUrl('graph', path),
      params,
      function(result) {
        result = JSON.parse(result);
        if (result && result.error) {
          var result = new FacebookApiException(result);
          switch (result.getType()) {
            case 'OAuthException': // OAuth 2.0 Draft 00 style
            case 'invalid_token':  // OAuth 2.0 Draft 10 style
              // TODO: test and check if headers have alread been sent
              try {
                self.setSession(null);
              } catch (err) {
                console.log(err);
              }
          }
        }
        callback && callback(result);
      },
      callback
    );
  },

  /**
   * Make a OAuth Request
   *
   * @param {String} path the path (required)
   * @param {Object} params the query/post data
   * @param {Function( string )} success to send the raw response string
   * @param {Function( FacebookApiException )} error to send the error on failure
   */
  _oauthRequest: function(url, params, success, error) {
    if (!params.access_token) {
      params.access_token = this.getAccessToken();
    }

    // json encode all params values that are not strings
    // TODO: untested
    for (var key in params) {
      if (typeof params[key] == 'object') {
        params[key] = JSON.stringify(params[key]);
      }
    }

    this._makeRequest(url, params, success, error);
  },

  /**
   * Makes an HTTP request. This method can be overriden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param {String} url the URL to make the request to
   * @param {Object} params the parameters to use for the POST body
   * @param {Function( string )} success callback to send the raw response data
   * @param {Function{ FacebookApiException }} error callback to send an error object
   */
  _makeRequest: function(url, params, success, error) {
    var parts = URL.parse(url);

    var protocol = http;
    var port = 80;
    if (parts.protocol == 'https:') {
      protocol = https;
      port = 443;
    }

    var options = {
      host: parts.hostname,
      port: parts.port ? parts.port : port,
      path: parts.pathname,
      method: 'POST',
      agent: false
    };

    // TODO: header 'Expect: 100-continue'? This was a part of the original curl makeRequest

    var request = protocol.request(options, function(result) {
      result.setEncoding('utf8');

      var body = '';
      result.on('data', function(chunk) {
        body += chunk;
      });

      result.on('end', function() {
        clearTimeout(timeout);
        success(body);
      });
    });

    // TODO?
    // if (this.useFileUploadSupport()) {
    //   opts[CURLOPT_POSTFIELDS] = params;
    // } else {
    //   opts[CURLOPT_POSTFIELDS] = http_build_query(params, null, '&');
    // }
    
    request.write(querystring.stringify(params));
    request.end();

    var timeout = setTimeout(function() {
      request.abort();
      var e = new FacebookApiException({
        error_code : 28 /* CURLE_OPERATION_TIMEDOUT */,
        error      : {
          message : 'timeout',
          type    : 'CurlException'
        }
      });
      error && error(e);
    }, this.timeout);
  },

  /**
   * The name of the Cookie that contains the session.
   *
   * @return {String} the cookie name
   */
  _getSessionCookieName: function() {
    return 'fbs_' + this.appId;
  },

  /**
   * Set a JS Cookie based on the _passed in_ session. It does not use the
   * currently stored session -- you need to explicitly pass it in.
   *
   * @param {Object} session the session to use for setting the cookie
   */
  _setCookieFromSession: function(session) {
    if (!this.response) {
      return;
    }

    var name = this._getSessionCookieName();
    var value = 'deleted';
    var expires = new Date(Date.now() - 3600000);
    var domain = this.domain;
    if (session) {
      value = '"' + querystring.stringify(session) + '"';
      if (session.base_domain) {
        domain = session.base_domain;
      }
      expires = new Date(session.expires * 1000);
    }
    
    // prepend dot if a domain is found
    if (domain) {
      domain = '.' + domain;
    }
    
    // if an existing cookie is not set, we dont need to delete it
    // TODO: how do we know the cookie does not exist?
    //if (value == 'deleted' && empty(_COOKIE[cookieName])) {
    //  return;
    //}
    
    // TODO: statusCode check does not work, write proper test for this
    //if (this.response.statusCode) {
    //  this._errorLog('Could not set cookie. Headers already sent.');
    //} else {
      var cookie = require('connect').utils.serializeCookie(name, value, {
        domain: domain,
        path: '/',
        expires: expires
      });
      this.response.setHeader('Set-Cookie', cookie);
    //}
  },

  /**
   * Validates a session_version=3 style session object.
   *
   * @param {Object} session the session object
   * @return {Object} the session object if it validates, null otherwise
   */
  _validateSessionObject: function(session) {
    // make sure some essential fields exist
    if (session &&
        session.uid &&
        session.access_token &&
        session.sig) {
      expected_sig = this._generateSignature(session, this.secret);
      if (session.sig != expected_sig) {
        this._errorLog('Got invalid session signature in cookie.');
        session = null;
      }
      // TODO: check expiry time? this was never implemented in the original php lib
    } else {
      session = null;
    }
    return session;
  },

  /**
   * Returns something that looks like our JS session object from the
   * signed token's data
   *
   * TODO: Nuke this once the login flow uses OAuth2
   *
   * @param {Object} data the output of getSignedRequest
   * @return {Object} Something that will work as a session
   */
  _createSessionFromSignedRequest: function(data) {
    if (!data.oauth_token) {
      return null;
    }

    session = {
      uid          : data.user_id,
      access_token : data.oauth_token,
      expires      : data.expires
    };

    // put a real sig, so that validateSignature works
    session.sig = this._generateSignature(session, this.secret);

    return session;
  },

  /**
   * Parses a signed_request and validates the signature.
   * Then saves it in this.signed_data
   *
   * @param {String} signed_request A signed token
   * @return {Object} the payload inside it or null if the sig is wrong
   */
  _parseSignedRequest: function(signed_request) {
    var split = signed_request.split('.', 2);
    if (split.length != 2) {
      return null;
    }
    var encoded_sig = split[0];
    var payload = split[1];

    // decode the data
    sig = this._base64UrlDecode(encoded_sig);
    data = JSON.parse(this._base64UrlDecode(payload));

    if (data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
      this._errorLog('Unknown algorithm. Expected HMAC-SHA256');
      return null;
    }

    // check sig
    var hmac = crypto.createHmac('sha256', this.secret);
    hmac.update(payload);
    expected_sig = hmac.digest();
    if (sig !== expected_sig) {
      this._errorLog('Bad Signed JSON signature!');
      return null;
    }

    return data;
  },

  /**
   * Build the URL for api given parameters.
   *
   * @param {String} method the method name.
   * @return {String} the URL for the given parameters
   */
  _getApiUrl: function(method) {
    const READ_ONLY_CALLS = {
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
    method = method.toLowerCase();
    if (READ_ONLY_CALLS[method]) {
      name = 'api_read';
    } else if (method === 'video.upload') {
      name = 'api_video';
    }
    return this._getUrl(name, 'restserver.php');
  },

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param {String} name the name of the domain
   * @param {String} path optional path (without a leading slash)
   * @param {Object} params optional query parameters
   * @return {String} the URL for the given parameters
   */
  _getUrl: function(name, path, params) {
    var url = this.DOMAIN_MAP[name];
    if (path) {
      if (path[0] === '/') {
        path = path.substr(1);
      }
      url += path;
    }
    if (params) {
      url += '?' + querystring.stringify(params);
    }
    return url;
  },

  /**
   * Returns the Current URL, stripping it of known FB parameters that should
   * not persist.
   *
   * @return {String} the current URL
   */
  _getCurrentUrl: function() {
    if (this.request && this.request.headers.host) {
      var site = {
        protocol: this.request.connection.encrypted ? 'https:' : 'http:',
        host: this.request.headers.host
      };
    } else {
      throw new Error('No request host available');
    }
    
    var url = URL.parse(this.request.url, true);

    // drop known fb params
    this.DROP_QUERY_PARAMS.forEach(function(key) {
      delete url.query[key];
    });

    var currentUrl = site.protocol + '//' + site.host + url.pathname;
    if (url.query) {
      currentUrl += '?' + querystring.stringify(url.query);
    }

    return currentUrl;
  },

  /**
   * Generate a signature for the given params and secret.
   *
   * @param {Object} params the parameters to sign
   * @param {String} secret the secret to sign with
   * @return {String} the generated signature
   */
  _generateSignature: function(params, secret) {
    var md5 = crypto.createHash('md5');
    Object.keys(params).sort().forEach(function(key) {
      if (key !== 'sig') {
        md5.update(key + '=' + params[key]);
      }
    });
    md5.update(secret);
    return md5.digest('hex');
  },

  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param {String} msg log message
   */
  _errorLog: function(msg) {
    console.log(msg);
  },

  /**
   * Base64 encoding that doesn't need to be urlencode()ed.
   * Exactly the same as base64_encode except it uses
   *   - instead of +
   *   _ instead of /
   *
   * @param {String} input base64UrlEncodeded string
   * @param {String} decoded
   */
  _base64UrlDecode: function(input) {
    var buffer = new Buffer(input.replace('-', '+').replace('_', '/'), 'base64');
    return buffer.toString('binary');
  }
};
