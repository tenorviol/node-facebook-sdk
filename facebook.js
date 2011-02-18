var crypto = require('crypto'),
    http = require('http'),
    https = require('https'),
    querystring = require('querystring'),
    URL = require('url'),
    util = require('util');

/**
 * Thrown when an API call returns an exception.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */


var FacebookApiException = function(result) {
  this.result = result;

  this.code = result['error_code'] ? result['error_code'] : 0;

  if (result['error_description']) {
    // OAuth 2.0 Draft 10 style
    this.message = result['error_description'];
  } else if (result['error'] && result['error']['message']) {
    // OAuth 2.0 Draft 00 style
    this.message = result['error']['message'];
  } else if (result['error_msg']) {
    // Rest server style
    this.message = result['error_msg'];
  } else {
    this.message = 'Unknown Error. Check getResult()';
  }
};

FacebookApiException.prototype = {
  /**
   * The result from the API server that represents the exception information.
   */
  result: null,

  /**
   * Return the associated result object returned by the API server.
   *
   * @returns Array the result from the API server
   */
  getResult: function() {
    return this.result;
  },

  /**
   * Returns the associated type for the error. This will default to
   * 'Exception' when a type is not available.
   *
   * @return String
   */
  getType: function() {
    if (this.result['error']) {
      error = this.result['error'];
      if (typeof error == 'string') {
        // OAuth 2.0 Draft 10 style
        return error;
      } else if (error['type']) {
        // OAuth 2.0 Draft 00 style
        return error['type'];
      }
    }
    return 'Exception';
  },

  /**
   * To make debugging easier.
   *
   * @returns String the string representation of the error
   */
  toString: function() {
    str = this.getType() + ': ';
    if (this.code != 0) {
      str += this.code + ': ';
    }
    return str + this.message;
  }
}

/**
 * Initialize a Facebook Application.
 *
 * The configuration:
 * - appId: the application ID
 * - secret: the application secret
 * - cookie: (optional) boolean true to enable cookie support
 * - domain: (optional) domain for the cookie
 * - fileUpload: (optional) boolean indicating if file uploads are enabled
 *
 * @param Array config the application configuration
 */
var Facebook = exports.Facebook = function(config) {
  this.appId = config['appId'];
  this.apiSecret = config['secret'];
  if (config['cookie']) {
    this.cookieSupport = config['cookie'];
  }
  if (config['domain']) {
    this.baseDomain = config['domain'];
  }
  if (config['fileUpload']) {
    this.fileUploadSupport = config['fileUpload'];
  }
}

/**
 * Provides access to the Facebook Platform.
 */
Facebook.prototype = {
  /**
   * Version.
   */
  VERSION: '0.1.0',

  /**
   * Default options for curl.
   */
  // TODO: can these be used?
  CURLOPT_CONNECTTIMEOUT : 10,
  CURLOPT_RETURNTRANSFER : true,
  CURLOPT_TIMEOUT_MS     : 60000,
  CURLOPT_USERAGENT      : 'facebook-php-2.0',

  /**
   * List of query parameters that get automatically dropped when rebuilding
   * the current URL.
   */
  DROP_QUERY_PARAMS: [
    'session',
    'signed_request'
  ],

  /**
   * Maps aliases to Facebook domains.
   */
  DOMAIN_MAP: {
    'api'      : 'https://api.facebook.com/',
    'api_read' : 'https://api-read.facebook.com/',
    'graph'    : 'https://graph.facebook.com/',
    'www'      : 'https://www.facebook.com/'
  },

//  /**
//   * The active user session, if one is available.
//   */
//  protected session;
//
//  /**
//   * The data from the signed_request token.
//   */
//  protected signedRequest;
//
//  /**
//   * Indicates that we already loaded the session as best as we could.
//   */
//  protected sessionLoaded = false;

  /**
   * Get the data from a signed_request token
   *
   * @return String the base domain
   */
  getSignedRequest: function() {
//    if (!this.signedRequest) {
//      if (isset(_REQUEST['signed_request'])) {
//        this.signedRequest = this.parseSignedRequest(
//          _REQUEST['signed_request']);
//      }
//    }
    return this.signedRequest;
  },

  /**
   * Set the Session.
   *
   * @param Array session the session
   * @param Boolean write_cookie indicate if a cookie should be written. this
   * value is ignored if cookie support has been disabled.
   */
  setSession: function(session, write_cookie) {
    write_cookie = write_cookie === undefined ? true : write_cookie;
    session = this._validateSessionObject(session);
    this.sessionLoaded = true;
    this.session = session;
    if (write_cookie) {
      this._setCookieFromSession(session);
    }
    return this;
  },

  /**
   * Get the session object. This will automatically look for a signed session
   * sent via the signed_request, Cookie or Query Parameters if needed.
   *
   * @return Array the session
   */
  getSession: function() {
    if (!this.sessionLoaded) {
      session = null;
      write_cookie = true;

      // try loading session from signed_request in _REQUEST
      signedRequest = this.getSignedRequest();
      if (signedRequest) {
        // sig is good, use the signedRequest
        session = this.createSessionFromSignedRequest(signedRequest);
      }

      // try loading session from _REQUEST
//      if (!session && isset(_REQUEST['session'])) {
//        session = json_decode(
//          get_magic_quotes_gpc()
//            ? stripslashes(_REQUEST['session'])
//            : _REQUEST['session'],
//          true
//        );
//        session = this.validateSessionObject(session);
//      }

      // try loading session from cookie if necessary
//      if (!session && this.cookieSupport) {
//        cookieName = this.getSessionCookieName();
//        if (isset(_COOKIE[cookieName])) {
//          session = array();
//          parse_str(trim(
//            get_magic_quotes_gpc()
//              ? stripslashes(_COOKIE[cookieName])
//              : _COOKIE[cookieName],
//            '"'
//          ), session);
//          session = this.validateSessionObject(session);
//          // write only if we need to delete a invalid session cookie
//          write_cookie = empty(session);
//        }
//      }

      this.setSession(session, write_cookie);
    }

    return this.session;
  },

  /**
   * Get the UID from the session.
   *
   * @return String the UID if available
   */
  getUser: function() {
    session = this.getSession();
    return session ? session['uid'] : null;
  },

  /**
   * Gets a OAuth access token.
   *
   * @return String the access token
   */
  getAccessToken: function() {
    session = this.getSession();
    // either user session signed, or app signed
    if (session) {
      return session['access_token'];
    } else {
      return this.appId +'|'+ this.apiSecret;
    }
  },

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the params.
   *
   * The parameters:
   * - next: the url to go to after a successful login
   * - cancel_url: the url to go to after the user cancels
   * - req_perms: comma separated list of requested extended perms
   * - display: can be "page" (default, full page) or "popup"
   *
   * @param Array params provide custom parameters
   * @return String the URL for the login flow
   */
  getLoginUrl: function(params) {
	params = params || {};
    currentUrl = this.getCurrentUrl();
    return this._getUrl(
      'www',
      'login.php',
      array_merge({
        'api_key'         : this.appId,
        'cancel_url'      : currentUrl,
        'display'         : 'page',
        'fbconnect'       : 1,
        'next'            : currentUrl,
        'return_session'  : 1,
        'session_version' : 3,
        'v'               : '1.0'
      }, params)
    );
  },

  /**
   * Get a Logout URL suitable for use with redirects.
   *
   * The parameters:
   * - next: the url to go to after a successful logout
   *
   * @param Array params provide custom parameters
   * @return String the URL for the logout flow
   */
  getLogoutUrl: function(params) {
    params = params || {};
    return this._getUrl(
      'www',
      'logout.php',
      array_merge({
        'next'         : this.getCurrentUrl(),
        'access_token' : this.getAccessToken()
      }, params)
    );
  },

  /**
   * Get a login status URL to fetch the status from facebook.
   *
   * The parameters:
   * - ok_session: the URL to go to if a session is found
   * - no_session: the URL to go to if the user is not connected
   * - no_user: the URL to go to if the user is not signed into facebook
   *
   * @param Array params provide custom parameters
   * @return String the URL for the logout flow
   */
  getLoginStatusUrl: function(params) {
    params = params || {};
    return this._getUrl(
      'www',
      'extern/login_status.php',
      array_merge({
        'api_key'         : this.appId,
        'no_session'      : this.getCurrentUrl(),
        'no_user'         : this.getCurrentUrl(),
        'ok_session'      : this.getCurrentUrl(),
        'session_version' : 3
      }, params)
    );
  },

  /**
   * Make an API call.
   *
   * @param Array params the API call parameters
   * @return the decoded response
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
   * @param Array params method call object
   * @return the decoded response object
   * @throws FacebookApiException
   */
  _restserver: function(params, success, error) {
    // generic application level parameters
    params['api_key'] = this.appId;
    params['format'] = 'json-strings';

    this._oauthRequest(
      this._getApiUrl(params['method']),
      params,
      function(result) {
        result = JSON.parse(result);
        if (result && result['error_code']) {
          error(new FacebookApiException(result));
        } else {
          success(result);
        }
      },
      error
    );
  },

  /**
   * Invoke the Graph API.
   *
   * @param String path the path (required)
   * @param String method the http method (default 'GET')
   * @param Array params the query/post data
   * @return the decoded response object
   * @throws FacebookApiException
   * NOTE: the method param has been removed, but can be included in the params (default 'GET')
   */
  _graph: function(path, params, success, error) {
    var self = this;
    
    if (typeof params == 'function') {
      error = success;
      success = params;
      params = { method:'GET' };
    } else if (!params.method) {
      params.method = 'GET';
    }

    this._oauthRequest(
      this._getUrl('graph', path),
      params,
      function(result) {
        result = JSON.parse(result);
        if (result && result['error']) {
          var e = new FacebookApiException(result);
          switch (e.getType()) {
            // OAuth 2.0 Draft 00 style
            case 'OAuthException':
            // OAuth 2.0 Draft 10 style
            case 'invalid_token':
              self.setSession(null);
          }
          error(e);
        } else {
          success(result);
        }
      },
      error
    );
  },

  /**
   * Make a OAuth Request
   *
   * @param String path the path (required)
   * @param Array params the query/post data
   * @return the decoded response object
   * @throws FacebookApiException
   */
  _oauthRequest: function(url, params, success, error) {
    if (!params['access_token']) {
      params['access_token'] = this.getAccessToken();
    }

    // json_encode all params values that are not strings
//    foreach (params as key : value) {
//      if (!is_string(value)) {
//        params[key] = json_encode(value);
//      }
//    }
    this._makeRequest(url, params, success, error);
  },

  /**
   * Makes an HTTP request. This method can be overriden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param String url the URL to make the request to
   * @param Array params the parameters to use for the POST body
   * @param CurlHandler ch optional initialized curl handle
   * @return String the response text
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
      method: 'POST'
    };

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

    request.write(querystring.stringify(params));
    request.end();

    var timeout = setTimeout(function() {
      request.abort();
      var e = new FacebookApiException({
        'error_code' : 28 /* CURLE_OPERATION_TIMEDOUT */,
        'error'      : {
          'message' : 'timeout',
          'type'    : 'CurlException'
        }
      });
      error(e);
    }, this.CURLOPT_TIMEOUT_MS);


//    opts = self::CURL_OPTS;
//    if (this.useFileUploadSupport()) {
//      opts[CURLOPT_POSTFIELDS] = params;
//    } else {
//      opts[CURLOPT_POSTFIELDS] = http_build_query(params, null, '&');
//    }
//    opts[CURLOPT_URL] = url;
//
//    // disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
//    // for 2 seconds if the server does not support this header.
//    if (isset(opts[CURLOPT_HTTPHEADER])) {
//      existing_headers = opts[CURLOPT_HTTPHEADER];
//      existing_headers[] = 'Expect:';
//      opts[CURLOPT_HTTPHEADER] = existing_headers;
//    } else {
//      opts[CURLOPT_HTTPHEADER] = array('Expect:');
//    }
//
//    curl_setopt_array(ch, opts);
//    result = curl_exec(ch);
//
//    if (curl_errno(ch) == 60) { // CURLE_SSL_CACERT
//      self::errorLog('Invalid or no certificate authority found, using bundled information');
//      curl_setopt(ch, CURLOPT_CAINFO,
//                  dirname(__FILE__) . '/fb_ca_chain_bundle.crt');
//      result = curl_exec(ch);
//    }
//
//    if (result === false) {
//      e = new FacebookApiException(array(
//        'error_code' : curl_errno(ch),
//        'error'      : array(
//          'message' : curl_error(ch),
//          'type'    : 'CurlException',
//        ),
//      ));
//      curl_close(ch);
//      throw e;
//    }
//    curl_close(ch);
//    return result;
  },

  /**
   * The name of the Cookie that contains the session.
   *
   * @return String the cookie name
   */
  _getSessionCookieName: function() {
    return 'fbs_' + this.appId;
  },

  /**
   * Set a JS Cookie based on the _passed in_ session. It does not use the
   * currently stored session -- you need to explicitly pass it in.
   *
   * @param Array session the session to use for setting the cookie
   */
  _setCookieFromSession: function(session) {
    if (!this.cookieSupport) {
      return;
    }

    cookieName = this._getSessionCookieName();
//    value = 'deleted';
//    expires = time() - 3600;
//    domain = this.getBaseDomain();
//    if (session) {
//      value = '"' + http_build_query(session, null, '&') + '"';
//      if (isset(session['base_domain'])) {
//        domain = session['base_domain'];
//      }
//      expires = session['expires'];
//    }
//
//    // prepend dot if a domain is found
//    if (domain) {
//      domain = '.' . domain;
//    }
//
//    // if an existing cookie is not set, we dont need to delete it
//    if (value == 'deleted' && empty(_COOKIE[cookieName])) {
//      return;
//    }
//
//    if (headers_sent()) {
//      this._errorLog('Could not set cookie. Headers already sent.');
//
//    // ignore for code coverage as we will never be able to setcookie in a CLI
//    // environment
//    // @codeCoverageIgnoreStart
//    } else {
//      setcookie(cookieName, value, expires, '/', domain);
//    }
    // @codeCoverageIgnoreEnd
  },

  /**
   * Validates a session_version=3 style session object.
   *
   * @param Array session the session object
   * @return Array the session object if it validates, null otherwise
   */
  _validateSessionObject: function(session) {
    // make sure some essential fields exist
    if (session &&
        session['uid'] &&
        session['access_token'] &&
        session['sig']) {
      // validate the signature
      session_without_sig = {};
      for (var key in session) {
        if (key != 'sig') {
          session_without_sig[key] = session[key];
        }
      }
      expected_sig = this._generateSignature(
        session_without_sig,
        this.apiSecret
      );
      if (session['sig'] != expected_sig) {
        this._errorLog('Got invalid session signature in cookie.');
        session = null;
      }
      // check expiry time
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
   * @param Array the output of getSignedRequest
   * @return Array Something that will work as a session
   */
  _createSessionFromSignedRequest: function(data) {
    if (!data['oauth_token']) {
      return null;
    }

    session = {
      'uid'          : data['user_id'],
      'access_token' : data['oauth_token'],
      'expires'      : data['expires']
    };

    // put a real sig, so that validateSignature works
    session['sig'] = this._generateSignature(
      session,
      this.apiSecret
    );

    return session;
  },

  /**
   * Parses a signed_request and validates the signature.
   * Then saves it in this.signed_data
   *
   * @param String A signed token
   * @param Boolean Should we remove the parts of the payload that
   *                are used by the algorithm?
   * @return Array the payload inside it or null if the sig is wrong
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

    if (data['algorithm'].toUpperCase() !== 'HMAC-SHA256') {
      this._errorLog('Unknown algorithm. Expected HMAC-SHA256');
      return null;
    }

    // check sig
    var hmac = crypto.createHmac('sha256', this.apiSecret);
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
   * @param method String the method name.
   * @return String the URL for the given parameters
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
    if (READ_ONLY_CALLS[method.toLowerCase()]) {
      name = 'api_read';
    }
    return this._getUrl(name, 'restserver.php');
  },

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param name String the name of the domain
   * @param path String optional path (without a leading slash)
   * @param params Array optional query parameters
   * @return String the URL for the given parameters
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
   * @return String the current URL
   */
  _getCurrentUrl: function() {
    protocol = isset(_SERVER['HTTPS']) && _SERVER['HTTPS'] == 'on'
      ? 'https://'
      : 'http://';
    currentUrl = protocol . _SERVER['HTTP_HOST'] . _SERVER['REQUEST_URI'];
    parts = parse_url(currentUrl);

    // drop known fb params
    query = '';
    if (!empty(parts['query'])) {
      params = {};
      parse_str(parts['query'], params);
      this.DROP_QUERY_PARAMS.forEach(function(key) {
        delete params[key];
      });
      if (!empty(params)) {
        query = '?' + http_build_query(params, null, '&');
      }
    }

    // use port if non default
    port =
      isset(parts['port']) &&
      ((protocol === 'http://' && parts['port'] !== 80) ||
       (protocol === 'https://' && parts['port'] !== 443))
      ? ':' + parts['port'] : '';

    // rebuild
    return protocol + parts['host'] + port + parts['path'] + query;
  },

  /**
   * Generate a signature for the given params and secret.
   *
   * @param Array params the parameters to sign
   * @param String secret the secret to sign with
   * @return String the generated signature
   */
  _generateSignature: function(params, secret) {
    var md5 = crypto.createHash('md5');
    Object.keys(params).sort().forEach(function(key) {
      md5.update(key + '=' + params[key]);
    });
    md5.update(secret);
    return md5.digest('hex');
  },

  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param String log message
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
   * @param String base64UrlEncodeded string
   */
  _base64UrlDecode: function(input) {
    var buffer = new Buffer(input.replace('-', '+').replace('_', '/'), 'base64');
    return buffer.toString('binary');
  }
}
