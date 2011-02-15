
var crypto = require('crypto');

/**
 * Maps aliases to Facebook domains.
 */
var DOMAIN_MAP = {
	api      : 'https://api.facebook.com/',
	api_read : 'https://api-read.facebook.com/',
	graph    : 'https://graph.facebook.com/',
	www      : 'https://www.facebook.com/'
};


/**
 * Initialize a Facebook Application.
 *
 * The configuration:
 * - appId: the application ID
 * - secret: the application secret
 * - request: (optional) HttpRequest object (for reading cookies from)
 * - response: (optional) HttpResponse object (for writing cookies to)
 * - cookie: (optional) boolean true to enable cookie support  ??? implicit in req/res?
 * - domain: (optional) domain for the cookie   ??? needed for setting cookie?
 * - fileUpload: (optional) boolean indicating if file uploads are enabled
 *
 * @param Array config the application configuration
 */
var Facebook = exports.Facebook = function(config) {
	if (config) {
		for (var param in config) {
			this[param] = config[param];
		}
	}
};

/**
 * Get the data from a signed_request token
 *
 * @return String the base domain
 */
Facebook.prototype.getSignedRequest = function() {
 	if (this.signedRequest) {
		if (this.request && signed_request = request.param('signed_request')) {
			this.signedRequest = this.parseSignedRequest(signed_request);
		}
	}
	return this.signedRequest;
}

/**
 * Set the Session.
 *
 * @param Array $session the session
 * @param Boolean $write_cookie indicate if a cookie should be written. this
 * value is ignored if cookie support has been disabled.
 */
Facebook.prototype.setSession = function(session, write_cookie) {
	session = this.validateSessionObject(session);
	this.sessionLoaded = true;
	this.session = session;
	if (write_cookie) {
		if (this.response) {
			this.setCookieFromSession(session);
		} else {
			// TODO: exception
		}
	}
	return this;
};

/**
 * Get the session object. This will automatically look for a signed session
 * sent via the signed_request, Cookie or Query Parameters if needed.
 *
 * @return Array the session
 */
Facebook.prototype.getSession = function() {
	if (!this.sessionLoaded) {
		session = null;
		write_cookie = true;

		// try loading session from signed_request in $_REQUEST
		signedRequest = this.getSignedRequest();
		if (signedRequest) {
			// sig is good, use the signedRequest
			session = this.createSessionFromSignedRequest(signedRequest);
		}

		// try loading session from $_REQUEST
		if (!session && this.request && this.request.param('session')) {
			session = JSON.parse(this.request.param('session'));
			session = this.validateSessionObject(session);
		}

		// try loading session from cookie if necessary
		if (!session && this.request && this.request.cookies) {
			var cookieName = this.getSessionCookieName();
			// TODO
			//if (this.request.cookies[cookieName]) {
			//	session = {};
			//	parse_str(trim($_COOKIE[$cookieName], '"'), $session);
			//	$session = $this->validateSessionObject($session);
			//	// write only if we need to delete a invalid session cookie
			//	$write_cookie = empty($session);
			//}
		}

		this.setSession(session, write_cookie);
	}

	return this.session;
};

/**
 * Get the UID from the session.
 *
 * @return String the UID if available
 */
Facebook.prototype.getUser = function() {
	session = this.getSession();
	return session ? session.uid : null;
}

/**
 * Gets a OAuth access token.
 *
 * @return String the access token
 */
Facebook.prototype.getAccessToken = function() {
	var session = this.getSession();
	// either user session signed, or app signed
	if (session) {
		return session.access_token;
	} else {
		return this.appId+'|'+this.secret;
	}
}

/**
 * Make an API call.
 *
 * @param Array $params the API call parameters
 * @return the decoded response
 */
Facebook.prototype.api = function() {
	if (typeof arguments[0] == 'object') {
		return _restserver.apply(this, arguments);
	} else {
		return _graph.apply(this, arguments);
	}
}

/**
 * Invoke the old restserver.php endpoint.
 *
 * @param Array $params method call object
 * @return the decoded response object
 * @throws FacebookApiException
 */
function _restserver(params, success, error) {
	// generic application level parameters
	params.api_key = this.appId;
	params.format = 'json-strings';

	result = JSON.parse(_oauthRequest.call(
		this,
		getApiUrl(params.method),
		params,
		function(result) {
			// results are returned, errors are thrown
			if (typeof result == 'object' && result.error_code) {
				if (error) {
					error(result);
				}
				return;
			}
			success(result);
		}
	));
}

/**
 * Make a OAuth Request
 *
 * @param String $path the path (required)
 * @param Array $params the query/post data
 * @return the decoded response object
 * @throws FacebookApiException
 */
function _oauthRequest(url, params) {
	if (!params.access_token) {
		params.access_token = this.getAccessToken();
	}

	// TODO? json_encode all params values that are not strings
	//foreach ($params as $key => $value) {
	//	if (!is_string($value)) {
	//		params[$key] = json_encode($value);
	//	}
	//}
	return this.makeRequest(url, params);
}

/**
 * Makes an HTTP request. This method can be overriden by subclasses if
 * developers want to do fancier things or use something other than curl to
 * make the request.
 *
 * @param String $url the URL to make the request to
 * @param Array $params the parameters to use for the POST body
 * @param CurlHandler $ch optional initialized curl handle
 * @return String the response text
 */
Facebook.prototype.makeRequest = function(url, params, success, error) {
//  if (!$ch) {
//    $ch = curl_init();
//  }
//
//  $opts = self::$CURL_OPTS;
//  if ($this->useFileUploadSupport()) {
//    $opts[CURLOPT_POSTFIELDS] = $params;
//  } else {
//    $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
//  }
//  $opts[CURLOPT_URL] = $url;
//
//  // disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
//  // for 2 seconds if the server does not support this header.
//  if (isset($opts[CURLOPT_HTTPHEADER])) {
//    $existing_headers = $opts[CURLOPT_HTTPHEADER];
//    $existing_headers[] = 'Expect:';
//    $opts[CURLOPT_HTTPHEADER] = $existing_headers;
//  } else {
//    $opts[CURLOPT_HTTPHEADER] = array('Expect:');
//  }
//
//  curl_setopt_array($ch, $opts);
//  $result = curl_exec($ch);
//
//  if (curl_errno($ch) == 60) { // CURLE_SSL_CACERT
//    self::errorLog('Invalid or no certificate authority found, using bundled information');
//    curl_setopt($ch, CURLOPT_CAINFO,
//                dirname(__FILE__) . '/fb_ca_chain_bundle.crt');
//    $result = curl_exec($ch);
//  }
//
//  if ($result === false) {
//    $e = new FacebookApiException(array(
//      'error_code' => curl_errno($ch),
//      'error'      => array(
//        'message' => curl_error($ch),
//        'type'    => 'CurlException',
//      ),
//    ));
//    curl_close($ch);
//    throw $e;
//  }
//  curl_close($ch);
//  return $result;
};


/**
 * Validates a session_version=3 style session object.
 *
 * @param Array $session the session object
 * @return Array the session object if it validates, null otherwise
 */
Facebook.prototype.validateSessionObject = function(session) {
	// make sure some essential fields exist
	if (session
			&& session.uid
			&& session.access_token
			&& session.sig) {
		// validate the signature
		session_without_sig = {};
		for (var i in session) {
			if (i != 'sig') {
				session_without_sig[i] = session[i];
			}
		}
		expected_sig = generateSignature(session_without_sig, this.secret);
		if (session.sig != expected_sig) {
			console.log('Got invalid session signature in cookie.');
			session = null;
		}
		// check expiry time
	} else {
		session = null;
	}
	return session;
}

/**
 * Generate a signature for the given params and secret.
 *
 * @param Array $params the parameters to sign
 * @param String $secret the secret to sign with
 * @return String the generated signature
 */
function generateSignature(params, secret) {
	var md5 = crypto.createHash('md5');
	var pairs = [];
	for (var i in params) {
		pairs.push(i + '=' + params[i]);
	}
	var tohash = pairs.sort().join('') + secret;
	return md5.update(tohash).digest('hex');
}


/**
 * Build the URL for api given parameters.
 *
 * @param $method String the method name.
 * @return String the URL for the given parameters
 */
function getApiUrl(method) {
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
	}
	return getUrl(name, 'restserver.php');
}

/**
 * Build the URL for given domain alias, path and parameters.
 *
 * @param $name String the name of the domain
 * @param $path String optional path (without a leading slash)
 * @param $params Array optional query parameters
 * @return String the URL for the given parameters
 */
function getUrl(name, path, params) {
	url = DOMAIN_MAP[name];
	if (path) {
		if (path.charAt(0) === '/') {
			path = path.substr(1);
		}
		url += path;
	}
	if (params) {
		url += '?' . http_build_query($params, null, '&');
	}
	return url;
}
