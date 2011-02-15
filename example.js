
var fbsdk = require('./facebook');

// create the facebook object
var facebook = new fbsdk.Facebook({
	appId: '117743971608120',
	secret: '943716006e74d9b9283d4d5d8ab93204'
});

// set the session (this also validates it)
facebook.setSession({
	'access_token' : '117743971608120|2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385|NF_2DDNxFBznj2CuwiwabHhTAHc.',
	'secret'       : 'u0QiRGAwaPCyQ7JE_hiz1w__',
	'session_key'  : '2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385',
	'sig'          : '7a9b063de0bef334637832166948dcad',
	'uid'          : '1677846385',
	'expires'      : '1281049200'
});

// get the facebook user id (if the session validated, this will return the number)
console.log(facebook.getUser());


// invalid session example (I changed the sig, removing one character)
facebook.setSession({
	'access_token' : '117743971608120|2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385|NF_2DDNxFBznj2CuwiwabHhTAHc.',
	'secret'       : 'u0QiRGAwaPCyQ7JE_hiz1w__',
	'session_key'  : '2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385',
	'sig'          : '7a9b063de0bef334637832166948dca',
	'uid'          : '1677846385',
	'expires'      : '1281049200'
});

// get the facebook user id (if the session validated, this will return the number)
console.log(facebook.getUser());
