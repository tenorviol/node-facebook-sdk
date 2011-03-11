node.js facebook-sdk API
========================


facebook.api
------------

### FQL

	facebook.api({
		method: 'fql.query',
		query: "SELECT name FROM user WHERE uid = me()"
	}, function(data) {
		console.log(data);
	});

