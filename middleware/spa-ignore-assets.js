// Single Page Apps - redirect to /#/ except when a file extension is given
var path = require('path');
module.exports = function(req, res, next) {
  if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST" && req.method !== "PUT" && req.method !== "PATCH" && req.method !== "DELETE")
		next();
	if (req.url !== '/' && path.extname(req.url) === '') {
		var route = req.url;
		req.url = '/';
		res.statusCode = 302;
		res.setHeader('Location', req.url + '#' + route);
		res.end();
	}
	else next();
}
