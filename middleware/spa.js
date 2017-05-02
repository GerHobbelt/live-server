// Single Page Apps - redirect to /#/
module.exports = function(req, res, next) {
  if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST" && req.method !== "PUT")
		next();
	if (req.url !== '/') {
		var route = req.url;
		req.url = '/';
		res.statusCode = 302;
		res.setHeader('Location', req.url + '#' + route);
		res.end();
	}
	else next();
}
