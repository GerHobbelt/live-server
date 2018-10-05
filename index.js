#!/usr/bin/env node
var fs = require('fs'),
  connect = require('connect'),
  serveIndex = require('serve-index'),
  logger = require('morgan'),
  WebSocket = require('faye-websocket'),
  path = require('path'),
  url = require('url'),
  http = require('http'),
  send = require('send'),
  formidable = require('formidable'),
  open = require('opn'),
  sink = require('@gerhobbelt/stream-sink'),
  marked = require('marked'),
  es = require("event-stream"),
	os = require('os'),
	chokidar = require('chokidar'),
  mkdirp = require('mkdirp');
require('colors');

var INJECTED_RELOAD_CODE = fs.readFileSync(path.join(__dirname, "injected.html"), "utf8");

var LiveServer = {
  server: null,
	watcher: null,
  logLevel: 2
};

var markdownStyles = {
  'html': 'standard',
  'hack': 'hack',
  'hack-dark': 'hack dark',
  'hack-light': 'hack'
};

function escape(html){
  return String(html)
    .replace(/&(?!\w+;)/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Based on connect.static(), but streamlined and with added code injector
function staticServer(root, headInjection, bodyInjection) {
  var isFile = false;
  try { // For supporting mounting files instead of just directories
    isFile = fs.statSync(root).isFile();
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  return function (req, res, next) {
    if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST" && req.method !== "PUT") return next();
    var reqpath = isFile ? "" : url.parse(req.url).pathname;
    var hasNoOrigin = !req.headers.origin;
		var injectCandidates = [ new RegExp("</body>", "i"), new RegExp("</svg>"), new RegExp("</head>", "i")];
    var injectTag = null;
		var injectBody = false;
		var injectHead = false;
    var injectMarkdown = false;

    function directory() {
      var pathname = url.parse(req.originalUrl).pathname;
      res.statusCode = 301;
      res.setHeader('Location', pathname + '/');
      res.end('Redirecting to ' + escape(pathname) + '/');
    }

    function find_inject_tag(filepath, contents) {
      var match;

      injectTag = null;
      for (var i = 0; i < injectCandidates.length; ++i) {
        match = injectCandidates[i].exec(contents);
        if (match) {
          injectTag = match[0];
          break;
        }
      }

			match = (new RegExp("</body>", "i")).exec(contents);
			if (match) {
				injectBody = true;
			}
			match = (new RegExp("</head>", "i")).exec(contents);
			if (match) {
				injectHead = true;
			}

      if (injectTag === null && LiveServer.logLevel >= 3) {
        console.warn("Failed to inject refresh script!".yellow,
          "Couldn't find any of the tags ", injectCandidates, "from", filepath);
      }
    }

    function file(filepath /*, stat*/) {
      var x = path.extname(filepath).toLocaleLowerCase(),
          possibleExtensions = [ "", ".html", ".htm", ".xhtml", ".php", ".svg" ];
      if (hasNoOrigin && (possibleExtensions.indexOf(x) > -1)) {
        // TODO: Sync file read here is not nice, but we need to determine if the html should be injected or not
        var contents = fs.readFileSync(filepath, "utf8");
        
        find_inject_tag(filepath, contents);
      }

      if (LiveServer.markdownStyle && x === '.md') {
        injectMarkdown = true;
      }
    }

    function error(err) {
      if (err.status === 404) return next();
      next(err);
    }

    function inject(stream) {
			var len = res.getHeader('Content-Length');
			var doInject = false;
      var originalPipe;

      if (injectTag) {
				len += Buffer.byteLength(INJECTED_RELOAD_CODE, 'utf8');
				doInject = true;
			}
			if (injectBody) {
				len += Buffer.byteLength(bodyInjection, 'utf8');
				doInject = true;
			}
			if (injectHead) {
				len += Buffer.byteLength(headInjection, 'utf8');
				doInject = true;
			}

			if (doInject) {
        res.setHeader('Content-Length', len);

        originalPipe = stream.pipe;
				stream.pipe = function(resp) {
					var p = originalPipe.call(stream, es.through(function write(data) {this.emit('data', data)}));

					if (injectTag) {
						p = p.pipe(es.replace(new RegExp(injectTag, "i"), INJECTED_RELOAD_CODE + injectTag));
					}

					if (injectHead) {
						p = p.pipe(es.replace(new RegExp("</head>", "i"), headInjection + "</head>"));
					}

					if (injectHead) {
						p = p.pipe(es.replace(new RegExp("</body>", "i"), bodyInjection + "</body>"));
					}

					p.pipe(resp);
				}
      }
      if (injectMarkdown) {
        res.setHeader('Content-Type', 'text/html');
        res.removeHeader('Content-Length');
        // TODO: Modify the length given to the browser
        originalPipe = stream.pipe;
        stream.pipe = function (s) {
          originalPipe.call(stream, sink()).then(function (md) {
            var content = marked(md);
            var template_filepath = __dirname + '/markdown.html';
            var html = fs.readFileSync(template_filepath).toString();
            html = html.replace('%content%', content);
            html = html.replace('%class%', markdownStyles[LiveServer.markdownStyle]);
        
            find_inject_tag(template_filepath, html);
            if (injectTag) {
              html = html.replace(new RegExp(injectTag, "i"), INJECTED_CODE + injectTag);
            }

            s.setHeader('Content-Length', html.length);
            s.write(html);
            s.end();
          });
        };
      }
    }

    if (req.method === "POST" || req.method === "PUT") {
      var inlen = parseFloat(req.headers['content-length']);
      var intype = req.headers['content-type'];

      console.log('request: ', req.method, req.url, req.headers, inlen, intype);

      // parse a file upload
      var form = new formidable.IncomingForm();
      // https://github.com/felixge/node-formidable  /  https://github.com/felixge/node-formidable/commit/228788774ba83f2f8cd93756bed9662ffb24e72f  /  https://github.com/felixge/node-formidable/issues/33
      form.multiples = true;

      form.parse(req, function (err, fields, files) {
        console.log('request decoded fields and files: ', {
          err: err, 
          fields: fields, 
          filelist: files
        });

        var cbCalled = [];
        var fileResults = [];
        var filelst4response = [];

        function copy_file_closure(ii) {
          function done(n, ex, msg) {
            console.warn('file copy done? ', ii, n, msg, ex, cbCalled);

            if (!cbCalled[n]) {
              fileResults[n] = {
                msg: msg,
                ex: ex
              };
              cbCalled[n] = true;
            }

            // check if all uploaded files have been processed, one way or another:
            var is_done = true;
            for (var j = 0, len = cbCalled.length; j < len; j++) {
              if (!cbCalled[j]) {
                is_done = false;
                break;
              }
            }
            if (is_done) {
              resf('done', cbCalled.length, ii, n);
            }
          }

          return function copy(srcpath, dstpath) {
            var rd = fs.createReadStream(srcpath);
            rd.on("error", function (ex) {
              done(ii, ex, "copying file from temporary storage");
            });

            filelst4response.push(dstpath);

            mkdirp.sync(path.dirname(dstpath));

            var wr = fs.createWriteStream(dstpath);
            wr.on("error", function(ex) {
              done(ii, ex, "writing uploaded file to storage");
            });
            wr.on("close", function(ex) {
              done(ii, ex, "closing uploaded file");
            });
            rd.pipe(wr);
          };
        }

        function do_one_file(file_info) {
          console.log('processing uploaded file: ', root, reqpath, file_info.name, file_info.type, file_info.size, file_info.path, file_info.lastModifiedDate);

          // when no actual file was uploaded in this slot, skip the slot!
          if (!file_info.name) return;

          var dstpath = root + '/' + reqpath + '/' + file_info.name.replace(/^[^a-z0-9_]/i, '_').replace(/[^a-z0-9_]$/i, '_').replace(/[^a-z0-9_\-\.]/i, '_');
          var dstpath2 = path.normalize(dstpath);
          console.log('dstpath: ', dstpath, dstpath2, path.dirname(dstpath2));
          
          // closure:
          var cp = copy_file_closure(i);

          cbCalled[i] = false;
          i++;

          cp(file_info.path, dstpath2);
        }

        var i = 0;
        for (var key in files) {
          // copy file:
          var file_infos = files[key];
          console.log('file_infos: ', file_infos, file_infos.length);
          if (file_infos.length > 0) {
            for (var i2 = 0, fcnt = file_infos.length; i2 < fcnt; i2++) {
              var file_info = file_infos[i2];

              do_one_file(file_info);
            } 
          } else {
            do_one_file(file_infos);
          }
        }

        // and when there are no files at all...
        if (i === 0) {
          console.log('no files uploaded at all!');
          resf('done', i);
        }

        function resf(mode) {
          console.log('response: ', mode, arguments, res.statusCode);

          res.statusCode = 200;
          res.setHeader('Content-Type', 'text/plain');
          res.removeHeader('Content-Length');
          res.write('received upload:\n\n' + filelst4response.length + ' files:\n\n' + filelst4response.join('\n') + '\n\n' + JSON.stringify(fileResults));
          res.end();
        }
      });
    } else {
      send(req, reqpath, { root: root })
        .on('error', error)
        .on('directory', directory)
        .on('file', file)
        .on('stream', inject)
        .pipe(res);
    }
  };
}

/**
 * Rewrite request URL and pass it back to the static handler.
 * @param staticHandler {function} Next handler
 * @param file {string} Path to the entry point file
 */
function entryPoint(staticHandler, file) {
  if (!file) return function (req, res, next) { next(); };

  return function (req, res, next) {
    req.url = "/" + file;
    staticHandler(req, res, next);
  };
}

/**
 * Start a live server with parameters given as an object
 * @param host {string} Address to bind to (default: 0.0.0.0)
 * @param port {number} Port number (default: 8080)
 * @param root {string} Path to root directory (default: cwd)
 * @param watch {array} Paths to exclusively watch for changes
 * @param ignore {array} Paths to ignore when watching files for changes
 * @param ignorePattern {regexp} Ignore files by RegExp
 * @param noCssInject Don't inject CSS changes, just reload as with any other file change
 * @param noBrowser {boolean} Suppress automatic web browser launching
 * @param browser {string} Specify browser to use instead of system default
 * @param open {(string|string[])} Subpath(s) to open in browser, use false to suppress launch (default: server root)
 * @param bodyInjection {string} Content to be injected before </body>
 * @param headInjection {string} Content to be injected before </head>
 * @param mount {array} Mount directories onto a route, e.g. [['/components', './node_modules']].
 * @param logLevel {number} 0 = errors only, 1 = some, 2 = lots
 * @param file {string} Path to the entry point file
 * @param wait {number} Server will wait the specified number of milliseconds for all changes, before reloading
 * @param htpasswd {string} Path to htpasswd file to enable HTTP Basic authentication
 * @param middleware {array} Append middleware to stack, e.g. [function (req, res, next) { next(); }].
 * @param cors {boolean} Enables CORS for any origin (reflects request origin, requests with credentials are supported)
 * @param https {string} PATH to a HTTPS configuration module
 * @param proxy {string} Proxy all requests for ROUTE to URL (string format: "ROUTE:URL") 
 * @param markdown {string} When non-NULL, render markdown files to HTML using the given style
 */
LiveServer.start = function (options) {
  options = options || {};
  var host = options.host || '0.0.0.0';
  var port = options.port !== undefined ? options.port : 8080; // 0 means random
  var root = options.root || process.cwd();
  var mount = options.mount || [];
  var watchPaths = options.watch || [root];
  LiveServer.logLevel = options.logLevel === undefined ? 2 : options.logLevel;
  var openPath = (options.open === undefined || options.open === true) ?
    "" : ((options.open === null || options.open === false) ? null : options.open);
  if (options.noBrowser) openPath = null; // Backwards compatibility with 0.7.0
  var file = options.file;
	var headInjection = options.headInjection || "";
	var bodyInjection = options.bodyInjection || "";
	var staticServerHandler = staticServer(root, headInjection, bodyInjection);
	var wait = options.wait === undefined ? 100 : options.wait;
  var browser = options.browser || null;
  var htpasswd = options.htpasswd || null;
  var cors = options.cors || false;
  var https = options.https || null;
  var proxy = options.proxy || [];
  var middleware = options.middleware || [];
	var noCssInject = options.noCssInject;
	var httpsModule = options.httpsModule;

  LiveServer.markdownStyle = options.markdown;

	if (httpsModule) {
		try {
			require.resolve(httpsModule);
		} catch (e) {
			console.error(("HTTPS module \"" + httpsModule + "\" you've provided was not found.").red);
			console.error("Did you do", "\"npm install " + httpsModule + "\"?");
			return;
		}
	} else {
		httpsModule = "https";
	}

  // Setup a web server
  var app = connect();

  // Add logger. Level 2 logs only errors
  if (LiveServer.logLevel === 2) {
    app.use(logger('dev', {
      skip: function (req, res) { return res.statusCode < 400; }
    }));
  // Level 2 or above logs all requests
  } else if (LiveServer.logLevel > 2) {
    app.use(logger('dev'));
  }
  // Add middleware
	middleware.map(function(mw) {
		if (typeof mw === "string") {
			var ext = path.extname(mw).toLocaleLowerCase();
			if (ext !== ".js") {
				mw = require(path.join(__dirname, "middleware", mw + ".js"));
			}
			else if (path.isAbsolute(mw)) {
				mw = require(mw);
			} else {
				mw = require(path.join(process.cwd(), mw));
			}
		}
		app.use(mw);
	});

	// Use http-auth if configured
	if (htpasswd !== null) {
		var auth = require('http-auth');
		var basic = auth.basic({
			realm: "Please authorize",
			file: htpasswd
		});
		app.use(auth.connect(basic));
	}
	if (cors) {
		app.use(require("cors")({
			origin: true, // reflecting request origin
			credentials: true // allowing requests with credentials
		}));
	}
	mount.forEach(function(mountRule) {
		var mountPath = path.resolve(process.cwd(), mountRule[1]);
		if (!options.watch) // Auto add mount paths to wathing but only if exclusive path option is not given
			watchPaths.push(mountPath);
		app.use(mountRule[0], staticServer(mountPath, headInjection, bodyInjection));
		if (LiveServer.logLevel >= 1)
			console.log('Mapping %s to "%s"', mountRule[0], mountPath);
	});
	proxy.forEach(function(proxyRule) {
		var proxyOpts = url.parse(proxyRule[1]);
		proxyOpts.via = true;
		proxyOpts.preserveHost = true;
		app.use(proxyRule[0], require('proxy-middleware')(proxyOpts));
		if (LiveServer.logLevel >= 1)
			console.log('Mapping %s to "%s"', proxyRule[0], proxyRule[1]);
	});
	app.use(staticServerHandler) // Custom static server
		.use(entryPoint(staticServerHandler, file))
		.use(serveIndex(root, { icons: true }));

	var server, protocol;
	if (https !== null) {
		var httpsConfig = https;
		if (typeof https === "string") {
			httpsConfig = require(path.resolve(process.cwd(), https));
		}
		server = require(httpsModule).createServer(httpsConfig, app);
		protocol = "https";
	} else {
		server = http.createServer(app);
		protocol = "http";
	}

	// Handle server startup errors
	server.addListener('error', function(e) {
		if (e.code === 'EADDRINUSE') {
			var serveURL = protocol + '://' + host + ':' + port;
			console.log('%s is already in use. Trying another port.'.yellow, serveURL);
			setTimeout(function() {
				server.listen(0, host);
			}, 1000);
		} else {
			console.error(e.toString().red);
			LiveServer.shutdown();
		}
	});

	// Handle successful server
	server.addListener('listening', function(/*e*/) {
		LiveServer.server = server;

		var address = server.address();
		var serveHost = address.address === "0.0.0.0" ? "127.0.0.1" : address.address;
		var openHost = host === "0.0.0.0" ? "127.0.0.1" : host;

		var serveURL = protocol + '://' + serveHost + ':' + address.port;
		var openURL = protocol + '://' + openHost + ':' + address.port;

		var serveURLs = [ serveURL ];
		if (LiveServer.logLevel > 2 && address.address === "0.0.0.0") {
			var ifaces = os.networkInterfaces();
			serveURLs = Object.keys(ifaces)
				.map(function(iface) {
					return ifaces[iface];
				})
				// flatten address data, use only IPv4
				.reduce(function(data, addresses) {
					addresses.filter(function(addr) {
						return addr.family === "IPv4";
					}).forEach(function(addr) {
						data.push(addr);
					});
					return data;
				}, [])
				.map(function(addr) {
					return protocol + "://" + addr.address + ":" + address.port;
				});
		}

    // Output
    if (LiveServer.logLevel >= 1) {
      if (serveURL === openURL)
				if (serveURLs.length === 1) {
					console.log(("Serving \"%s\" at %s").green, root, serveURLs[0]);
				} else {
					console.log(("Serving \"%s\" at\n\t%s").green, root, serveURLs.join("\n\t"));
				}
      else
        console.log(("Serving \"%s\" at %s (%s)").green, root, openURL, serveURL);
    }

    // Launch browser
    if (openPath !== null)
			if (typeof openPath === "object") {
				openPath.forEach(function(p) {
					open(openURL + p, {app: browser});
				});
			} else {
				open(openURL + openPath, {app: browser});
			}
  });

  // Setup server to listen at port
  server.listen(port, host);

  // WebSocket
  var clients = [];
  server.addListener('upgrade', function (request, socket, head) {
    var ws = new WebSocket(request, socket, head);
    ws.onopen = function () { 
      ws.send('connected'); 
    };

    if (wait > 0) {
      var wssend = ws.send;
      var waitTimeout;

      ws.send = function () {
        var args = arguments;
        if (waitTimeout) clearTimeout(waitTimeout);
        waitTimeout = setTimeout(function () {
          wssend.apply(ws, args);
        }, wait);
      };
    }

    ws.onclose = function () {
      clients = clients.filter(function (x) {
        return x !== ws;
      });
    };

    clients.push(ws);
  });

	var ignored = [
		function(testPath) { // Always ignore dotfiles (important e.g. because editor hidden temp files)
			return testPath !== "." && /(^[.#]|(?:__|~)$)/.test(path.basename(testPath));
		}
	];
	if (options.ignore) {
		ignored = ignored.concat(options.ignore);
	}
	if (options.ignorePattern) {
		ignored.push(options.ignorePattern);
	}
  // Setup file watcher
	LiveServer.watcher = chokidar.watch(watchPaths, {
		ignored: ignored,
		ignoreInitial: true
	});
	function handleChange(changePath) {
		var cssChange = path.extname(changePath) === ".css" && !noCssInject;
		if (LiveServer.logLevel >= 1) {
			if (cssChange) {
				console.log("CSS change detected".magenta, changePath);
      } else {
        console.log("Change detected".cyan, changePath);
      }
		}
		clients.forEach(function(ws) {
			if (ws)
				ws.send(cssChange ? 'refreshcss' : 'reload');
		});
	}
	LiveServer.watcher
		.on("change", handleChange)
		.on("add", handleChange)
		.on("unlink", handleChange)
		.on("addDir", handleChange)
		.on("unlinkDir", handleChange)
		.on("ready", function () {
			if (LiveServer.logLevel >= 1)
				console.log("Ready for changes".cyan);
		})
		.on("error", function (err) {
			console.log("ERROR:".red, err);
		});
	
	LiveServer.refreshCSS = function () {
		if (clients.length) {
			clients.forEach(function(ws) {
				if (ws) {
					ws.send('refreshcss');
				}
			});
		}
	};
	
	LiveServer.reload = function () {
		if (clients.length) {
			clients.forEach(function (ws) {
				if (ws) {
					ws.send('reload');
				}
			});
		}
	};
	
  return server;
};

LiveServer.shutdown = function () {
	var watcher = LiveServer.watcher;
	if (watcher) {
		watcher.close();
  }
  var server = LiveServer.server;
  if (server)
    server.close();
};

module.exports = LiveServer;
module.exports.markdownStyles = markdownStyles;
