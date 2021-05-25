#!/usr/bin/env node
var fs = require('fs'),
  connect = require('connect'),
  serveIndex = require('@gerhobbelt/serve-index'),
  logger = require('morgan'),
  WebSocket = require('faye-websocket'),
  path = require('path'),
  url = require('url'),
  http = require('http'),
  send = require('send'),
  formidable = require('formidable'),
  open = require('open'),
  sink = require('@gerhobbelt/stream-sink'),
  MarkdownIt = require('@gerhobbelt/markdown-it'),
  es = require("event-stream"),
	os = require('os'),
	chokidar = require('chokidar'),
  mkdirp = require('mkdirp'),
  { createProxyMiddleware } = require('http-proxy-middleware');
require('colors');

var INJECTED_RELOAD_CODE = fs.readFileSync(path.join(__dirname, "injected.html"), "utf8");

// MarkdownIt: options list
var markdown = MarkdownIt({
  html:         true,         // Enable HTML tags in source
  breaks:       false,        // Convert '\n' in paragraphs into <br>
  linkify:      true,         // Autoconvert URL-like text to links

  // Enable some language-neutral replacement + quotes beautification
  typographer:  true,

  // Double + single quotes replacement pairs, when typographer enabled,
  // and smartquotes on. Could be either a String or an Array.
  //
  // For example, you can use '«»„“' for Russian, '„“‚‘' for German,
  // and ['«\xA0', '\xA0»', '‹\xA0', '\xA0›'] for French (including nbsp).
  quotes: '“”‘’',

  // Highlighter function. Should return escaped HTML,
  // or '' if the source string is not changed and should be escaped externally.
  // If result starts with <pre... internal wrapper is skipped.
  highlight: function (/*str, lang*/) { return ''; },
  
  // Configure default attributes for given tags
  default_attributes:  { 'a': [/*['rel', 'nofollow']*/] }
});

// MarkdownIt Plugins load
// 
// markdown = markdown
//             .use(plugin1)
//             .use(plugin2, opts, ...)
//             .use(plugin3);


var LiveServer = {
  server: null,
	wsready: null,
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
		var injectCandidates = [ "body", "head", "svg" ];
    var injectTag = null;
		var injectCount = 0;
		var injectBody = false;
		var injectHead = false;
    var injectMarkdown = false;
    var fileExt = "";

    function directory() {
      var pathname = url.parse(req.originalUrl).pathname;
      res.statusCode = 301;
      res.setHeader('Location', pathname + '/');
      res.end('Redirecting to ' + escape(pathname) + '/');
    }

    function find_inject_tag(filepath, contents) {
      var matches;

      injectTag = null;

		  // first looking for tags with high priority
      for (var i = 0; i < injectCandidates.length; ++i) {
        var tag_re = new RegExp("</\\s*" + injectCandidates[i] + "\\s*>", "i");
				matches = contents.match(tag_re);
				injectCount = (matches && matches.length) || 0;
				if (injectCount) {
					injectTag = matches[0];
          break;
        }
      }

			var match = (new RegExp("</\\s*body\\s*>", "i")).exec(contents);
			if (match) {
				injectBody = true;
			}
			match = (new RegExp("</\\s*head\\s*>", "i")).exec(contents);
			if (match) {
				injectHead = true;
			}

  		// if injectTag not found then trying to find at least one closing tag on the page.
			if (injectTag === null) {
        // ignore the </HTML> tag as that one will be useless = occurring too late to matter:
        var c2 = contents.replace(/<\/\s*html\s*>/i, '');
  			var start = c2.lastIndexOf('</');
				var end = c2.lastIndexOf('>');

				if (start !== -1 && end > start) {
					injectTag = c2.slice(start, end + 1);
				}
			}

			if (injectTag) {
  	    if (LiveServer.logLevel >= 3) {
          console.log('Script is injected in the ' + injectTag + ' tag.');
        }
			} else {
        if (LiveServer.logLevel >= 1) {
          console.warn("Failed to inject refresh script!".yellow,
            "Couldn't find any of the tags", injectCandidates, "from", filepath, "nor any other closing tag.");
        }
      }
    }

    function file(filepath /*, stat*/) {
      fileExt = path.extname(filepath).toLocaleLowerCase();
      var possibleExtensions = [ "", ".html", ".htm", ".xhtml", ".php", ".svg" ];
			if (hasNoOrigin && (possibleExtensions.indexOf(fileExt) > -1)) {
				// TODO: Sync file read here is not nice, but we need to determine if the html should be injected or not
        var contents = fs.readFileSync(filepath, "utf8");
        
        find_inject_tag(filepath, contents);
      }

      if (LiveServer.markdownStyle && fileExt === '.md') {
        injectMarkdown = true;
      }
    }

    function error(err) {
			if (err.status === 404) {
				var accept = req.headers['accept'];
				if (accept && accept.indexOf('text/html') >= 0) {
          var requestedFile = req.url.replace(/[?#].*$/, '').replace(/^.*\/(?:index\.[a-z]*$)?/, '');
          if (requestedFile === '') {
            // directory index requested. Fall through!
            return next();
          }

					res.statusCode = 404;
					res.end(`<html><head><meta http-equiv="refresh" content="5"></head>
            <body><h1>404 not found</h1>
            <p>Error message: ${err}</p>
            <hr>
            <p>Will attempt to reload in 5 seconds...</p>
            <p>Or you can go to the home page <a href="/">by clicking here</a>.<p>
            </body></html>`);
          return;
				} else {
					if (LiveServer.logLevel >= 3) {
						console.warn("Didn't find text/html in ACCEPT header, so using default handler. ACCEPT header = ", accept);
					}
				}
        return next();
			}
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
			var len = INJECTED_RELOAD_CODE.length + res.getHeader('Content-Length');
			if (doInject) {
        res.setHeader('Content-Length', len);

        originalPipe = stream.pipe;
				stream.pipe = function(resp) {
					var p = originalPipe.call(stream, es.through(function write(data) {this.emit('data', data)}));

					if (injectTag) {
						p = p.pipe(es.replace(injectTag, INJECTED_RELOAD_CODE + injectTag));
					}

					if (injectHead) {
						p = p.pipe(es.replace(new RegExp("</\\s*head\\s*>", "i"), headInjection + "</head>"));
					}

					if (injectHead) {
						p = p.pipe(es.replace(new RegExp("</\\s*body\\s*>", "i"), bodyInjection + "</body>"));
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
            var content = markdown.render(md);
            var template_filepath = __dirname + '/markdown.html';
            var html = fs.readFileSync(template_filepath).toString();
            html = html.replace('%content%', content);
            html = html.replace('%class%', markdownStyles[LiveServer.markdownStyle] || markdownStyles['html']);
        
            find_inject_tag(template_filepath, html);
            if (injectTag) {
              html = html.replace(new RegExp(injectTag, "i"), INJECTED_RELOAD_CODE + injectTag);
            }

            s.setHeader('Content-Length', html.length);
            s.write(html);
            s.end();
          });
        };
      }
      else if (fileExt === ".wasm") {
        res.setHeader('Content-Type', 'application/wasm');
      }
   }

    if (req.method === "POST" || req.method === "PUT") {
      var inlen = parseFloat(req.headers['content-length']);
      var intype = req.headers['content-type'];

      if (LiveServer.logLevel >= 3) {
        console.log('request: ', req.method, req.url, req.headers, inlen, intype);
      }

      // parse a file upload
      var form = new formidable.IncomingForm();
      // https://github.com/felixge/node-formidable  /  https://github.com/felixge/node-formidable/commit/228788774ba83f2f8cd93756bed9662ffb24e72f  /  https://github.com/felixge/node-formidable/issues/33
      form.multiples = true;

      form.parse(req, function (err, fields, files) {
        if (LiveServer.logLevel >= 3) {
          console.log('request decoded fields and files: ', {
            err: err, 
            fields: fields, 
            filelist: files
          });
        }

        var cbCalled = [];
        var fileResults = [];
        var filelst4response = [];

        function copy_file_closure(ii) {
          function done(n, ex, msg) {
            if (LiveServer.logLevel >= 3) {
              console.warn('file copy done? ', ii, n, msg, ex, cbCalled);
            }

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
          if (LiveServer.logLevel >= 3) {
            console.log('processing uploaded file: ', root, reqpath, file_info.name, file_info.type, file_info.size, file_info.path, file_info.lastModifiedDate);
          }

          // when no actual file was uploaded in this slot, skip the slot!
          if (!file_info.name) return;

          var dstpath = root + '/' + reqpath + '/' + file_info.name.replace(/^[^a-z0-9_]/i, '_').replace(/[^a-z0-9_]$/i, '_').replace(/[^a-z0-9_\-\.]/i, '_');
          var dstpath2 = path.normalize(dstpath);
          if (LiveServer.logLevel >= 3) {
            console.log('dstpath: ', dstpath, dstpath2, path.dirname(dstpath2));
          }
          
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
          if (LiveServer.logLevel >= 3) {
            console.log('file_infos: ', file_infos, file_infos.length);
          }
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
          if (LiveServer.logLevel >= 3) {
            console.log('no files uploaded at all!');
          }
          resf('done', i);
        }

        function resf(mode) {
          if (LiveServer.logLevel >= 3) {
            console.log('response: ', mode, arguments, res.statusCode);
          }

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
	  		.on('headers', headers)
        .pipe(res);
    }
  };
}

function headers (res, path, stat) {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
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
 * Get the local ip
 * @return {String} IP
 */
function getIPAdress(){
	var interfaces = require('os').networkInterfaces();
	for(var devName in interfaces) {
		var iface = interfaces[devName];
		for(var i=0;i<iface.length;i++) {
			var alias = iface[i];
			if(alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal){
				return alias.address;
			}
		}
	}
	return '127.0.0.1';
}

/**
 * Start a live server with parameters given as an object
 * @param host {string} Address to bind to (default: 0.0.0.0)
 * @param port {number} Port number (default: 8085)
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
 * @param watchDotfiles Don't ignore changes to files & folders beginning with '.' from the watch directory
 * @param mimetypes {object} MIME Types of extended files.
 * @param cors {boolean} Enables CORS for any origin (reflects request origin, requests with credentials are supported)
 * @param https {string} PATH to a HTTPS configuration module
 * @param proxy {string} Proxy all requests for ROUTE to URL (string format: "ROUTE:URL") 
 * @param markdown {string} When non-NULL, render markdown files to HTML using the given style
 */
LiveServer.start = function (options) {
  options = options || {};
  var host = options.host || '0.0.0.0';
  var port = options.port !== undefined ? options.port : 8085; // 0 means random
  var root = options.root || process.cwd();
  var mount = options.mount || [];
  var watchPaths = options.watch || [root];
  LiveServer.watchPaths = watchPaths;
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
	var beforeReload = options.beforeReload || function noop() {};
	var noDirectories = options.noDirectories || false;
	var mimetypes = options.mimetypes || {};
	var setws = options.setws || null;

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
		app.use(logger('combined'));
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

	// Clear the default duplicate configuration
	var mimetypesKeys = Object.keys(mimetypes);
	Object.keys(send.mime.types).forEach(function(typesKey) {
		var typesValue = send.mime.types[typesKey];

		if (mimetypesKeys.indexOf(typesValue) > -1) {
			delete send.mime.types[typesKey];
			delete send.mime.extensions[typesValue];
		}
	});
	// Set extended mimetypes
	send.mime.define(mimetypes);

  var protocol;
  var httpsConfig = https;
  if (https !== null) {
    if (typeof https === "string") {
      httpsConfig = require(path.resolve(process.cwd(), https));
    }
    protocol = "https";
  } else {
    protocol = "http";
  }

	// Use http-auth if configured
	if (htpasswd !== null) {
		var auth = require('http-auth');
    var authConnect = require('http-auth-connect');
		var basic = auth.basic({
			realm: "Please authorize",
			file: htpasswd
		});
		app.use(authConnect(basic));
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
		proxyOpts.changeOrigin = false;
    //proxyOpts.changeOrigin = true;               // needed for virtual hosted sites
    proxyOpts.preserveHost = true;
    var openHost = host === "0.0.0.0" ? "127.0.0.1" : host;
    var serveURL = protocol + '://' + openHost + ':' + port;
    proxyOpts.target = serveURL; 
    if (LiveServer.logLevel >= 3) {
      console.log('proxy:', proxyOpts);
    }
    if (options.unsecureProxy) {
			process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
      proxyOpts.rejectUnauthorized = false;
      proxyOpts.checkServerIdentity = function () {
        return undefined;
      };
    }
		app.use(proxyRule[0], createProxyMiddleware('/', proxyOpts));
		if (LiveServer.logLevel >= 1)
			console.log('Mapping %s to "%s"', proxyRule[0], proxyRule[1]);
	});

  //
  // Sort helper: sort file & directory names numerically based on their numeric parts, 
  // if they have any *and* the non-numeric prefixes match up.
  // Otherwise sort them alphanumerically.
  // 
	function indexPageSort(a, b) {
	  var aIsADirectory = a.stat && a.stat.isDirectory();
	  var bIsADirectory = b.stat && b.stat.isDirectory();
	  var directoryComparison = Number(bIsADirectory) - Number(aIsADirectory);
	  if (directoryComparison !== 0) {
	    return directoryComparison;
    }
	
    var aParsedName = a.name;
    var bParsedName = b.name;

    // make sure the regex consumes at least one character each round:
    // that's what the `|...` alt at the end of it is for. The obvious
    // regex `/([^\d]*)([\d]*)/g` will fail miserably with zero-length 
    // matches till Kingdom Come!
    // 
    // This way we prevent running into (catastrophic regex execution)[https://www.regular-expressions.info/catastrophic.html].
    var re = /([^\d]*)([\d]+)|([^\d]+)/g;
    var aa = [];
    var bb = [];
    // we have to collect all matches for aParsedName before we do the same
    // for bParsedName due to the nature of the RegExp.exec() behaviour:
    for (;;) {
      var match = re.exec(aParsedName); 
      if (match === null) break;
      aa.push(match[1], match[2], match[3], match.index);
    }
    for (;;) {
      var match = re.exec(bParsedName); 
      if (match === null) break;
      bb.push(match[1], match[2], match[3], match.index);
    }

    // now the arrays `aa` and `bb` contain a set of the quads: (non-numeric)(numeric)(last-non-numeric)(start-index-of-match),
    // which we can use to compare the file/directory names:
    for (var i = 0; ; i += 4) {
      var aPrefix = aa[i];
      var bPrefix = bb[i];

      var stringComparison = String(aPrefix).toLocaleLowerCase().localeCompare(String(bPrefix).toLocaleLowerCase());
      if (stringComparison) {
        // WARNING: it may be that one of the files is lacking a numric part, hence we need 
        // to perform this comparison once again with the full tail of both:
        if (aPrefix === '' || bPrefix === '') {
          aPrefix = aParsedName.substring(aa[i + 3]);
          bPrefix = bParsedName.substring(bb[i + 3]);
          stringComparison = String(aPrefix).toLocaleLowerCase().localeCompare(String(bPrefix).toLocaleLowerCase());
        }
        return stringComparison;
      }

      var aNumber = Number(aa[i + 1]);
      var bNumber = Number(bb[i + 1]);
      var aCanBeCastToANumber = !isNaN(aNumber);
      var bCanBeCastToANumber = !isNaN(bNumber);
      var nanComparison = Number(bCanBeCastToANumber) - Number(aCanBeCastToANumber);
      if (nanComparison === 0 && aCanBeCastToANumber) {
        // this implies bCanBeCastToANumber=true once we arrive here!
        var numberComparison = Math.sign(bNumber - aNumber);
        if (numberComparison !== 0) {
          return numberComparison;
        }
      } else {
        // one of the files has only a non-numeric tail left (while that tail *may* be empty),
        // hence we can only end now with an alphanumeric comparison of the remaining tails:
        aPrefix = aParsedName.substring(aa[i + 3]);
        bPrefix = bParsedName.substring(bb[i + 3]);
        stringComparison = String(aPrefix).toLocaleLowerCase().localeCompare(String(bPrefix).toLocaleLowerCase());
        return stringComparison;
      }
    }
	}

	if (noDirectories) {
		app.use(staticServerHandler) // Custom static server
		  .use(entryPoint(staticServerHandler, file));
	} else {
		app.use(staticServerHandler) // Custom static server
	  	.use(entryPoint(staticServerHandler, file))
  		.use(serveIndex(root, { icons: true, sort: indexPageSort }));
	}

	var server;
	if (protocol === "https") {
		server = require(httpsModule).createServer(httpsConfig, app);
	} else {
		server = http.createServer(app);
	}

  LiveServer.server = server;

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
		var address = server.address();
		var serveHost = address.address === "0.0.0.0" ? "127.0.0.1" : address.address;
		var openHost = host === "0.0.0.0" ? getIPAdress() : host;

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

		if (setws) {
			setws(ws);
		}

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

	var alreadyWarnedDotfiles = false;
	var ignoredPaths = [
		function(testPath) { 
			/*
				Ignore dotfiles by default (important e.g. because editor
				hidden temp files), unless options.watchDotfiles is truthy.

				Regex explanation: 
				- Any relative or absolute path (the first capture group)
				- starting with a literal '.', and then followed by at least
				  one character (which excludes the CWD path '.')
			*/
			var notDotfileOrCwd = /(^|[\/\\])\../;
			var ignoreThisPath = options.watchDotfiles ? false : notDotfileOrCwd.test(path.basename(testPath));
			if (ignoreThisPath && LiveServer.logLevel >= 1) {
				if (alreadyWarnedDotfiles === false) {
          if (LiveServer.logLevel >= 3) {
	  				console.log('Ignoring files in paths beginning with ".", eg: %s\nUse "--watch-dotfiles" to also watch these.', path.basename(testPath));
          }
					alreadyWarnedDotfiles = true;
				}
      }
			return ignoreThisPath;
		}
	];
	if (options.ignore) {
		ignoredPaths = ignoredPaths.concat(options.ignore);
	}
	if (options.ignorePattern) {
		ignoredPaths.push(options.ignorePattern);
	}
  // Setup file watcher
	LiveServer.watcher = chokidar.watch(watchPaths, {
		ignored: ignoredPaths,
		ignoreInitial: true,
		disableGlobbing: true,
    atomic: 1000,              // treat editors' "Atomic writes" as such when they complete within 1 second. See https://github.com/paulmillr/chokidar#user-content-errors        
	});
	async function handleChange(changePath) {
    if (LiveServer.logLevel >= 1) {
      console.log("CHANGE:", changePath);
    }
		var cssChange = path.extname(changePath) === ".css" && !noCssInject;

		if (LiveServer.logLevel >= 1) {
			if (cssChange) {
				console.log("CSS change detected".magenta, changePath);
      } else {
        console.log("Change detected".cyan, changePath);
      }
			await beforeReload();
		}

		clients.forEach(function(ws) {
			if (ws)
				ws.send(cssChange ? 'refreshcss' : changePath);
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

  process.stdin.resume();
  process.stdin.setEncoding("utf-8");

  try {
    process.on('SIGINT', function() {
      if (LiveServer.logLevel >= 1) {
        console.log( "\nGracefully shutting down from SIGINT (Ctrl-C)" );
      }
      LiveServer.shutdown();
      process.exit(1);
    });

    var input_data = "";

    if (LiveServer.logLevel >= 1) {
      console.log(`

      +-------------------------------------------------------------------+
      |                                                                   |
      | Type the word 'exit' and then ENTER key to terminate live_server. |
      |                                                                   |
      +-------------------------------------------------------------------+

      `.yellow);
    }

    process.stdin.on("data", function(input) {
      input_data += input; // Reading input from STDIN
      //console.error("DATA: ", input_data.toLowerCase());

      // Be very lenient: any place the admin typed the letters "exit" 
      // in an otherwise possibly larger input stream from stdio,
      // terminate anyway!
      if (input_data.toLowerCase().includes("exit")) {
        if (LiveServer.logLevel >= 3) {
          console.log( "\nGracefully shutting down from EXIT admin command" );
        }
        LiveServer.shutdown();
        process.exit(2);
      }
    });

    process.stdin.on("end", function() {
      //console.error("END: ", input_data.toLowerCase());
    });
  }
  catch (ex) {
    console.error("stdin initialization failed. (Ignoring!)");
  }

  return server;
};

LiveServer.shutdown = function () {
  if (LiveServer.logLevel >= 1) {
    console.log("shutdown...");
  }
	var watcher = LiveServer.watcher;
	if (watcher) {
		watcher.close();
  }
  var server = LiveServer.server;
  if (server) {
    // see also https://stackoverflow.com/questions/14626636/how-do-i-shutdown-a-node-js-https-server-immediately
    server.keepAliveTimeout = 1; // ensure keep-alive connections are closed ASAP 
    server.timeout = 1;
    server.close(() =>  {
      if (LiveServer.logLevel >= 1) {
        console.log("server closed...");
      }
    });
    setImmediate(function () {
      server.emit('close');
    });
  }
  // // chokidar doesn't terminate.
  // // throw exception to kill the app anyway
  // setTimeout(() => {
  //   throw new Error("HACK: throw exception as long as https://github.com/paulmillr/chokidar/issues/855 has not been properly resolved");
  // }, 3000);
};

module.exports = LiveServer;
module.exports.markdownStyles = markdownStyles;
