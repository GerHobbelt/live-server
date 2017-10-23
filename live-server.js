#!/usr/bin/env node
var path = require('path');
var fs = require('fs');
var assign = require('object-assign');
var liveServer = require("./index");

var defaultOpts = {
  host: process.env.IP,
  port: process.env.PORT,
  open: true,
  markdown: 'html',
  mount: [],
  proxy: [],
	middleware: [],
	logLevel: 2,
};

var opts = {
  // MUST be empty as we will merge any option set in here to `defaultOpts` 
  // to produce the definitive `opts` collection for the server.
};

var configPath;

for (var i = process.argv.length - 1; i >= 2; --i) {
  var arg = process.argv[i];
  if (arg.indexOf("--port=") > -1) {
    var portString = arg.substring(7);
    var portNumber = parseInt(portString, 10);
    if (portNumber === +portString) {
      opts.port = portNumber;
      process.argv.splice(i, 1);
    }
  }
  else if (arg.indexOf("--host=") > -1) {
    opts.host = arg.substring(7);
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--open=") > -1) {
    var open = arg.substring(7);
    if (open.indexOf('/') !== 0) {
      open = '/' + open;
    }
		switch (typeof opts.open) {
      case "undefined":
			case "boolean":
				opts.open = open;
				break;
			case "string":
				opts.open = [opts.open, open];
				break;
			case "object":
				opts.open.push(open);
				break;
		}
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--watch=") > -1) {
    // Will be modified later when cwd is known
    opts.watch = arg.substring(8).split(",");
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--ignore=") > -1) {
    // Will be modified later when cwd is known
    opts.ignore = arg.substring(9).split(",");
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--ignorePattern=") > -1) {
    opts.ignorePattern = new RegExp(arg.substring(16));
    process.argv.splice(i, 1);
  }
	else if (arg === "--no-css-inject") {
		opts.noCssInject = true;
		process.argv.splice(i, 1);
	}
  else if (arg === "--no-browser") {
    opts.open = false;
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--browser=") > -1) {
    opts.browser = arg.substring(10).split(",");
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--entry-file=") > -1) {
    var file = arg.substring(13);
    if (file.length) {
      opts.file = file;
      process.argv.splice(i, 1);
    }
  }
  else if (arg === "--spa") {
    if (!opts.middleware) opts.middleware = [];
		opts.middleware.push("spa");
    process.argv.splice(i, 1);
  }
	else if (arg === '--spa-ignore-assets') {
    if (!opts.middleware) opts.middleware = [];
		opts.middleware.push("spa-ignore-assets");
		process.argv.splice(i, 1);
	}
  else if (arg === "--quiet" || arg === "-q") {
    opts.logLevel = 0;
    process.argv.splice(i, 1);
  }
  else if (arg === "--verbose" || arg === "-V") {
    opts.logLevel = 3;
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--mount=") > -1) {
    // e.g. "--mount=/components:./node_modules" will be ['/components', '<process.cwd()>/node_modules']
		// split only on the first ":", as the path may contain ":" as well (e.g. C:\file.txt)
		var match = arg.substring(8).match(/([^:]+):(.+)$/);
    if (!match) {
      console.log("Invalid mount point / route specified: the route must be non-empty, the path must be non-empty as well.");
      process.exit();
    }
		match[2] = path.resolve(process.cwd(), match[2]);
    if (!opts.mount) opts.mount = [];
		opts.mount.push([ match[1], match[2] ]);
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--wait=") > -1) {
    var waitString = arg.substring(7);
    var waitNumber = parseInt(waitString, 10);
    if (waitNumber === +waitString) {
      opts.wait = waitNumber;
      process.argv.splice(i, 1);
    } else {
      console.log('Invalid wait value (not a legal decimal numeric value): ', waitString);
      process.exit();
    }
  }
  else if (arg === "--version" || arg === "-v") {
    var packageJson = require('./package.json');
    console.log(packageJson.name, packageJson.version);
    process.exit();
  }
  else if (arg.indexOf("--htpasswd=") > -1) {
    opts.htpasswd = arg.substring(11);
    process.argv.splice(i, 1);
  }
  else if (arg === "--cors") {
    opts.cors = true;
    process.argv.splice(i, 1);
  }
  else if (arg.indexOf("--https=") > -1) {
    opts.https = arg.substring(8);
    process.argv.splice(i, 1);
  }
	else if (arg.indexOf("--https-module=") > -1) {
		opts.httpsModule = arg.substring(15);
		process.argv.splice(i, 1);
	}
	else if (arg.indexOf("--https") > -1) {
		opts.https = path.join(__dirname, 'test/conf/https.conf.js');
		process.argv.splice(i, 1);
	}
  else if (arg.indexOf("--proxy=") > -1) {
    // split only on the first ":", as the URL will contain ":" as well
    var match = arg.substring(8).match(/([^:]+):(.+)$/);
    if (!opts.proxy) opts.proxy = [];
    opts.proxy.push([ match[1], match[2] ]);
    process.argv.splice(i, 1);
  }
	else if (arg.indexOf("--middleware=") > -1) {
    if (!opts.middleware) opts.middleware = [];
		opts.middleware.push(arg.substring(13));
		process.argv.splice(i, 1);
	}
  else if (arg === "--help" || arg === "-h") {
    console.log('Usage: live-server [-v|--version] [-h|--help] [-q|--quiet] [-V|--verbose] [--port=PORT] [--host=HOST] [--open=PATH] [--no-browser] [--browser=BROWSER] [--ignore=PATH] [--ignorePattern=RGXP] [--no-css-inject] [--entry-file=PATH] [--spa] [--spa-ignore-assets] [--mount=ROUTE:PATH] [--wait=MILLISECONDS] [--htpasswd=PATH] [--cors] [--https[=PATH]] [--https-module=MODULE_NAME] [--proxy=PATH] [--config=FILE] [PATH]');
    process.exit();
  }
  else if (arg === "--test") {
    // Hidden param for tests to exit automatically
    setTimeout(liveServer.shutdown, 500);
    process.argv.splice(i, 1);
  } else if (arg === "--no-markdown") {
    opts.markdown = false;
    process.argv.splice(i, 1);
  } else if (arg.indexOf("--markdown=") > -1) {
    opts.markdown = arg.substring(11);
    var valid = Object.keys(liveServer.markdownStyles);
    if(valid.indexOf(opts.markdown) === -1) {
      console.log('Invalid markdown style. Options: ' + valid.join(', '));
      process.exit();
    }
    process.argv.splice(i, 1);
  } else if (arg.indexOf("--config=") > -1) {
    configPath = arg.substring(9);
    if (opts.logLevel) {
      console.info("Command-line-argument-level config file specified at: ".cyan, configPath);
    }
    process.argv.splice(i, 1);
  }
}

// Patch paths
opts.root = process.argv[2] || process.cwd();

// When no config file has been specified, load a user-level or project-level one, iff available:
if (!configPath) {
  var homeDir = process.env[(process.platform === 'win32') ? 'USERPROFILE' : 'HOME'];
  if (homeDir) {
    var userConfigPath = path.join(homeDir, '.live-server.json');
    if (fs.existsSync(userConfigPath)) {
      if (opts.logLevel) {
        console.log("User-level config file detected at: ".cyan, userConfigPath);
      }
      configPath = userConfigPath;
    }
  }
}
if (!configPath) {
  var projectConfigPath = path.join(opts.root, '.live-server.json');
  if (fs.existsSync(projectConfigPath)) {
    if (opts.logLevel) {
      console.log("Project-level config file detected at: ".cyan, projectConfigPath);
    }
    configPath = projectConfigPath;
  }
}

// Note: if `configPath` is set, it MUST exist (or trigger a fatal error)
if (configPath) {
  var configData = fs.readFileSync(configPath, 'utf8');
  assign(defaultOpts, JSON.parse(configData));
  if (defaultOpts.ignorePattern) defaultOpts.ignorePattern = new RegExp(defaultOpts.ignorePattern);
}
// Merge config file/default options and the ones obtained from the command line:
assign(defaultOpts, opts);
opts = defaultOpts;

if (opts.watch) {
  opts.watch = opts.watch.map(function (relativePath) {
    return path.join(opts.root, relativePath);
  });
}
if (opts.ignore) {
  opts.ignore = opts.ignore.map(function (relativePath) {
    return path.join(opts.root, relativePath);
  });
}

liveServer.start(opts);
