# Molly Brown

The Unsinkable Molly Brown is a full-featured Gemini server
implemented in Go.

For more information on the Gemini protocol see:

* https://gemini.circumlunar.space
* gopher://gemini.circumlunar.space
* gemini://gemini.circumlunar.space

## Overview

Molly Brown is intended to be a full-featured Gemini server which is
suitable for use in pubnix or similar shared-hosting environments,
where users can upload their content but do not have access to the
main configuration file (of course, it is also perfectly suitable for
single user environments, but its multi-user supports sets it apart
from many other Gemini servers).

Molly Brown features:

* Support for traditional `~username` URLs.
* Automatic directory listings, with support for customised headers
  and footers, control over file sorting order and the ability to
  use headings from `text/gemini` content in place of filenames.
* Determination of MIME type via filename extension, which can be
  manually overridden to allow, e.g., serving Atom feeds as
  `application/atom+xml` instead of `application/xml` or `text/xml`.
  The file extension for `text/gemini` defaults to `gmi`, but this can
  be overrideen too.
* Support for temporary and permanent redirects, specified via regular
  expressions.
* Dynamic content via CGI and SCGI.
* Support for "certificate zones", where access to certain paths is
  restricted to clients providing TLS certificates whose SHA256
  fingerprints have been added to a list of approved fingerprints,
  analogous to SSH's `authorized_keys` file.
* The ability for users to override some configuration settings on a
  per-directory basis using `.molly` files, analogous to Apache's
  `.htaccess` files.

The follow features are planned for the future:

* Name-based virtual hosting

## System requirements

Molly Brown is known to run on:

* FreeBSD
* GNU/Linux
* OpenBSD
* 9Front

Please let us know if you get it to work on some other platform!

Molly Brown only has a single dependency beyond the Go standard
library, which is [this TOML parsing
library](https://github.com/BurntSushi/toml).

The OpenBSD implementation also uses the [golang.org/x/sys/unix
package](https://godoc.org/golang.org/x/sys/unix) to provide the
[pledge(2)](https://man.openbsd.org/pledge.2) and
[unveil(2)](https://man.openbsd.org/unveil.2) system calls to provide
additional security features.

## Installation

The easiest way for now to install Molly Brown is to use the standard
Golang tool `go` (note I said "easiest", not "easy" - this is still a
pretty clunky manual process, sorry).  Unfortunately, you have to do a
little bit of preparation for this to work (unless you're a Go
developer yourself in which case you surely already have this done)...

### Prepare your $GOPATH

1. Create an empty directory `~/go`.
2. Set the $GOPATH environment variable to `~/go`.

(you can in fact put your $GOPATH anywhere you like, but `~/go` is the
convention)

### Fetch and build Molly Brown

Run `go get tildegit.org/solderpunk/molly-brown`.  If everything goes
well, the end result of this will be that you'll have the Molly Brown
source code sitting in `~/go/src/tildegit.org/solderpunk/molly-brown`
and an executable binary sitting at `~/go/bin/molly-brown`.  If it
makes you happier or your life easier, you can copy that binary to
`/usr/sbin/` or anywhere else.

### Configuration

Molly Brown can run without a configuration file, in which case it
will use compiled-in default settings.  However, these settings are
oriented toward quick test runs with all files in the current
working directory.  For regular use, you will want to override these
defaults with more suitable settings from a config file.  An example
config file showing the syntax for all settings can be found in the
`~/go/src/tildegit.org/solderpunk/molly-brown/` directory with the
filename `example.conf`.  You can copy this file to `/etc/molly.conf`
and edit it to suit your environment.  All the options are explained
further below.  If you put your configuration file somewhere other
than `/etc/molly.conf`, you will need to use Molly Brown's `-c`
command line option to tell Molly Brown where to find it.

### Running

The `molly-brown` executable recognises the following command line
switches:

* `-c`: Used to specify a config file.
* `-C`: Used to specify a directory to chroot to (unix only).
* `-u`: Used to specify the name of an unprivileged user which
        Molly Brown should switch to running as if started as
        root or run as a setuid executable (unix only).
* `-v`: Print version number and exit.

Molly Brown does not handle details like daemonising itself, changing
the user it runs as, etc.  You will need to take care of these tasks
by, e.g. integrating Molly Brown with your operating system's init
system.  Some limited instructions on how to do this for common
systems follows.

#### Manual management

You can always use a tool like [daemon](`http://libslack.org/daemon/`)
to take care of daemonising the Molly Brown process, changing the user
it runs as, chrooting it to a particular location, etc.  You can call
`daemon` from `/etc/rc.local` (if your OS still supports it) to start
it on system boot.

#### Systemd

An example systemd unit file for Molly Brown, named 
`molly-brown.service.example`, can be found in the `contrib/init`
directory of the Molly Brown source directory.  After copying this
file to `/etc/systemd/system/molly-brown.service`
or `/usr/lib/systemd/system/molly-brown.service` (consult your
system's documentation for the appropriate choice) and making any
necessary changes for your environment, you can run the follow
commands as root to start Molly Brown and make sure it starts
automatically on system boot.

```sh
# systemctl daemon-reload
# systemctl enable molly-brown.service
# systemctl start molly-brown.service
```

#### OpenRC

An example OpenRC initscript for Molly Brown, named
`molly-brown.openrc.example`, can be found in the `contrib/init`
directory of the Molly Brown source directory.

More detailed instructions on OpenRC setup are welcome!

#### OpenBSD

An example OpenBSD initscript for Molly Brown, named
`molly-brown.openbsd.example`, can be found in the `contrib/init`
directory of the Molly Brown source directory. After copying this
file to `/etc/rc.d/mollybrownd`, you can add the `mollybrownd`
daemon to your system startup with `rcctl` or by manually adding
`mollybrownd` to your `/etc/rc.conf.local` configuration. The
following lines in `rc.conf.local` will autostart your
`mollybrownd` daemon as the user `username`:
```
mollybrownd_user=username
pkg_scripts=mollybrownd
```
Be sure that the user running your `mollybrownd` daemon has
read access to `/etc/molly.conf` and all of the files and
directories listed in `/etc/molly.conf`. That user will
also need write access to the configured log file locations.

You can start your `mollybrownd` daemon with `rcctl`:
```
rcctl start mollybrownd
```

#### FreeBSD

An example FreeBSD rc script is in
`contrib/init/molly-brown.freebsd.example`.

Copy rc script to `/etc/rc.d/molly`, and add `molly_enable="YES"`
to `/etc/rc.conf` to enable the service.

Make sure the `daemon` user has access to config locations in
`molly.conf` like `CertPath`, `KeyPath`, `DocBase`, etc.

Start `molly` with,

```
service molly start
```

## Configuration Options

The following sections detail all the options which can be set in
`/etc/molly.conf` or any other configuration file specified with the
`-c` option.

The format of the configuration file is
[TOML](https://github.com/toml-lang/toml), which bares some similarity
to the "INI" format.  Remember that you can check `example.conf` for
examples of the appropriate syntax.

### Basic options

* `Port`: The TCP port to listen for connections on (default value
  `1965`).
* `Hostname`: The hostname to respond to requests for (default value
  `localhost`).  Requests for URLs with other hosts will result in a
  status 53 (PROXY REQUEST REFUSED) response.
* `CertPath`: Path to TLS certificate in PEM format (default value
  `cert.pem`).
* `KeyPath`: Path to TLS private key in PEM format (default value
  `key.pem`).
* `DocBase`: Base directory for Gemini content (default value
  `/var/gemini/`).  Only world-readable files stored in or below this
  directory will be served by Molly Brown.
* `HomeDocBase`: Requests for paths beginning with `~/username/` will
  be looked up relative to `DocBase/HomeDocBase/username/` (default
  value `users`).  Note that Molly Brown does *not* look inside user's
  actual home directories like you may expect based on experience with
  other server software.  Of course, you can symlink
  `/var/gemini/users/gus/` to `/home/gus/public_gemini/` if you want.
* `AccessLog`: Path to access log file (default value `access.log`,
  i.e. in the current wrorking directory).  Note that all intermediate
  directories must exist, Molly Brown won't create them for you.  Set
  to `-` for logging to `stdout`, or to an empty string to disable
  access logging.
* `ErrorLog`: Path to error log file.  If set to an empty string (the
  default), Molly Brown will log errors to stderr (where they are
  easily captured by systemd or similar init systems).  If set to a
  file, note that all intermediate directories must exist, Molly Brown
  won't create them for you.
* `GeminiExt`: Files with this extension will be served with a MIME
  type of `text/gemini` (default value `gmi`).
* `MimeOverrides`: In this section of the config file, keys are path
  regexs and values are MIME types.  If the path of a file which is
  about to be served matches one the regexs, the corresponding MIME type
  will be used instead of one inferred from the filename extension.
* `DefaultLang`: If this option is set, it will be served as the
  `lang` parameter of the MIME type for all `text/gemini` content.
* `DefaultEncoding`: If this option is set, it will be served as the
  `charset` parameter of the MIME type for all `text/gemini` content.

### Directory listings

Molly Brown will automatically generate directory listings for
world-readable directories under `DocBase` which do not contain an
`index.gmi` file.  Only world-readable files and directories will be
listed.  If a world-readable file named `.mollyhead` is found in a
directory, it's contents will be inserted above the directory listing
instead of the default "Directory listing" title.

The following options allow users to configure various aspects of the
directory listing:

* `DirectoryListing` (boolean): if true, enable directory listing; if false,
  return 51 Not found (default value true)
* `DirectorySort`: A string specifying how to sort files in
  automatically generated directory listings.  Must be one of "Name",
  "Size" or "Time" (default value "Name").
* `DirectorySubdirsFirst` (boolean): if true, list subdirectories of
  the directory being listed before files.  Subdirs and files will be
  sorted within their respective categories according to
  `DirectorySort` (default value false).
* `DirectoryReverse` (boolean): if true, automatically generated
  directory listings will list files in descending order of whatever
  `DirectorySort` is set to (default value false).
* `DirectoryTitles` (boolean): if true, automatically generated
  directory listings will use the first top-level heading (i.e. line
  beginning with "# ") in files with an extension of `GeminiExt`
  instead of the filename (default value false).

### Redirects

* `TempRedirects`: In this section of the config file, keys are
  regular expressions which the server will attempt to match against
  the path component if incoming request URLs.  If a match is found,
  Molly Brown will serve a redirect to a new URL derived by replacing
  the path component with the value corresponding to the matched key.
  Within the replacement values, $1, $2, etc. will be replaced by the
  first, second, etc. submatch in the regular expression.  Named
  captures can also be used for more sophisticated redirect logic -
  see the documentation for the Go standard library's `regexp` package
  for full details.
* `PermRedirects`: As per `TempRedirects` above, but Molly Brown will
  use the 31 status code instead of 30.

### Dynamic content

Molly Brown supports dynamically generated content using an adaptation
of the CGI standard, and also the SCGI standard.

The `stdout` of CGI processes will be sent verbatim as the response to
the client, and CGI applications are responsible for generating their
own response headers.  CGI processes must terminate naturally within
10 seconds of being spawned to avoid being killed.  Details about the
request are available to CGI applications through environment
variables, generally following RFC 3875.  In particular, note that if
a request URL includes components after the path to an executable
(e.g. `cgi-bin/script.py/foo/bar/baz`) then the environment variable
`SCRIPT_PATH` will contain the part of the URL path mapping to the
executable (e.g. `/var/gemini/cgi-bin/scripty.py`) while the variable
`PATH_INFO` will contain the remainder (e.g. `foo/bar/baz`).

Molly Brown itself tries very hard to avoid being tricked into serving
content that isn't supposed to be served, but it is completely unable
to impose any control over what CGI processes can or can't go after
they are started!  Where possible, Molly Brown will use the operating
system's security features to reduce risk, but it is your
responsibility to understand what it can and cannot do and weigh the
risks accordingly:

When compiled on GNU/Linux with Go version 1.16 or later, or on any
other unix operating system with any version of Go, Molly Brown will
use the setuid() system call as follows.  When the compiled
`molly-brown` executable has its SETUID bit set, so that it starts
with the privileges of the user who owns the binary, it will change
the effective UID back to the real UID before it begins accepting
network connections.  This way, config files, log files and TLS keys
can be set readable by the user who owns the binary, but not readable
by the user who runs the binary.  CGI processes will then be unable to
read any of those sensitive files.  If the binary is not SETUID but is
run by the superuser/root, then Molly will change its UID to that of
the `nobody` user (or any other user specified with the `-u` option)
before accepting network connections, so CGI processes will again not
be able to read sensitive files.  Note that while these measures can
protect Molly's own sensitive files from CGI processes, CGI processes
may still be able to read other sensitive files anywhere else on the
system.  Consider chroot()-ing Molly Brown into a small corner of the
filesystem (see discussion of the `-C` option at the start of the
Running section) to reduce this risk.

When compiled on GNU/Linux with Go versions 1.15 or earlier, Molly
Brown is completley unable to reliably change its UID due to the way
early implementations of goroutines interacted with the setuid()
system call.  In this situation, Molly Brown will refuse to run as
superuser/root.  It will run as any other user, but CGI processes will
necessary run as the same user as the server and so unavoidably will
have access to sensitive files.  You should proceed with extreme
caution and only use carefully vetted CGI programs.  Consider using
systemd's ability to chroot a non-privileged process at the moment of
startup to at least confine the risk to Molly Brown's sensitive files
and not the entire system's.

Molly Brown will compile on non-unix operating systems and is known to
run on Plan9, for example, but no special security measures are taken
on these non-unix platforms.  It is your responsibility to understand
the risks.  If you are aware of security measures for these systems
which can be implemented in Go, patches are extremely welcome.

SCGI applications must be started separately (i.e. Molly Brown expects
them to already be running and will not attempt to start them itself),
and as such they can run e.g. as their own user and/or chrooted into
their own filesystem, meaning that they are less of a security threat
than CGI applications (in addition to avoiding the overhead of process
startup, database connection etc. on each request).

* `CGIPaths`: A list of filesystem paths, within which
  world-executable files will be run as CGI processes.  The paths act
  as prefixes, i.e. if `/var/gemini/cgi-bin` is listed then
  `/var/gemini/cgi-bin/script.py` and
  `/var/gemini/cgi-bin/subdir/subsubdir/script.py` will both be run.
  The paths may include basic wildcard characters, where `?` matches a
  single non-separator character and `*` matches a sequence of them -
  if wildcards are used, the path should *not* end in a trailing slash
  - this appears to be a peculiarity of the Go standard library's
  `filepath.Glob` function.  Any non-absolute paths will be resolved
  relative to `DocBase`.
* `SCGIPaths`: In this section of the config file, keys are URL path
  prefixes and values are filesystem paths to unix domain sockets.
  Any request for a URL whose path begins with one of the specified
  prefixes will cause an SCGI request to be sent to the corresponding
  domain socket.  Anything sent back from a program listening on the
  other end of the socket will be sent as the response to the client.
  SCGI applications are responsible for generating their own response
  headers.

### TLS options

* `AllowTLS12` (boolean): if true, Molly Brown will accept connections
  from clients using TLS version 1.2 or later (1.2 is the bare minimum
  allowed by the Gemini spec).  If set to false, Molly Brown will
  instead require TLS version 1.3 or later - 1.2 to 1.3 was a big
  change and drastic simplification of the TLS spec which discarded a
  wide range of old and insecure configurations.  (default value `true`)

#### Certificate zones

Molly Brown allows you to use client certificates to restrict access
to certain resources (which may be static or dynamic).  The overall
workflow is highly reminiscent of OpenSSH's `authorized_keys`
facility.

* `CertificateZones`: In this section of the config file, keys are
  path regexs and values are lists of hex-encoded SHA256 fingerprints
  of client certificates.  Any requests whose path matches one of the
  regexs will only be served as normal if the request is made with a
  client certificate whose fingerprint is in the corresponding list.
  Requests made without a certificate will cause a response with a
  status code of 60.  Requests made with a certificate not in the list
  will cause a response with a status code of 60.

## .molly files

In order to allow users of shared-hosting who do not have access to
the main Molly Brown configuration file to customise some aspects of
their Gemini site, Molly Brown features functionality much like
Apache's `.htaccess` files.  If the main configuration file contains
the line `ReadMollyFiles = true`, then each directory in the path to a
resource will be checked for a file named `.molly`.  These files
should be in exactly the same format as the main configuration file,
an their contents will override (some) settings from the main file.
Each `.molly` file will override settings specified in `.molly` files
from higher directories.

E.g. when handling a request which maps to
`/var/gemini/foo/bar/baz/file.gmi`, then:

* The settings in the file `/var/gemini/.molly`, if it exists, will
  override those in `/etc/molly.conf`.
* The settings in the file `/var/gemini/foo/.molly`, if it exists,
  will override those in `/var/gemini/.molly`.
* The settings in the file `/var/gemini/foo/bar/.molly`, if it exists,
  will override those in `/var/gemini/foo/.molly`.
* The settings in the file `/var/gemini/foo/bar/baz/.molly`, if it
  exists, will override those in `/var/gemini/foo/bar/.molly`.

Only the following settings can be overriden by `.molly` files.  Any
other settings in `.molly` files will be ignored:

* `CertificateZones`
* `DefaultLang`
* `DefaultEncoding`
* `DirectorySort`
* `DirectorySubdirsFirst`
* `DirectoryReverse`
* `DirectoryTitles`
* `GeminiExt`
* `MimeOverrides`
* `PermRedirects`
* `TempRedirects`

## Trivia

Margaret Brown was an American philanthropist and socialite who
survived the sinking of the RMS Titanic, leading to a Broadway musical
and later a film about her life being titled "The Unsinkable Molly
Brown".  The "unsinkable" moniker inspired NASA astronaut Gus Grissom
to name the Gemini 3 capsule he commanded "Molly Brown" - Grissom had
almost drowned a few years earlier when his Mercury 4 capsule "Liberty
Bell" sank after splashdown.
