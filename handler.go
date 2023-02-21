package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Utility function below borrowed from
// https://stackoverflow.com/questions/28024731/check-if-given-path-is-a-subdirectory-of-another-in-golang
func isSubdir(subdir, superdir string) (bool, error) {
    up := ".." + string(os.PathSeparator)

    // path-comparisons using filepath.Abs don't work reliably according to docs (no unique representation).
    rel, err := filepath.Rel(superdir, subdir)
    if err != nil {
        return false, err
    }
    if !strings.HasPrefix(rel, up) && rel != ".." {
        return true, nil
    }
    return false, nil
}

func handleGeminiRequest(conn net.Conn, config Config, accessLogEntries chan LogEntry, wg *sync.WaitGroup) {
	defer conn.Close()
	defer wg.Done()
	var tlsConn (*tls.Conn) = conn.(*tls.Conn)
	var logEntry LogEntry
	logEntry.Time = time.Now()
	logEntry.RemoteAddr = conn.RemoteAddr()
	logEntry.RequestURL = "-"
	logEntry.Status = 0
	if accessLogEntries != nil {
		defer func() { accessLogEntries <- logEntry }()
	}

	// Read request
	URL, err := readRequest(conn, &logEntry)
	if err != nil {
		return
	}

	// Enforce client certificate validity
	clientCerts := tlsConn.ConnectionState().PeerCertificates
	enforceCertificateValidity(clientCerts, conn, &logEntry)
	if logEntry.Status != 0 {
		return
	}

	// Reject non-gemini schemes
	if URL.Scheme != "gemini" {
		conn.Write([]byte("53 No proxying to non-Gemini content!\r\n"))
		logEntry.Status = 53
		return
	}

	// Reject requests for content from other servers
	requestedHost := strings.ToLower(URL.Hostname())
	// Trim trailing . from FQDNs
	if strings.HasSuffix(requestedHost, ".") {
		requestedHost = requestedHost[:len(requestedHost)-1]
	}
	if requestedHost != config.Hostname || (URL.Port() != "" && URL.Port() != strconv.Itoa(config.Port)) {
		conn.Write([]byte("53 No proxying to other hosts or ports!\r\n"))
		logEntry.Status = 53
		return
	}

	// Fail if there are dots in the path
	if strings.Contains(URL.Path, "..") {
		conn.Write([]byte("50 Your directory traversal technique has been defeated!\r\n"))
		logEntry.Status = 50
		return
	}

	// Resolve URI path to actual filesystem path, including following symlinks
	raw_path := resolvePath(URL.Path, config)
	path, err := filepath.EvalSymlinks(raw_path)
	if err!= nil {
		log.Println("Error evaluating path " + raw_path + " for symlinks: " + err.Error())
		conn.Write([]byte("51 Not found!\r\n"))
		logEntry.Status = 51
	}

	// If symbolic links have been used to escape the intended document directory,
	// deny all knowledge
	isSub, err := isSubdir(path, config.DocBase)
	if err != nil {
		log.Println("Error testing whether path " + path + " is below DocBase: " + err.Error())
	}
	if !isSub {
		log.Println("Refusing to follow simlink from " + raw_path + " outside of DocBase!")
	}
	if err != nil || !isSub {
		conn.Write([]byte("51 Not found!\r\n"))
		logEntry.Status = 51
		return
	}

	// Paranoid security measures:
	// Fail ASAP if the URL has mapped to a sensitive file
	if path == config.CertPath || path == config.KeyPath || path == config.AccessLog || path == config.ErrorLog || filepath.Base(path) == ".molly" {
		conn.Write([]byte("51 Not found!\r\n"))
		logEntry.Status = 51
		return
	}

	// Read Molly files
	if config.ReadMollyFiles {
		parseMollyFiles(path, &config)
	}

	// Check whether this URL is in a certificate zone
	handleCertificateZones(URL, clientCerts, config, conn, &logEntry)
	if logEntry.Status != 0 {
		return
	}

	// Check for redirects
	handleRedirects(URL, config, conn, &logEntry)
	if logEntry.Status != 0 {
		return
	}

	// Check whether this URL is mapped to an SCGI app
	for scgiPath, scgiSocket := range config.SCGIPaths {
		if strings.HasPrefix(URL.Path, scgiPath) {
			handleSCGI(URL, scgiPath, scgiSocket, config, &logEntry, conn)
			return
		}
	}

	// Check whether this URL is in a configured CGI path
	for _, cgiPath := range config.CGIPaths {
		if strings.HasPrefix(path, cgiPath) {
			handleCGI(config, path, cgiPath, URL, &logEntry, conn)
			if logEntry.Status != 0 {
				return
			}
		}
	}

	// Fail if file does not exist or perms aren't right
	info, err := os.Stat(path)
	if os.IsNotExist(err) || os.IsPermission(err) {
		conn.Write([]byte("51 Not found!\r\n"))
		logEntry.Status = 51
		return
	} else if err != nil {
		log.Println("Error getting info for file " + path + ": " + err.Error())
		conn.Write([]byte("40 Temporary failure!\r\n"))
		logEntry.Status = 40
		return
	} else if uint64(info.Mode().Perm())&0444 != 0444 {
		conn.Write([]byte("51 Not found!\r\n"))
		logEntry.Status = 51
		return
	}

	// Finally, serve the file or directory
	if info.IsDir() {
		serveDirectory(URL, path, &logEntry, conn, config)
	} else {
		serveFile(path, &logEntry, conn, config)
	}
}

func readRequest(conn net.Conn, logEntry *LogEntry) (*url.URL, error) {
	reader := bufio.NewReaderSize(conn, 1024)
	request, overflow, err := reader.ReadLine()
	if overflow {
		conn.Write([]byte("59 Request too long!\r\n"))
		logEntry.Status = 59
		return nil, errors.New("Request too long")
	} else if err != nil {
		log.Println("Error reading request from " + conn.RemoteAddr().String() + ": " + err.Error())
		conn.Write([]byte("40 Unknown error reading request!\r\n"))
		logEntry.Status = 40
		return nil, errors.New("Error reading request")
	}

	// Parse request as URL
	URL, err := url.Parse(string(request))
	if err != nil {
		log.Println("Error parsing request URL " + string(request) + ": " + err.Error())
		conn.Write([]byte("59 Error parsing URL!\r\n"))
		logEntry.Status = 59
		return nil, errors.New("Bad URL in request")
	}
	logEntry.RequestURL = URL.String()

	// Set implicit scheme
	if URL.Scheme == "" {
		URL.Scheme = "gemini"
	}

	return URL, nil
}

func resolvePath(path string, config Config) string {
	// Handle tildes
	if strings.HasPrefix(path, "/~") {
		bits := strings.Split(path, "/")
		username := bits[1][1:]
		new_prefix := filepath.Join(config.DocBase, config.HomeDocBase, username)
		path = strings.Replace(path, bits[1], new_prefix, 1)
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(config.DocBase, path)
	}
	return path
}

func handleRedirects(URL *url.URL, config Config, conn net.Conn, logEntry *LogEntry) {
	handleRedirectsInner(URL, config.TempRedirects, 30, conn, logEntry)
	handleRedirectsInner(URL, config.PermRedirects, 31, conn, logEntry)
}

func handleRedirectsInner(URL *url.URL, redirects map[string]string, status int, conn net.Conn, logEntry *LogEntry) {
	strStatus := strconv.Itoa(status)
	for src, dst := range redirects {
		compiled, err := regexp.Compile(src)
		if err != nil {
			log.Println("Error compiling redirect regexp " + src + ": " + err.Error())
			continue
		}
		if compiled.MatchString(URL.Path) {
			new_target := compiled.ReplaceAllString(URL.Path, dst)
			if !strings.HasPrefix(new_target, "gemini://") {
				URL.Path = new_target
				new_target = URL.String()
			}
			conn.Write([]byte(strStatus + " " + new_target + "\r\n"))
			logEntry.Status = status
			return
		}
	}
}

func serveDirectory(URL *url.URL, path string, logEntry *LogEntry, conn net.Conn, config Config) {
	// Redirect to add trailing slash if missing
	// (otherwise relative links don't work properly)
	if !strings.HasSuffix(URL.Path, "/") {
		URL.Path += "/"
		conn.Write([]byte(fmt.Sprintf("31 %s\r\n", URL.String())))
		logEntry.Status = 31
		return
	}
	// Check for index.gmi if path is a directory
	index_path := filepath.Join(path, "index."+config.GeminiExt)
	index_info, err := os.Stat(index_path)
	if err == nil && uint64(index_info.Mode().Perm())&0444 == 0444 {
		serveFile(index_path, logEntry, conn, config)
		// Serve a generated listing
	} else {
		listing, err := generateDirectoryListing(URL, path, config)
		if err != nil {
			log.Println("Error generating listing for directory " + path + ": " + err.Error())
			conn.Write([]byte("40 Server error!\r\n"))
			logEntry.Status = 40
			return
		}
		conn.Write([]byte("20 text/gemini\r\n"))
		logEntry.Status = 20
		conn.Write([]byte(listing))
	}
}

func serveFile(path string, logEntry *LogEntry, conn net.Conn, config Config) {
	// Get MIME type of files
	ext := filepath.Ext(path)
	var mimeType string
	if ext == "."+config.GeminiExt {
		mimeType = "text/gemini"
	} else {
		mimeType = mime.TypeByExtension(ext)
	}

	// Override extension-based MIME type
	for pathRegex, newType := range config.MimeOverrides {
		overridden, err := regexp.Match(pathRegex, []byte(path))
		if err == nil && overridden {
			mimeType = newType
		}
	}

	// Try to open the file
	f, err := os.Open(path)
	if err != nil {
		log.Println("Error reading file " + path + ": " + err.Error())
		conn.Write([]byte("50 Error!\r\n"))
		logEntry.Status = 50
		return
	}
	defer f.Close()

	// If the file extension wasn't recognised, or there's not one, use bytes
	// from the now open file to sniff!
	if mimeType == "" {
		buffer := make([]byte, 512)
		n, err := f.Read(buffer)
		if err == nil {
			_, err = f.Seek(0, 0)
		}
		if err != nil {
			log.Println("Error peeking into file " + path + ": " + err.Error())
			conn.Write([]byte("50 Error!\r\n"))
			logEntry.Status = 50
			return
		}
		mimeType = http.DetectContentType(buffer[0:n])
	}

	// Add charset parameter
	if strings.HasPrefix(mimeType, "text/gemini") && config.DefaultEncoding != "" {
		mimeType += "; charset=" + config.DefaultEncoding
	}
	// Add lang parameter
	if strings.HasPrefix(mimeType, "text/gemini") && config.DefaultLang != "" {
		mimeType += "; lang=" + config.DefaultLang
	}

	conn.Write([]byte(fmt.Sprintf("20 %s\r\n", mimeType)))
	io.Copy(conn, f)
	logEntry.Status = 20
}
