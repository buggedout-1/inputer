package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version info
const version = "2.0.0"

// Config holds all configuration options
type Config struct {
	ListFile    string
	OutputFile  string
	Concurrency int
	Timeout     int
	RateLimit   int
	Retries     int
	UserAgent   string
	IncludePOST bool
	Verbose     bool
	Silent      bool
	NoColor     bool
	FollowRedirects bool
	MaxRedirects    int
	Delay       int
	ProxyURL    string
	Insecure    bool
}

// Stats for tracking progress
type Stats struct {
	Total     int64
	Processed int64
	Success   int64
	Failed    int64
	Found     int64
}

// Colors for terminal output
type Colors struct {
	Reset   string
	Red     string
	Green   string
	Yellow  string
	Blue    string
	Magenta string
	Cyan    string
	Gray    string
}

var colors = Colors{
	Reset:   "\033[0m",
	Red:     "\033[31m",
	Green:   "\033[32m",
	Yellow:  "\033[33m",
	Blue:    "\033[34m",
	Magenta: "\033[35m",
	Cyan:    "\033[36m",
	Gray:    "\033[90m",
}

func main() {
	config := parseFlags()

	if config.NoColor {
		colors = Colors{}
	}

	if !config.Silent {
		printBanner()
	}

	// Validate input
	if config.ListFile == "" {
		printError("No input file specified. Use -l <file>")
		printUsage()
		os.Exit(1)
	}

	// Read URLs
	urls, err := readURLsFromFile(config.ListFile)
	if err != nil {
		printError(fmt.Sprintf("Failed to read file: %v", err))
		os.Exit(1)
	}

	if len(urls) == 0 {
		printError("No URLs found in input file")
		os.Exit(1)
	}

	// Setup output
	var output io.Writer = os.Stdout
	var outputFile *os.File
	if config.OutputFile != "" {
		outputFile, err = os.Create(config.OutputFile)
		if err != nil {
			printError(fmt.Sprintf("Failed to create output file: %v", err))
			os.Exit(1)
		}
		defer outputFile.Close()
		output = outputFile
	}

	// Initialize stats
	stats := &Stats{Total: int64(len(urls))}

	if !config.Silent {
		printInfo(fmt.Sprintf("Loaded %d URLs", len(urls)))
		printInfo(fmt.Sprintf("Concurrency: %d | Timeout: %ds | Retries: %d", config.Concurrency, config.Timeout, config.Retries))
		if config.RateLimit > 0 {
			printInfo(fmt.Sprintf("Rate limit: %d requests/second", config.RateLimit))
		}
		fmt.Println()
	}

	// Process URLs
	startTime := time.Now()
	processURLs(config, urls, output, stats)
	duration := time.Since(startTime)

	// Print summary
	if !config.Silent {
		fmt.Println()
		printSummary(stats, duration)
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.ListFile, "l", "", "File containing list of URLs to scan")
	flag.StringVar(&config.OutputFile, "o", "", "Output file (default: stdout)")
	flag.IntVar(&config.Concurrency, "c", 10, "Number of concurrent workers")
	flag.IntVar(&config.Timeout, "t", 10, "HTTP timeout in seconds")
	flag.IntVar(&config.RateLimit, "r", 0, "Rate limit (requests per second, 0 = unlimited)")
	flag.IntVar(&config.Retries, "retries", 2, "Number of retries for failed requests")
	flag.StringVar(&config.UserAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "User-Agent header")
	flag.BoolVar(&config.IncludePOST, "post", false, "Include POST forms in output")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output (show errors)")
	flag.BoolVar(&config.Silent, "s", false, "Silent mode (only output results)")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&config.FollowRedirects, "follow", true, "Follow redirects")
	flag.IntVar(&config.MaxRedirects, "max-redirects", 5, "Maximum redirects to follow")
	flag.IntVar(&config.Delay, "delay", 0, "Delay between requests in milliseconds")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	flag.BoolVar(&config.Insecure, "insecure", false, "Skip TLS certificate verification")

	showVersion := flag.Bool("version", false, "Show version")
	showHelp := flag.Bool("h", false, "Show help")

	flag.Parse()

	if *showVersion {
		fmt.Printf("inputer v%s\n", version)
		os.Exit(0)
	}

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	return config
}

func printBanner() {
	banner := `
  ___                   _
 |_ _|_ __  _ __  _   _| |_ ___ _ __
  | || '_ \| '_ \| | | | __/ _ \ '__|
  | || | | | |_) | |_| | ||  __/ |
 |___|_| |_| .__/ \__,_|\__\___|_|
           |_|        v%s
`
	fmt.Printf(colors.Cyan+banner+colors.Reset, version)
	fmt.Println()
}

func printUsage() {
	fmt.Println(`
Usage: inputer -l <urls.txt> [options]

Options:
  -l string          File containing list of URLs to scan (required)
  -o string          Output file (default: stdout)
  -c int             Number of concurrent workers (default: 10)
  -t int             HTTP timeout in seconds (default: 10)
  -r int             Rate limit - requests per second (default: 0 = unlimited)
  -retries int       Number of retries for failed requests (default: 2)
  -ua string         Custom User-Agent header
  -post              Include POST forms in output
  -v                 Verbose output (show errors and progress)
  -s                 Silent mode (only output results)
  -no-color          Disable colored output
  -follow            Follow redirects (default: true)
  -max-redirects int Maximum redirects to follow (default: 5)
  -delay int         Delay between requests in milliseconds
  -proxy string      Proxy URL (e.g., http://127.0.0.1:8080)
  -insecure          Skip TLS certificate verification
  -version           Show version
  -h                 Show this help

Examples:
  inputer -l urls.txt
  inputer -l urls.txt -o results.txt -c 50 -t 15
  inputer -l urls.txt -r 100 -v
  inputer -l urls.txt -post -proxy http://127.0.0.1:8080
  cat urls.txt | inputer -l /dev/stdin
`)
}

func printInfo(msg string) {
	fmt.Printf("%s[*]%s %s\n", colors.Blue, colors.Reset, msg)
}

func printSuccess(msg string) {
	fmt.Printf("%s[+]%s %s\n", colors.Green, colors.Reset, msg)
}

func printError(msg string) {
	fmt.Fprintf(os.Stderr, "%s[!]%s %s\n", colors.Red, colors.Reset, msg)
}

func printWarning(msg string) {
	fmt.Printf("%s[~]%s %s\n", colors.Yellow, colors.Reset, msg)
}

func printVerbose(config *Config, msg string) {
	if config.Verbose {
		fmt.Printf("%s[-]%s %s\n", colors.Gray, colors.Reset, msg)
	}
}

func printSummary(stats *Stats, duration time.Duration) {
	fmt.Println()
	fmt.Printf("%s╔══════════════════════════════════════╗%s\n", colors.Cyan, colors.Reset)
	fmt.Printf("%s║           SCAN COMPLETE              ║%s\n", colors.Cyan, colors.Reset)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n", colors.Cyan, colors.Reset)
	fmt.Printf("  Total URLs:     %d\n", stats.Total)
	fmt.Printf("  Successful:     %s%d%s\n", colors.Green, stats.Success, colors.Reset)
	fmt.Printf("  Failed:         %s%d%s\n", colors.Red, stats.Failed, colors.Reset)
	fmt.Printf("  Forms Found:    %s%d%s\n", colors.Yellow, stats.Found, colors.Reset)
	fmt.Printf("  Duration:       %s\n", duration.Round(time.Second))
	fmt.Printf("  Speed:          %.1f URLs/sec\n", float64(stats.Total)/duration.Seconds())
}

func newHTTPClient(config *Config) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        config.Concurrency,
		MaxIdleConnsPerHost: config.Concurrency,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
		},
	}

	// Setup proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	if config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}

		// Normalize and deduplicate
		normalized := normalizeURL(u)
		if _, exists := seen[normalized]; !exists {
			seen[normalized] = struct{}{}
			urls = append(urls, normalized)
		}
	}

	return urls, scanner.Err()
}

func normalizeURL(rawURL string) string {
	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Normalize path
	if u.Path == "" {
		u.Path = "/"
	}

	return u.String()
}

func smartNormalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if strings.HasSuffix(u.Path, "/") || path.Ext(u.Path) != "" || isAPIPath(u.Path) {
		return u.String()
	}
	u.Path += "/"
	return u.String()
}

func isAPIPath(p string) bool {
	apiKeywords := []string{
		"api", "ajax", "rest", "rpc", "graphql", "soap",
		"json", "xml", "balance", "promotion", "service",
		"endpoint", "v1", "v2", "v3",
	}
	p = strings.ToLower(p)
	for _, keyword := range apiKeywords {
		if strings.Contains(p, keyword) {
			return true
		}
	}
	return false
}

func processURLs(config *Config, urls []string, output io.Writer, stats *Stats) {
	client := newHTTPClient(config)

	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Concurrency)
	var mu sync.Mutex

	// Rate limiter
	var rateLimiter <-chan time.Time
	if config.RateLimit > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(config.RateLimit))
	}

	// Result deduplication
	uniqueResults := make(map[string]struct{})

	// Progress ticker - only for larger scans (10+ URLs)
	var progressDone chan struct{}
	var progressWg sync.WaitGroup
	showProgress := !config.Silent && !config.Verbose && len(urls) >= 10
	if showProgress {
		progressDone = make(chan struct{})
		progressWg.Add(1)
		go func() {
			defer progressWg.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					mu.Lock()
					fmt.Fprintf(os.Stderr, "\r%s[*]%s Progress: %d/%d (%.1f%%) | Success: %d | Failed: %d | Forms Found: %d    ",
						colors.Blue, colors.Reset,
						atomic.LoadInt64(&stats.Processed), stats.Total,
						float64(atomic.LoadInt64(&stats.Processed))/float64(stats.Total)*100,
						atomic.LoadInt64(&stats.Success),
						atomic.LoadInt64(&stats.Failed),
						atomic.LoadInt64(&stats.Found))
					mu.Unlock()
				case <-progressDone:
					// Clear progress line before exiting
					fmt.Fprintf(os.Stderr, "\r%s\n", strings.Repeat(" ", 100))
					return
				}
			}
		}()
	}

	for _, rawURL := range urls {
		wg.Add(1)
		sem <- struct{}{}

		if rateLimiter != nil {
			<-rateLimiter
		}

		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Delay if configured
			if config.Delay > 0 {
				time.Sleep(time.Duration(config.Delay) * time.Millisecond)
			}

			normalizedURL := smartNormalizeURL(rawURL)
			results, err := processURL(config, client, normalizedURL)

			atomic.AddInt64(&stats.Processed, 1)

			if err != nil {
				atomic.AddInt64(&stats.Failed, 1)
				printVerbose(config, fmt.Sprintf("Error %s: %v", rawURL, err))
				return
			}

			atomic.AddInt64(&stats.Success, 1)

			// Output results
			mu.Lock()
			for _, result := range results {
				if _, exists := uniqueResults[result]; !exists {
					uniqueResults[result] = struct{}{}
					atomic.AddInt64(&stats.Found, 1)
					// Clear progress line before printing result
					if showProgress {
						fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 100))
					}
					fmt.Fprintln(output, result)
				}
			}
			mu.Unlock()
		}(rawURL)
	}

	wg.Wait()

	if progressDone != nil {
		close(progressDone)
		progressWg.Wait() // Wait for progress goroutine to finish and clear line
	}
}

func processURL(config *Config, client *http.Client, rawURL string) ([]string, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	var resp *http.Response
	var lastErr error

	// Retry logic
	for attempt := 0; attempt <= config.Retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*500) * time.Millisecond)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}

		req.Header.Set("User-Agent", config.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Connection", "keep-alive")

		resp, err = client.Do(req)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}

		break
	}

	if resp == nil {
		return nil, lastErr
	}
	defer resp.Body.Close()

	// Update base URL if redirected
	finalURL := resp.Request.URL.String()
	if finalURL != rawURL {
		baseURL, err = url.Parse(finalURL)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect URL: %v", err)
		}
	}

	// Check status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml") {
		return nil, fmt.Errorf("not HTML content: %s", contentType)
	}

	// Limit body size to prevent memory issues
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	// Parse HTML and find forms
	var results []string
	forms := findForms(string(body), config.IncludePOST)

	for _, form := range forms {
		if targetURL := buildTargetURL(baseURL, form); targetURL != "" {
			results = append(results, targetURL)
		}
	}

	return results, nil
}

type formData struct {
	action string
	method string
	inputs map[string]string
}

var (
	formRegex     = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	actionRegex   = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	methodRegex   = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
	inputRegex    = regexp.MustCompile(`(?i)<input[^>]*>`)
	selectRegex   = regexp.MustCompile(`(?i)<select[^>]*name\s*=\s*["']([^"']*)["'][^>]*>`)
	textareaRegex = regexp.MustCompile(`(?i)<textarea[^>]*name\s*=\s*["']([^"']*)["'][^>]*>`)
	nameRegex     = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']*)["']`)
	valueRegex    = regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	typeRegex     = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']*)["']`)
	templateRegex = regexp.MustCompile(`\{\{.*?\}\}|\$\{.*?\}|<%.*?%>`)

	// Regex to find URL query parameters in page content (e.g., ?p1=...&p2=...)
	urlParamHintRegex = regexp.MustCompile(`\?([a-zA-Z_][a-zA-Z0-9_]*(?:=[^&\s<>"']*)?(?:&[a-zA-Z_][a-zA-Z0-9_]*(?:=[^&\s<>"']*)?)*)`)
	// Regex to find standalone inputs outside forms
	standaloneInputRegex = regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
)

func findForms(html string, includePOST bool) []formData {
	var forms []formData
	formInputNames := make(map[string]struct{}) // Track inputs already in forms

	// First, find all forms and their inputs
	formMatches := formRegex.FindAllStringSubmatch(html, -1)
	for _, formMatch := range formMatches {
		if len(formMatch) < 2 {
			continue
		}

		fullForm := formMatch[0]
		formContent := formMatch[1]

		fd := formData{
			method: "get",
			inputs: make(map[string]string),
		}

		// Extract action
		if actionMatch := actionRegex.FindStringSubmatch(fullForm); len(actionMatch) > 1 {
			fd.action = strings.TrimSpace(actionMatch[1])
		}

		// Extract method
		if methodMatch := methodRegex.FindStringSubmatch(fullForm); len(methodMatch) > 1 {
			fd.method = strings.ToLower(strings.TrimSpace(methodMatch[1]))
		}

		// Filter by method
		if fd.method != "get" && !includePOST {
			continue
		}

		// Extract inputs
		inputMatches := inputRegex.FindAllString(formContent, -1)
		for _, input := range inputMatches {
			name := ""
			value := ""
			inputType := "text"

			if nameMatch := nameRegex.FindStringSubmatch(input); len(nameMatch) > 1 {
				name = strings.TrimSpace(nameMatch[1])
			}
			if valueMatch := valueRegex.FindStringSubmatch(input); len(valueMatch) > 1 {
				value = strings.TrimSpace(valueMatch[1])
			}
			if typeMatch := typeRegex.FindStringSubmatch(input); len(typeMatch) > 1 {
				inputType = strings.ToLower(strings.TrimSpace(typeMatch[1]))
			}

			// Skip certain input types
			if inputType == "submit" || inputType == "button" || inputType == "image" || inputType == "reset" {
				continue
			}

			if name != "" {
				formInputNames[name] = struct{}{}
				if value == "" || templateRegex.MatchString(value) {
					value = "FUZZ"
				}
				fd.inputs[name] = value
			}
		}

		// Extract select elements
		selectMatches := selectRegex.FindAllStringSubmatch(formContent, -1)
		for _, match := range selectMatches {
			if len(match) > 1 {
				name := strings.TrimSpace(match[1])
				if name != "" {
					formInputNames[name] = struct{}{}
					fd.inputs[name] = "FUZZ"
				}
			}
		}

		// Extract textarea elements
		textareaMatches := textareaRegex.FindAllStringSubmatch(formContent, -1)
		for _, match := range textareaMatches {
			if len(match) > 1 {
				name := strings.TrimSpace(match[1])
				if name != "" {
					formInputNames[name] = struct{}{}
					fd.inputs[name] = "FUZZ"
				}
			}
		}

		if len(fd.inputs) > 0 {
			forms = append(forms, fd)
		}
	}

	// Find standalone inputs (outside forms)
	standaloneInputs := make(map[string]string)
	allInputMatches := inputRegex.FindAllString(html, -1)
	for _, input := range allInputMatches {
		name := ""
		value := ""
		inputType := "text"

		if nameMatch := nameRegex.FindStringSubmatch(input); len(nameMatch) > 1 {
			name = strings.TrimSpace(nameMatch[1])
		}
		if valueMatch := valueRegex.FindStringSubmatch(input); len(valueMatch) > 1 {
			value = strings.TrimSpace(valueMatch[1])
		}
		if typeMatch := typeRegex.FindStringSubmatch(input); len(typeMatch) > 1 {
			inputType = strings.ToLower(strings.TrimSpace(typeMatch[1]))
		}

		// Skip certain input types
		if inputType == "submit" || inputType == "button" || inputType == "image" || inputType == "reset" {
			continue
		}

		// Only add if not already in a form
		if name != "" {
			if _, inForm := formInputNames[name]; !inForm {
				if value == "" || templateRegex.MatchString(value) {
					value = "FUZZ"
				}
				standaloneInputs[name] = value
			}
		}
	}

	// Add standalone inputs as a virtual form
	if len(standaloneInputs) > 0 {
		forms = append(forms, formData{
			action: "",
			method: "get",
			inputs: standaloneInputs,
		})
	}

	// Find URL parameter hints in the page content (e.g., ?p1=...&p2=...)
	// Only use if NO forms/inputs were found at all
	if len(forms) == 0 {
		paramHints := findURLParamHints(html)
		if len(paramHints) > 0 {
			forms = append(forms, formData{
				action: "",
				method: "get",
				inputs: paramHints,
			})
		}
	}

	return forms
}

// findURLParamHints extracts parameter names from URL patterns in the page
func findURLParamHints(html string) map[string]string {
	params := make(map[string]string)

	matches := urlParamHintRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		queryPart := match[1]
		pairs := strings.Split(queryPart, "&")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) > 0 {
				paramName := strings.TrimSpace(parts[0])
				if paramName != "" && isValidParamName(paramName) {
					params[paramName] = "FUZZ"
				}
			}
		}
	}

	return params
}

// isValidParamName checks if a parameter name looks valid
func isValidParamName(name string) bool {
	if len(name) == 0 || len(name) > 50 {
		return false
	}
	// Must start with letter or underscore
	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}
	// Rest must be alphanumeric or underscore
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func buildTargetURL(baseURL *url.URL, form formData) string {
	targetURL := resolveFormAction(baseURL, form.action)
	if targetURL == nil {
		return ""
	}

	params := url.Values{}
	for name, value := range form.inputs {
		params.Add(name, value)
	}

	if form.method == "get" {
		targetURL.RawQuery = params.Encode()
		return targetURL.String()
	}

	// For POST forms, return URL with method indicator
	return fmt.Sprintf("[POST] %s (params: %s)", targetURL.String(), params.Encode())
}

func resolveFormAction(baseURL *url.URL, action string) *url.URL {
	if action == "" || action == "#" {
		result := *baseURL
		result.Fragment = ""
		return &result
	}

	if strings.HasPrefix(action, "#") {
		result := *baseURL
		result.Fragment = ""
		return &result
	}

	// Handle javascript: actions
	if strings.HasPrefix(strings.ToLower(action), "javascript:") {
		result := *baseURL
		result.Fragment = ""
		return &result
	}

	actionURL, err := url.Parse(action)
	if err != nil {
		result := *baseURL
		result.Fragment = ""
		return &result
	}

	if actionURL.IsAbs() {
		actionURL.Fragment = ""
		return actionURL
	}

	resolvedURL := *baseURL
	if strings.HasPrefix(action, "/") {
		resolvedURL.Path = actionURL.Path
	} else if strings.HasPrefix(action, "//") {
		// Protocol-relative URL
		resolvedURL.Host = actionURL.Host
		resolvedURL.Path = actionURL.Path
	} else {
		resolvedURL.Path = path.Join(path.Dir(baseURL.Path), actionURL.Path)
	}
	resolvedURL.RawQuery = actionURL.RawQuery
	resolvedURL.Fragment = ""

	return &resolvedURL
}
