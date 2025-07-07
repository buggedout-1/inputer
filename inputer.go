package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

func main() {
	listFile := flag.String("l", "", "File containing list of URLs to scan")
	flag.Parse()

	if *listFile == "" {
		fmt.Println("Usage: go run tool.go -l urls.txt")
		os.Exit(1)
	}

	urls, err := readURLsFromFile(*listFile)
	if err != nil {
		os.Exit(1) // silently fail if file error
	}

	uniqueURLs := make(map[string]struct{})
	client := newHTTPClient()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // limit to 10 concurrent workers
	var mu sync.Mutex

	for _, rawURL := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			normalizedURL := smartNormalizeURL(rawURL)
			for _, foundURL := range processURL(client, normalizedURL) {
				mu.Lock()
				if _, exists := uniqueURLs[foundURL]; !exists {
					uniqueURLs[foundURL] = struct{}{}
					fmt.Println(foundURL)
				}
				mu.Unlock()
			}
		}(rawURL)
	}
	wg.Wait()
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

func isAPIPath(path string) bool {
	apiKeywords := []string{
		"api", "ajax", "rest", "rpc", "graphql", "soap",
		"json", "xml", "balance", "promotion", "service",
	}
	path = strings.ToLower(path)
	for _, keyword := range apiKeywords {
		if strings.Contains(path, keyword) {
			return true
		}
	}
	return false
}

func newHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
		Timeout: 10 * time.Second,
	}
}

func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if u := strings.TrimSpace(scanner.Text()); u != "" {
			urls = append(urls, u)
		}
	}
	return urls, scanner.Err()
}

func processURL(client *http.Client, rawURL string) []string {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if finalURL != rawURL {
		baseURL, err = url.Parse(finalURL)
		if err != nil {
			return nil
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil
	}

	var results []string
	for _, form := range findForms(doc) {
		if targetURL := buildTargetURL(baseURL, form); targetURL != "" {
			results = append(results, targetURL)
		}
	}
	return results
}

type formData struct {
	action string
	method string
	inputs map[string]string
}

var templateRegex = regexp.MustCompile(`\{\{.*?\}\}`)

func findForms(n *html.Node) []formData {
	var forms []formData
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			fd := formData{method: "get", inputs: make(map[string]string)}
			for _, attr := range n.Attr {
				switch attr.Key {
				case "action":
					fd.action = strings.TrimSpace(attr.Val)
				case "method":
					fd.method = strings.ToLower(strings.TrimSpace(attr.Val))
				}
			}
			if fd.method == "get" {
				findInputsInForm(n, &fd)
				if len(fd.inputs) > 0 {
					forms = append(forms, fd)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(n)
	return forms
}

func findInputsInForm(formNode *html.Node, fd *formData) {
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				switch attr.Key {
				case "name":
					name = strings.TrimSpace(attr.Val)
				case "value":
					value = strings.TrimSpace(attr.Val)
				}
			}
			if name != "" {
				if value == "" || templateRegex.MatchString(value) {
					value = "FOUND"
				}
				fd.inputs[name] = value
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(formNode)
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
	targetURL.RawQuery = params.Encode()
	return targetURL.String()
}

func resolveFormAction(baseURL *url.URL, action string) *url.URL {
	if action == "" || action == "#" {
		return baseURL
	}
	if strings.HasPrefix(action, "#") {
		newURL := *baseURL
		newURL.Fragment = strings.TrimPrefix(action, "#")
		return &newURL
	}
	actionURL, err := url.Parse(action)
	if err != nil {
		return baseURL
	}
	if actionURL.IsAbs() {
		return actionURL
	}
	resolvedURL := *baseURL
	if strings.HasPrefix(action, "/") {
		resolvedURL.Path = actionURL.Path
	} else {
		resolvedURL.Path = path.Join(path.Dir(baseURL.Path), actionURL.Path)
	}
	resolvedURL.Fragment = actionURL.Fragment
	return &resolvedURL
}


