package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	// "path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	RED    = "\033[1;91m"
	GREEN  = "\033[1;92m"
	YELLOW = "\033[1;33m"
	BLUE   = "\033[0;34m"
	RESET  = "\033[0m"
	ARROW  = GREEN + "→" + RESET
	DOLLAR = GREEN + "$" + RESET
	TAB    = "    "
)

type Config struct {
	Ports       []string   `yaml:"ports"`
	RateLimit   int        `yaml:"rate_limit"`
	StatusCodes []int      `yaml:"status_codes"`
	GitPaths    []string   `yaml:"git_paths"`
	Fingerprints []string  `yaml:"fingerprints"`
	UserAgents  []string   `yaml:"user_agents"`
}

var (
	inputFile    string
	dumpRepo     bool
	outputFile   string
	configFile   string
	config       Config
	semaphore    chan struct{}
	outputMutex  sync.Mutex
	dumperActive sync.WaitGroup
)

func init() {
	flag.StringVar(&inputFile, "i", "", "Input file with domains (use stdin if empty)")
	flag.StringVar(&inputFile, "d", "", "Alias for -i, input file with domains")
	flag.BoolVar(&dumpRepo, "dump", false, "Attempt to dump .git if possible")
	flag.StringVar(&outputFile, "o", "", "Write valid URLs to this file")
	flag.StringVar(&configFile, "c", "gitex.cfg", "Path to configuration file (default '/root/.config/gitex/gitex.cfg')")
}

func safeOutput(format string, a ...interface{}) {
	outputMutex.Lock()
	fmt.Printf(format, a...)
	outputMutex.Unlock()
}

func loadConfig() error {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	semaphore = make(chan struct{}, config.RateLimit)
	return nil
}

func printBanner() {
	banner := (` 
 _______  ___   _______  _______  __   __ 
|       ||   | |       ||       ||  |_|  |
|    ___||   | |_     _||    ___||       |
|   | __ |   |   |   |  |   |___ |       |
|   ||  ||   |   |   |  |    ___| |     | 
|   |_| ||   |   |   |  |   |___ |   _   |
|_______||___|   |___|  |_______||__| |__|` + 
	"\n" + ARROW + YELLOW + ` GitEx` + RESET + ` - https://github.com/1hehaq/gitex`)
	fmt.Println(GREEN + banner + RESET + "\n")
	fmt.Printf("%s[CONFIG]%s Successfully loaded %s\n", GREEN, RESET, configFile)
}

func readInput() []string {
	var reader io.Reader
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[-]%s Failed to open input file: %v\n", RED, RESET, err)
			os.Exit(1)
		}
		reader = file
	} else {
		fmt.Printf("%s[INFO]%s Waiting for input from stdin (press Ctrl+D when done)...\n", BLUE, RESET)
		reader = os.Stdin
	}
	var lines []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func checkGitPath(client *http.Client, url, userAgent string) (bool, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	
	req.Header.Set("User-Agent", userAgent)
	
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return false, err
	}

	statusMatch := false
	for _, code := range config.StatusCodes {
		if resp.StatusCode == code {
			statusMatch = true
			break
		}
	}
	
	if statusMatch {
		text := string(body)
		for _, fingerprint := range config.Fingerprints {
			if strings.Contains(text, fingerprint) {
				return true, nil
			}
		}
	}
	return false, nil
}

func checkGit(base string) (bool, string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	userAgent := config.UserAgents[rand.Intn(len(config.UserAgents))]
	var wg sync.WaitGroup
	foundChan := make(chan string, 1)
	done := make(chan bool)

	for _, port := range config.Ports {
		for _, path := range config.GitPaths {
			wg.Add(1)
			go func(p, pth string) {
				defer wg.Done()
				
				select {
				case semaphore <- struct{}{}: //acquire
					defer func() { <-semaphore }() //release
				case <-done:
					return
				}

				url := strings.TrimRight(base, "/") + ":" + p + "/" + pth
				found, err := checkGitPath(client, url, userAgent)
				if err != nil {
					return
				}
				if found {
					select {
					case foundChan <- url:
						close(done)
					default:
					}
				}
			}(port, path)
		}
	}

	go func() {
		wg.Wait()
		close(foundChan)
	}()

	foundURL, ok := <-foundChan
	if ok {
		return true, foundURL
	}
	return false, ""
}

func dumpGit(url, dest string) {
	dumperActive.Add(1)
	defer dumperActive.Done()
	
	safeOutput("%s%s[GIT-DUMPER]%s Trying to dump repository...\n", TAB, BLUE, RESET)
	cmd := exec.Command("git-dumper", url, dest)
	
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	
	if err := cmd.Start(); err != nil {
		safeOutput("%s%s[GIT-DUMPER ERROR]%s Failed to start: %v\n", TAB, RED, RESET, err)
		return
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			safeOutput("%s%s\n", TAB, scanner.Text())
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			safeOutput("%s%s\n", TAB, scanner.Text())
		}
	}()

	if err := cmd.Wait(); err != nil {
		safeOutput("%s%s[GIT-DUMPER ERROR]%s %v\n", TAB, RED, RESET, err)
		return
	}
	
	safeOutput("%s%s[GIT-DUMPER]%s Repository dumped successfully to %s\n", TAB, GREEN, RESET, dest)
}

func main() {
	flag.Parse()
	
	rand.Seed(time.Now().UnixNano())
	
	if err := loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "%s[ERR]%s %v\n", RED, RESET, err)
		os.Exit(1)
	}

	printBanner()

	domains := readInput()
	if len(domains) == 0 {
		fmt.Fprintf(os.Stderr, "%s[ERR]%s No domains provided\n", RED, RESET)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	results := make(chan string, len(domains))
	notDumpable := make(chan string, len(domains)*2)
	notDumpableResults := []string{}

	go func() {
		for domain := range notDumpable {
			notDumpableResults = append(notDumpableResults, domain)
		}
	}()

	for _, item := range domains {
		bases := []string{}
		if strings.HasPrefix(item, "http://") || strings.HasPrefix(item, "https://") {
			bases = append(bases, item)
		} else {
			bases = append(bases, "http://"+item, "https://"+item)
		}
		for _, base := range bases {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				ok, gitURL := checkGit(u)
				if ok {
					safeOutput("%s[OK]%s %s\n", GREEN, RESET, gitURL)
					results <- gitURL
					if dumpRepo {
						dir := "dumps/" + strings.ReplaceAll(strings.ReplaceAll(u, "://", "_"), "/", "_")
						os.MkdirAll(dir, 0755)
						dumpGit(u+"/.git/", dir)
					}
				} else {
					notDumpable <- u
				}
			}(base)
		}
	}

	go func() {
		wg.Wait()
		dumperActive.Wait()
		close(results)
		close(notDumpable)
		
		safeOutput("\n%s[SUMMARY]%s Not dumpable domains:%s\n", BLUE, RESET, RESET)
		for _, domain := range notDumpableResults {
			safeOutput("%s-%s %s %s %snot dumpable%s\n", YELLOW, RESET, domain, ARROW, RED, RESET)
		}
	}()

	var outfile *os.File
	var err error
	if outputFile != "" {
		outfile, err = os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERR]%s Could not open output file: %v\n", RED, RESET, err)
			os.Exit(1)
		}
		defer outfile.Close()
	}

	for url := range results {
		if outfile != nil {
			outfile.WriteString(url + "\n")
		}
	}
}
