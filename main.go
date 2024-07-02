package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] target1 target2 ... \n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  %s 192.168.1.1\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s --list ips.txt\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s --list ips.txt --port 2222\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s 192.168.1.0/24\n", os.Args[0])
}

func printBanner() {
	banner := `
                       ___ ___ _  _ _          
  _ _ ___ __ _ _ _ ___/ __/ __| || (_)___ _ _  
 | '_/ -_) _  | '_/ -_)__ \__ \ __ | / _  ' \ 
 |_| \___\__, |_|_\___|___/___/_||_|_\___/_||_|
  __| |_ |___/__| |_____ _ _                   
 / _| ' \/ -_) _| / / -_) '_|                  
 \__|_||_\___\__|_\_\___|_|                    

 version 0.1.0 | github.com/xonoxitron/regreSSHion-checker
 
 `
	fmt.Println(banner)
}

// Function to check if SSH port is open and retrieve banner
func getSSHBanner(ip string, port int, timeout time.Duration) (string, error) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(banner), nil
}

// Function to check vulnerability based on SSH banner
func checkVulnerability(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, resultChan chan<- string) {
	defer wg.Done()

	banner, err := getSSHBanner(ip, port, timeout)
	if err != nil {
		resultChan <- fmt.Sprintf("%s:%d closed: %v", ip, port, err)
		return
	}

	vulnerableVersions := []string{
		"SSH-2.0-OpenSSH_8.5",
		"SSH-2.0-OpenSSH_8.6",
		"SSH-2.0-OpenSSH_8.7",
		"SSH-2.0-OpenSSH_8.8",
		"SSH-2.0-OpenSSH_8.9",
		"SSH-2.0-OpenSSH_9.0",
		"SSH-2.0-OpenSSH_9.1",
		"SSH-2.0-OpenSSH_9.2",
		"SSH-2.0-OpenSSH_9.3",
		"SSH-2.0-OpenSSH_9.4",
		"SSH-2.0-OpenSSH_9.5",
		"SSH-2.0-OpenSSH_9.6",
		"SSH-2.0-OpenSSH_9.7",
	}

	excludedVersions := []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	}

	isVulnerable := false
	for _, version := range vulnerableVersions {
		if strings.Contains(banner, version) {
			isVulnerable = true
			break
		}
	}

	if isVulnerable {
		excluded := false
		for _, excludedVersion := range excludedVersions {
			if banner == excludedVersion {
				excluded = true
				break
			}
		}
		if !excluded {
			resultChan <- fmt.Sprintf("%s:%d vulnerable (running %s)", ip, port, banner)
			return
		}
	}

	resultChan <- fmt.Sprintf("%s:%d not vulnerable (running %s)", ip, port, banner)
}

func main() {
	printBanner()
	var targets []string
	var ipListFile string
	var port int
	var timeout time.Duration

	flag.IntVar(&port, "port", 22, "Port number to check (default: 22)")
	flag.DurationVar(&timeout, "timeout", 1*time.Second, "Connection timeout in seconds (default: 1 second)")
	flag.StringVar(&ipListFile, "list", "", "File containing a list of IP addresses to check")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 && ipListFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	targets = flag.Args()
	if ipListFile != "" {
		file, err := os.Open(ipListFile)
		if err != nil {
			fmt.Printf("❌ [-] Could not read file: %s\n", ipListFile)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			targets = append(targets, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("❌ [-] Error reading file: %v\n", err)
			return
		}
	}

	var wg sync.WaitGroup
	resultChan := make(chan string)

	for _, target := range targets {
		if strings.Contains(target, "/") {
			ips, err := getIPsFromCIDR(target)
			if err != nil {
				fmt.Printf("❌ [-] Invalid CIDR notation: %s\n", target)
				continue
			}
			for _, ip := range ips {
				wg.Add(1)
				go checkVulnerability(ip.String(), port, timeout, &wg, resultChan)
			}
		} else {
			wg.Add(1)
			go checkVulnerability(target, port, timeout, &wg, resultChan)
		}
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	notVulnerableCount := 0
	vulnerableCount := 0
	closedPortsCount := 0

	for result := range resultChan {
		if strings.Contains(result, "closed") {
			closedPortsCount++
		} else if strings.Contains(result, "vulnerable") {
			vulnerableCount++
			fmt.Printf("🚨 %s\n", result)
		} else if strings.Contains(result, "not vulnerable") {
			notVulnerableCount++
			fmt.Printf("🛡️ %s\n", result)
		} else {
			fmt.Printf("⚠️ [!] %s\n", result)
		}
	}

	fmt.Printf("\n🔒 Servers with port %d closed: %d\n", port, closedPortsCount)
	fmt.Printf("\n📊 Total scanned targets: %d\n", len(targets))
}

// Function to get IPs from CIDR notation
func getIPsFromCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, net.IP{ip[0], ip[1], ip[2], ip[3]})
	}
	// Remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// Function to increment IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
