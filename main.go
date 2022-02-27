package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

type prefix struct {
	IP_range string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
	Nbg      string `json:"network_border_group"`
}

type response struct {
	Prefixes []prefix `json:"prefixes"`
}

const AWS_PUBLIC_IP_RANGES = "https://ip-ranges.amazonaws.com/ip-ranges.json"

func GetAWSPublicIPs() (r response, err error) {
	resp, err := http.Get(AWS_PUBLIC_IP_RANGES)
	if err != nil {
		return r, err
	}

	// We Read the response body on the line below.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}

	if err = json.Unmarshal(body, &r); err != nil {
		return r, err
	}
	return r, nil
}

type SafeRegionMap struct {
	mu      sync.Mutex
	regions map[string][]string
}

func (l *SafeRegionMap) Append(key string, ips []string) {
	l.mu.Lock()
	// Lock so only one goroutine at a time can access the map c.v.
	l.regions[key] = append(l.regions[key], ips...)
	l.mu.Unlock()
}

func Hosts(pref prefix, l *SafeRegionMap, wg *sync.WaitGroup) {
	defer wg.Done()

	ip, ipnet, err := net.ParseCIDR(pref.IP_range)
	if err != nil {
		return
	}
	if pref.Region != "eu-west-1" {
		return
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); nextIP(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		l.Append(pref.Region, ips)

	default:
		l.Append(pref.Region, ips[1:len(ips)-1])
	}
}

func nextIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type SafePortScan struct {
	mu   sync.Mutex
	Open map[string]bool
}

// Inc increments the counter for the given key.
func (p *SafePortScan) Set(key string, value bool) {
	p.mu.Lock()
	// Lock so only one goroutine at a time can access the map c.v.
	p.Open[key] = value
	p.mu.Unlock()
}

func testConnect(host string, port string, scan *SafePortScan, sem *semaphore.Weighted) {
	defer sem.Release(1)
	timeout := 3 * time.Second

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		scan.Set(host, false)
		return
	}
	if conn != nil {
		defer conn.Close()
		scan.Set(host, true)
		return
	}
	scan.Set(host, false)
}

func main() {
	r, err := GetAWSPublicIPs()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Initiating phase 1. Counting AWS IP addresses")

	var wg sync.WaitGroup
	regionMap := SafeRegionMap{regions: make(map[string][]string)}
	for _, prefix := range r.Prefixes {
		wg.Add(1)
		go Hosts(prefix, &regionMap, &wg)
	}
	wg.Wait()

	ipCount := 0
	for _, value := range regionMap.regions {
		ipCount += len(value)
	}
	log.Printf("Phase 1 done, identified %d IP addresses.", ipCount)

	size := len(regionMap.regions["eu-west-1"])
	log.Printf("Initiating phase 2, scanning %d IPs in 'eu-west-1' region.", size)
	portScan := SafePortScan{Open: make(map[string]bool)}

	semaphoreSize := int64(100000)
	sem := semaphore.NewWeighted(semaphoreSize)
	for k, ip := range regionMap.regions["eu-west-1"] {
		ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
		sem.Acquire(ctx, 1) // acquire n with timeout
		if int64(k)%semaphoreSize == 0 {
			go func() {
				log.Printf("\tScanned %d results, %d more to go.", k, size-k)
				counter := 0
				portScan.mu.Lock()
				for _, v := range portScan.Open {
					if v {
						counter += 1
					}
				}
				portScan.mu.Unlock()
				log.Printf("\tFor now, got %d open results.", counter)
			}()
		}
		go testConnect(ip, "22", &portScan, sem)
	}
	log.Printf("Phase 2 done, got %d results.", len(portScan.Open))

	log.Printf("Initiating phase 3, filtering out closed ports.")
	var result []string
	for ip, v := range portScan.Open {
		if v {
			result = append(result, ip)
		}
	}
	log.Printf("Phase 3 done, got %d open results.", len(result))
}
