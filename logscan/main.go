package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("logscan starting")

	// Open the log file
	file, err := os.Open("logs/access.logs")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Read the contents of the file (bufio is better for large files)
	scanner := bufio.NewScanner(file)

	// initialise empty counters
	ipCount := make(map[string]int)
	statusCount := make(map[int]int)
	// counter to keep track of those that are not parsed
	unparsedCount := 0
	// counter to keep track of the total number of lines processed
	total := 0

	// Iterate over each line and print it
	for scanner.Scan() {
		data, err := parseLog(scanner.Text())
		// this handles the error if the log line is not in the expected format
		if err != nil {
			log.Printf("Error parsing log line: %v", err)
			unparsedCount++
			continue
		}
		fmt.Printf("IP: %s, Method: %s, Status: %d, Path: %s\n", data.IP, data.Method, data.Status, data.Path)
		// increment the counters
		ipCount[data.IP]++
		statusCount[data.Status]++
		total++
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	// Print the summary of counts
	fmt.Println("\nSummary:")
	fmt.Printf("Total parsed lines: %d\n", total)
	fmt.Printf("Total unparsed lines: %d\n", unparsedCount)
	fmt.Println("Top IP Address Counts:")
	// arrange the IP addresses by the number of requests
	ipList := arrangeByIP(ipCount)
	// loop to count the times each IP address appears in the log file
	for _, ip := range ipList {
		fmt.Printf("%s: %d\n", ip, ipCount[ip])
	}
	// loop to count the times each status code appears in the log file
	fmt.Println("Top Status Code Counts:")
	// arrange the status codes by the number of requests
	statusList := arrangeByStatus(statusCount)
	for _, status := range statusList {
		fmt.Printf("%d: %d\n", status, statusCount[status])
	}

}

// define a struct to hold the log data
type LogData struct {
	IP     string
	Method string
	Status int
	Path   string
}

func parseLog(line string) (LogData, error) {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return LogData{}, fmt.Errorf("invalid log line: %q", line)
	}

	// convert the status code to an integer
	status, err := strconv.Atoi(fields[8])
	if err != nil {
		return LogData{}, fmt.Errorf("invalid status code %q: %w", fields[8], err)
	}

	return LogData{
		IP: fields[0],
		// use trim to remove the quotes from the method and path
		Method: strings.Trim(fields[5], `"`),
		Status: status,
		Path:   strings.Trim(fields[6], `"`),
	}, nil
}

// function to arrange the log data by amount of requests per IP address
// also get the top N IP addresses with the most requests
func arrangeByIP(ipCount map[string]int) []string {
	// create a slice to hold the IP addresses
	ipList := make([]string, 0, len(ipCount))
	for ip := range ipCount {
		ipList = append(ipList, ip)
	}

	// sort the slice by the count of requests per IP address
	sort.Slice(ipList, func(i, j int) bool {
		// sort in ascending order of IP addresses, but descending order of counts
		if ipCount[ipList[i]] == ipCount[ipList[j]] {
			return ipList[i] < ipList[j]
		}
		// sort in descending order of counts
		return ipCount[ipList[i]] > ipCount[ipList[j]]
	})

	// take the top N IP addresses with the most requests
	N := 3
	if len(ipList) > N {
		ipList = ipList[:N]
	}
	return ipList
}

// function to arrange the log data by amount of requests per status code
func arrangeByStatus(statusCount map[int]int) []int {
	// create a slice to hold the status codes
	statusList := make([]int, 0, len(statusCount))
	for status := range statusCount {
		statusList = append(statusList, status)
	}

	// sort the slice by the count of requests per status code
	sort.Slice(statusList, func(i, j int) bool {
		// sort in ascending order of status codes, but descending order of counts
		if statusCount[statusList[i]] == statusCount[statusList[j]] {
			return statusList[i] < statusList[j]
		}
		// sort in descending order of counts
		return statusCount[statusList[i]] > statusCount[statusList[j]]
	})
	return statusList
}
