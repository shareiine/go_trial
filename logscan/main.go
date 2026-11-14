package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
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
	fmt.Println("IP Address Counts:")
	// loop to count the times each IP address appears in the log file
	for ip, count := range ipCount {
		fmt.Printf("%s: %d\n", ip, count)
	}
	// loop to count the times each status code appears in the log file
	fmt.Println("Status Code Counts:")
	for status, count := range statusCount {
		fmt.Printf("%d: %d\n", status, count)
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
