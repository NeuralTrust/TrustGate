package functional_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestResult represents the result of a single test
type TestResult struct {
	TestName     string
	TestSuite    string
	Passed       bool
	ErrorMessage string
	Duration     time.Duration
}

// TestReporter collects and reports test results
type TestReporter struct {
	results   []TestResult
	startTime time.Time
	mu        sync.Mutex
}

// GlobalReporter is the global test reporter instance
var GlobalReporter *TestReporter

// NewTestReporter creates a new test reporter
func NewTestReporter() *TestReporter {
	return &TestReporter{
		results:   make([]TestResult, 0),
		startTime: time.Now(),
	}
}

// AddResult adds a test result to the reporter
func (tr *TestReporter) AddResult(result TestResult) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.results = append(tr.results, result)
}

// PrintReport prints a comprehensive test report to console
func (tr *TestReporter) PrintReport() {
	tr.PrintReportWithExitCode(-1)
}

// PrintReportWithExitCode prints a comprehensive test report to console with exit code info
func (tr *TestReporter) PrintReportWithExitCode(exitCode int) {
	totalDuration := time.Since(tr.startTime)
	totalTests := len(tr.results)
	passedTests := 0
	failedTests := 0

	suiteStats := make(map[string]struct {
		total  int
		passed int
		failed int
	})

	for _, result := range tr.results {
		if result.Passed {
			passedTests++
		} else {
			failedTests++
		}

		stats := suiteStats[result.TestSuite]
		stats.total++
		if result.Passed {
			stats.passed++
		} else {
			stats.failed++
		}
		suiteStats[result.TestSuite] = stats
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    FUNCTIONAL TEST REPORT")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   ⏱️  Total Duration: %s\n", totalDuration.Round(time.Millisecond))

	if exitCode == 0 {
		fmt.Printf("   ✅ All tests PASSED\n")
	} else if exitCode > 0 {
		fmt.Printf("   ❌ Some tests FAILED (exit code: %d)\n", exitCode)
	}

	// If we have detailed results, show them
	if totalTests > 0 {
		fmt.Printf("\n   Recorded Tests:  %d\n", totalTests)
		fmt.Printf("   ✅ Passed:        %d\n", passedTests)
		fmt.Printf("   ❌ Failed:        %d\n", failedTests)
		if totalTests > 0 {
			fmt.Printf("   📈 Success Rate:  %.1f%%\n", float64(passedTests)/float64(totalTests)*100)
		}

		if len(suiteStats) > 0 {
			fmt.Printf("\n📋 Per Test Suite Breakdown:\n")
			fmt.Println(strings.Repeat("-", 80))
			for suite, stats := range suiteStats {
				successRate := float64(0)
				if stats.total > 0 {
					successRate = float64(stats.passed) / float64(stats.total) * 100
				}
				status := "✅"
				if stats.failed > 0 {
					status = "⚠️"
				}
				fmt.Printf("   %s %-35s: %d/%d passed (%.1f%%)\n",
					status, suite, stats.passed, stats.total, successRate)
			}
		}

		if failedTests > 0 {
			fmt.Printf("\n❌ Failed Tests:\n")
			fmt.Println(strings.Repeat("-", 80))
			for _, result := range tr.results {
				if !result.Passed {
					fmt.Printf("   • %s [%s]\n", result.TestName, result.TestSuite)
					if result.ErrorMessage != "" {
						fmt.Printf("     Error: %s\n", result.ErrorMessage)
					}
					fmt.Printf("     Duration: %s\n", result.Duration.Round(time.Millisecond))
				}
			}
		}

		if passedTests > 0 {
			fmt.Printf("\n✅ Passed Tests:\n")
			fmt.Println(strings.Repeat("-", 80))
			for _, result := range tr.results {
				if result.Passed {
					fmt.Printf("   ✓ %s [%s] (%s)\n",
						result.TestName, result.TestSuite, result.Duration.Round(time.Millisecond))
				}
			}
		}
	}

	fmt.Println(strings.Repeat("=", 80))
}

// GetResults returns all test results
func (tr *TestReporter) GetResults() []TestResult {
	return tr.results
}

// RecordTest is a helper function to record test results
// Call this at the end of each test with defer
func RecordTest(t interface {
	Name() string
	Failed() bool
}, suite string, startTime time.Time, errMsg string) {
	if GlobalReporter == nil {
		return
	}

	result := TestResult{
		TestName:     t.Name(),
		TestSuite:    suite,
		Passed:       !t.Failed(),
		ErrorMessage: errMsg,
		Duration:     time.Since(startTime),
	}
	GlobalReporter.AddResult(result)
}

// RunSubtest runs a subtest and automatically records the result
// Usage: RunSubtest(t, "MyTestSuite", "SubtestName", func(t *testing.T) { ... })
func RunSubtest(t *testing.T, suite, name string, fn func(t *testing.T)) {
	t.Run(name, func(t *testing.T) {
		start := time.Now()
		defer func() {
			if GlobalReporter != nil {
				GlobalReporter.AddResult(TestResult{
					TestName:  t.Name(),
					TestSuite: suite,
					Passed:    !t.Failed(),
					Duration:  time.Since(start),
				})
			}
		}()
		fn(t)
	})
}

// RunTest records a top-level test result
// Usage: defer RunTest(t, "MyTestSuite", time.Now())()
func RunTest(t *testing.T, suite string, start time.Time) func() {
	return func() {
		if GlobalReporter != nil {
			GlobalReporter.AddResult(TestResult{
				TestName:  t.Name(),
				TestSuite: suite,
				Passed:    !t.Failed(),
				Duration:  time.Since(start),
			})
		}
	}
}
