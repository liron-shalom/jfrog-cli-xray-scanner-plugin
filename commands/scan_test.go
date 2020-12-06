package commands

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetMinSeverity(t *testing.T) {
	var testCases = []struct {
		input            string
		expectedSeverity severityType
		errorExpected    bool
	}{
		{
			input:            "low",
			expectedSeverity: low,
			errorExpected:    false,
		},
		{
			input:            "medium",
			expectedSeverity: medium,
			errorExpected:    false,
		},
		{
			input:            "high",
			expectedSeverity: high,
			errorExpected:    false,
		},
		{
			input:            "Low",
			expectedSeverity: low,
			errorExpected:    false,
		},
		{
			input:            "MEDIUM",
			expectedSeverity: medium,
			errorExpected:    false,
		},
		{
			input:            "HiGh",
			expectedSeverity: high,
			errorExpected:    false,
		},
		{
			input:            "loow",
			expectedSeverity: low,
			errorExpected:    true,
		},
		{
			input:            "h",
			expectedSeverity: low,
			errorExpected:    true,
		},
		{
			input:            "Mid",
			expectedSeverity: low,
			errorExpected:    true,
		},
		{
			input:            "loW",
			expectedSeverity: low,
			errorExpected:    false,
		},
	}
	for _, tc := range testCases {
		minSeverity, err := getMinSeverity(tc.input)
		if tc.errorExpected {
			assert.Error(t, err)
		}
		assert.Equal(t, tc.expectedSeverity, minSeverity)
	}
}

func TestFilterIssues(t *testing.T) {
	issues1 := []ArtifactIssue{
		{
			Severity: "High",
		},
		{
			Severity: "Medium",
		},
		{
			Severity: "Low",
		},
		{
			Severity: "Low",
		},
	}
	issues2 := []ArtifactIssue{
		{
			Severity: "Medium",
		},
		{
			Severity: "Low",
		},
		{
			Severity: "Medium",
		},
	}
	var testCases = []struct {
		minSeverity        severityType
		expectedIssues1len int
		expectedIssues2len int
	}{
		{
			minSeverity:        low,
			expectedIssues1len: 4,
			expectedIssues2len: 3,
		},
		{
			minSeverity:        medium,
			expectedIssues1len: 2,
			expectedIssues2len: 2,
		},
		{
			minSeverity:        high,
			expectedIssues1len: 1,
			expectedIssues2len: 0,
		},
	}
	for _, tc := range testCases {
		filteredIssues := filterIssues(issues1, tc.minSeverity)
		assert.Equal(t, tc.expectedIssues1len, len(filteredIssues))
		filteredIssues = filterIssues(issues2, tc.minSeverity)
		assert.Equal(t, tc.expectedIssues2len, len(filteredIssues))
	}
}
