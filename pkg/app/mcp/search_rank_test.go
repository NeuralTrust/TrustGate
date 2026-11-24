// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcp

import (
	"reflect"
	"strings"
	"testing"
)

// rankingCorpus is a surface of the shape the Store serves: several servers
// with overlapping verbs, so a ranking that leans on the verb alone fails.
var rankingCorpus = []searchDoc{
	{Name: "linear_list_issues", Server: "Linear", Code: "app.linear/mcp", Description: "List issues in the user's Linear workspace, filtered by assignee, team or state.", Params: []string{"assignee", "team", "state", "limit"}},
	{Name: "linear_save_issue", Server: "Linear", Code: "app.linear/mcp", Description: "Create or update a Linear issue.", Params: []string{"id", "title", "description", "team"}},
	{Name: "linear_save_comment", Server: "Linear", Code: "app.linear/mcp", Description: "Add a comment to a Linear issue.", Params: []string{"issueId", "body"}},
	{Name: "linear_list_comments", Server: "Linear", Code: "app.linear/mcp", Description: "List the comments on a Linear issue.", Params: []string{"issueId"}},
	{Name: "github_create_issue", Server: "GitHub", Code: "com.github/mcp", Description: "Create an issue in a GitHub repository.", Params: []string{"owner", "repo", "title", "body"}},
	{Name: "github_add_issue_comment", Server: "GitHub", Code: "com.github/mcp", Description: "Add a comment to an issue or pull request.", Params: []string{"owner", "repo", "issue_number", "body"}},
	{Name: "github_create_pull_request", Server: "GitHub", Code: "com.github/mcp", Description: "Open a pull request.", Params: []string{"owner", "repo", "title", "head", "base"}},
	{Name: "gmail_send_message", Server: "Gmail", Code: "com.google/gmail", Description: "Send an email from the user's mailbox.", Params: []string{"to", "subject", "body"}},
	{Name: "gmail_search_threads", Server: "Gmail", Code: "com.google/gmail", Description: "Search the user's email threads.", Params: []string{"query"}},
	{Name: "slack_post_message", Server: "Slack", Code: "com.slack/mcp", Description: "Post a message to a Slack channel.", Params: []string{"channel", "text"}},
	{Name: "notion_create_page", Server: "Notion", Code: "com.notion/mcp", Description: "Create a page in a Notion workspace.", Params: []string{"parent", "title", "content"}},
}

func topNames(query string, n int) []string {
	ranked := rankSearchDocs(query, rankingCorpus)
	var out []string
	for i := 0; i < n && i < len(ranked); i++ {
		out = append(out, rankingCorpus[ranked[i].Index].Name)
	}
	return out
}

func TestRankSearchDocs_FindsTheToolForTheJob(t *testing.T) {
	t.Parallel()
	for query, want := range map[string]string{
		"add a comment to a linear issue": "linear_save_comment",
		"list my linear issues":           "linear_list_issues",
		"open a pull request on github":   "github_create_pull_request",
		"send an email":                   "gmail_send_message",
		"post in a slack channel":         "slack_post_message",
		"create a notion page":            "notion_create_page",
		// The words people use, not the ones the tool is named with.
		"new ticket in linear":           "linear_save_issue",
		"enviar un correo":               "gmail_send_message",
		"crear una incidencia en linear": "linear_save_issue",
		"PR":                             "github_create_pull_request",
	} {
		got := topNames(query, 1)
		if len(got) == 0 || got[0] != want {
			t.Fatalf("%q: top = %v, want %s", query, topNames(query, 3), want)
		}
	}
}

// The right tool must be on the first page, not just somewhere: the case the
// spec measures is the top 10.
func TestRankSearchDocs_KeepsTheRightToolOnTheFirstPage(t *testing.T) {
	t.Parallel()
	for query, want := range map[string]string{
		"comment": "github_add_issue_comment",
		// Ambiguous between reading and writing: both are on the first page.
		"linear issues":     "linear_list_issues",
		"issue":             "github_create_issue",
		"reply to a ticket": "linear_save_comment",
	} {
		if !containsString(topNames(query, 10), want) {
			t.Fatalf("%q: first page %v lacks %s", query, topNames(query, 10), want)
		}
	}
}

// Asked for by its exact name, a tool comes first whatever else matches.
func TestRankSearchDocs_ExactNameFirst(t *testing.T) {
	t.Parallel()
	for _, doc := range rankingCorpus {
		if got := topNames(doc.Name, 1); len(got) == 0 || got[0] != doc.Name {
			t.Fatalf("%q: top = %v", doc.Name, got)
		}
	}
}

// The same query over the same tools answers the same way every time.
func TestRankSearchDocs_IsDeterministic(t *testing.T) {
	t.Parallel()
	first := topNames("create", len(rankingCorpus))
	for i := 0; i < 20; i++ {
		if got := topNames("create", len(rankingCorpus)); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d: %v, want %v", i, got, first)
		}
	}
}

// A server cannot buy the top of every search by stuffing its descriptions:
// the description is cut before it is indexed and weighs less than names.
func TestRankSearchDocs_DescriptionStuffingDoesNotWin(t *testing.T) {
	t.Parallel()
	docs := append([]searchDoc{}, rankingCorpus...)
	docs = append(docs, searchDoc{
		Name:        "evil_helper",
		Server:      "Evil",
		Description: strings.Repeat("send email message gmail mail ", 200),
	})
	ranked := rankSearchDocs("send an email", docs)
	if len(ranked) == 0 || docs[ranked[0].Index].Name != "gmail_send_message" {
		t.Fatalf("top = %v, want gmail_send_message", docs[ranked[0].Index].Name)
	}
}

func TestRankSearchDocs_NothingMatchesNothing(t *testing.T) {
	t.Parallel()
	if got := rankSearchDocs("zzzz qqqq", rankingCorpus); len(got) != 0 {
		t.Fatalf("got %d results for gibberish", len(got))
	}
	if got := rankSearchDocs("the of and", rankingCorpus); len(got) != 0 {
		t.Fatalf("stopwords alone matched %d tools", len(got))
	}
}

// The fallback finds what a plain substring search found before there was a
// ranking, so a query never finds less than it used to.
func TestSubstringMatches(t *testing.T) {
	t.Parallel()
	got := substringMatches("threads", rankingCorpus)
	if len(got) != 1 || rankingCorpus[got[0].Index].Name != "gmail_search_threads" {
		t.Fatalf("got %v", got)
	}
}

func TestSearchTokens(t *testing.T) {
	t.Parallel()
	for in, want := range map[string][]string{
		"linear_list_issues":          {"linear", "list", "issue"},
		"listIssues":                  {"list", "issue"},
		"Send an e-mail!":             {"send", "mail"},
		"comentario en la incidencia": {"comentario", "incidencia"},
		"v2 API":                      {"v2", "api"},
		"repositories":                {"repository"},
	} {
		if got := searchTokens(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: %v, want %v", in, got, want)
		}
	}
}
