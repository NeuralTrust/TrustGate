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

package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type memModelRequestStore map[string]ModelRequestTicket

func (m memModelRequestStore) SaveTicket(_ context.Context, id string, t ModelRequestTicket) error {
	m[id] = t
	return nil
}

func (m memModelRequestStore) GetTicket(_ context.Context, id string) (*ModelRequestTicket, error) {
	if t, ok := m[id]; ok {
		return &t, nil
	}
	return nil, nil
}

func (m memModelRequestStore) DeleteTicket(_ context.Context, id string) error {
	delete(m, id)
	return nil
}

type fakeModelConsole struct {
	answer *ModelAccessAnswer
	err    error
	filed  []ModelAccessFiling
}

func (c *fakeModelConsole) Check(context.Context, ModelAccessQuery) (*ModelAccessAnswer, error) {
	return c.answer, c.err
}

func (c *fakeModelConsole) File(_ context.Context, f ModelAccessFiling) (*ModelAccessAnswer, error) {
	c.filed = append(c.filed, f)
	return c.answer, c.err
}

var mistralTicket = ModelRequestTicket{TeamID: "team-1", GatewayID: "gw-1", PrincipalSub: "alice", Provider: "mistral", RegistryID: "reg-mistral", Name: "Mistral"}

func newModelRequestPages(t *testing.T, answer *ModelAccessAnswer) (ModelRequestPages, memModelRequestStore, *fakeModelConsole, string) {
	t.Helper()
	store := memModelRequestStore{}
	console := &fakeModelConsole{answer: answer}
	pages, err := NewModelRequestPages(store, console)
	require.NoError(t, err)
	id, err := pages.CreateTicket(context.Background(), mistralTicket)
	require.NoError(t, err)
	return pages, store, console, id
}

// Sending the form files the request with the person's words, for the ticket's
// owner and target, and spends the link.
func TestModelRequestPages_SendFilesThePersonsRequest(t *testing.T) {
	pages, store, console, id := newModelRequestPages(t, &ModelAccessAnswer{Status: ModelAccessRequested, Name: "Mistral"})

	page, err := pages.Page(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, &ModelRequestPage{Name: "Mistral"}, page)

	page, err = pages.Submit(context.Background(), id, "  French support tickets  ")
	require.NoError(t, err)
	require.True(t, page.Sent)
	require.Equal(t, []ModelAccessFiling{{
		ModelAccessQuery: ModelAccessQuery{TeamID: "team-1", GatewayID: "gw-1", UserID: "alice", Provider: "mistral", RegistryID: "reg-mistral"},
		Reason:           "French support tickets",
	}}, console.filed)
	require.Empty(t, store, "a sent request spends its link")

	_, err = pages.Page(context.Background(), id)
	require.ErrorIs(t, err, ErrModelRequestLinkGone)
}

func TestModelRequestPages_NeedsTheReason(t *testing.T) {
	pages, store, console, id := newModelRequestPages(t, &ModelAccessAnswer{Status: ModelAccessRequested})
	_, err := pages.Submit(context.Background(), id, "   ")
	require.ErrorIs(t, err, ErrModelRequestReasonRequired)
	require.Empty(t, console.filed)
	require.Len(t, store, 1, "the form stays for the words")
}

// What the console refused is said on the page: a final answer closes the
// form, a limit leaves it for a later send.
func TestModelRequestPages_SaysWhyNothingWasFiled(t *testing.T) {
	pages, store, _, id := newModelRequestPages(t, &ModelAccessAnswer{Status: ModelAccessAlreadyAsked, Error: "A request for Mistral models is already waiting for an admin"})
	page, err := pages.Submit(context.Background(), id, "Tickets")
	require.NoError(t, err)
	require.Equal(t, &ModelRequestPage{Name: "Mistral", Notice: "A request for Mistral models is already waiting for an admin", Closed: true}, page)
	require.Empty(t, store)

	pages, store, _, id = newModelRequestPages(t, &ModelAccessAnswer{Status: ModelAccessRateLimited, Error: "Too many access requests. Try again later."})
	page, err = pages.Submit(context.Background(), id, "Tickets")
	require.NoError(t, err)
	require.Equal(t, &ModelRequestPage{Name: "Mistral", Notice: "Too many access requests. Try again later."}, page)
	require.Len(t, store, 1)
}

func TestModelRequestPages_KeepsTheLinkWhenTheConsoleCannotBeReached(t *testing.T) {
	pages, store, console, id := newModelRequestPages(t, nil)
	console.err = errors.New("console down")
	_, err := pages.Submit(context.Background(), id, "Tickets")
	require.Error(t, err)
	require.Len(t, store, 1)
}

// Shortened to what the console keeps, counted as the browser and the console
// count: an astral character is two.
func TestTrimModelRequestReason(t *testing.T) {
	require.Equal(t, "why", trimModelRequestReason("  why  "))
	require.Equal(t, strings.Repeat("a", MaxModelRequestReasonLength), trimModelRequestReason(strings.Repeat("a", MaxModelRequestReasonLength+20)))
	emoji := strings.Repeat("🙂", MaxModelRequestReasonLength)
	require.Equal(t, strings.Repeat("🙂", MaxModelRequestReasonLength/2), trimModelRequestReason(emoji))
}

func TestModelRequestPages_TicketNeedsItsOwnerAndTarget(t *testing.T) {
	pages, err := NewModelRequestPages(memModelRequestStore{}, &fakeModelConsole{})
	require.NoError(t, err)
	_, err = pages.CreateTicket(context.Background(), ModelRequestTicket{GatewayID: "gw-1", PrincipalSub: "alice", Provider: "mistral"})
	require.Error(t, err)
	_, err = pages.CreateTicket(context.Background(), ModelRequestTicket{TeamID: "team-1", GatewayID: "gw-1", PrincipalSub: "alice"})
	require.Error(t, err)

	_, err = NewModelRequestPages(nil, &fakeModelConsole{})
	require.Error(t, err)
}
