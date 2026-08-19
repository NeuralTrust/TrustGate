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
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// SubscriptionAuthorization re-evaluates one complete binding for an event.
type SubscriptionAuthorization func(
	ctx context.Context,
	identity SubscriptionIdentity,
	source SubscriptionSourceKey,
	kind NotificationKind,
) (bool, error)

// SubscriptionWaiter performs a context-cancellable reconnect wait.
type SubscriptionWaiter interface {
	Wait(ctx context.Context, delay time.Duration) error
}

// SubscriptionSourceRecorder records fixed-cardinality source lifecycle signals.
type SubscriptionSourceRecorder interface {
	// ListenerLive adjusts the number of joined physical listeners.
	ListenerLive(ctx context.Context, delta int64)
	// Lifecycle records listener preparation and pooling outcomes.
	Lifecycle(ctx context.Context, outcome string)
	// FanOut records one authorization decision for an upstream event.
	FanOut(ctx context.Context, kind NotificationKind, outcome string)
	// Reconnect records one bounded reconnect outcome.
	Reconnect(ctx context.Context, outcome string)
	// Queue records one bounded per-handle queue outcome.
	Queue(ctx context.Context, kind NotificationKind, outcome string)
	// Terminal records why a physical listener ended.
	Terminal(ctx context.Context, outcome string)
}

const (
	maxTransientAuthorizationFailures = 3

	subscriptionSourceLifecycleUnsupported = "unsupported"
	subscriptionSourceLifecycleOpenFailed  = "open_failed"
	subscriptionSourceLifecycleOpened      = "opened"
	subscriptionSourceLifecycleReused      = "reused"
	subscriptionSourceLifecycleJoined      = "joined"

	subscriptionSourceFanOutAuthorized = "authorized"
	subscriptionSourceFanOutDenied     = "denied"
	subscriptionSourceFanOutRevoked    = "revoked"
	subscriptionSourceFanOutTransient  = "transient"
	subscriptionSourceFanOutRejected   = "rejected"

	subscriptionSourceReconnectAttempted     = "attempted"
	subscriptionSourceReconnectSucceeded     = "succeeded"
	subscriptionSourceReconnectFailed        = "failed"
	subscriptionSourceReconnectExhausted     = "exhausted"
	subscriptionSourceReconnectSourceChanged = "source_changed"
	subscriptionSourceReconnectCancelled     = "cancelled"
	subscriptionSourceReconnectTerminal      = "terminal"

	subscriptionSourceQueueEnqueued = "enqueued"
	subscriptionSourceQueueFull     = "full"

	subscriptionSourceTerminalLastDetach         = "last_detach"
	subscriptionSourceTerminalShutdown           = "shutdown"
	subscriptionSourceTerminalReconnectExhausted = "reconnect_exhausted"
	subscriptionSourceTerminalSourceChanged      = "source_changed"
	subscriptionSourceTerminalAuthentication     = "authentication"
	subscriptionSourceTerminalProtocolFailure    = "protocol_failure"
	subscriptionSourceTerminalTransportFailure   = "transport_failure"
)

// SubscriptionMultiplexerOptions bounds listener, queue and reconnect resources.
type SubscriptionMultiplexerOptions struct {
	MaxListeners         int
	MaxPerOrigin         int
	QueueCapacity        int
	ReconnectAttempts    int
	ReconnectBackoffMin  time.Duration
	ReconnectBackoffMax  time.Duration
	AuthorizationTimeout time.Duration
	Refresher            SubscriptionTargetRefresher
	Waiter               SubscriptionWaiter
	Jitter               func(time.Duration) time.Duration
	Recorder             SubscriptionSourceRecorder
}

// SubscriptionMultiplexer shares equivalent physical listeners across authorized handles.
type SubscriptionMultiplexer struct {
	connector SubscriptionConnector
	authorize SubscriptionAuthorization
	options   SubscriptionMultiplexerOptions

	rootCtx    context.Context
	rootCancel context.CancelFunc

	attachMu sync.Mutex
	mu       sync.Mutex
	closed   bool
	pool     map[SubscriptionSourceKey]*subscriptionListener
	origins  map[[32]byte]int
	live     int
	wg       sync.WaitGroup
	attachWG sync.WaitGroup
	handleWG sync.WaitGroup
}

type preparedSubscriptionBinding struct {
	request  SubscriptionRequest
	prepared PreparedSubscription
	kinds    HonouredSet
}

type subscriptionAttachReservation struct {
	_ byte
}

type subscriptionListener struct {
	mux       *SubscriptionMultiplexer
	key       SubscriptionSourceKey
	target    Target
	prepared  PreparedSubscription
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	ready     chan struct{}
	readyOnce sync.Once
	openErr   error
	reserved  *subscriptionAttachReservation
	committed bool
	initial   SubscriptionStream
	bindings  map[*subscriptionHandle][]subscriptionListenerBinding
	joining   map[*subscriptionHandle]struct{}
	started   bool
	stopping  bool
	terminal  string
}

type subscriptionListenerBinding struct {
	identity             SubscriptionIdentity
	requested            HonouredSet
	authorizationContext context.Context
	request              SubscriptionRequest
}

type subscriptionAuthorizationWork struct {
	listener *subscriptionListener
	event    SubscriptionEvent
	bindings []subscriptionListenerBinding
}

type subscriptionHandle struct {
	mux                     *SubscriptionMultiplexer
	events                  chan SubscriptionEvent
	done                    chan struct{}
	doneOnce                sync.Once
	completionOnce          sync.Once
	lifecycleOnce           sync.Once
	work                    chan subscriptionAuthorizationWork
	admission               chan struct{}
	workerCtx               context.Context
	cancelWorker            context.CancelFunc
	workerDone              chan struct{}
	workMu                  sync.Mutex
	workerStopped           bool
	mu                      sync.Mutex
	terminal                bool
	err                     error
	workerTransientFailures int
	emitTransientFailures   int
	listeners               map[*subscriptionListener]struct{}
}

type timerSubscriptionWaiter struct{}

func (timerSubscriptionWaiter) Wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// NewSubscriptionMultiplexer creates a bounded process-local listener pool.
func NewSubscriptionMultiplexer(
	parent context.Context,
	connector SubscriptionConnector,
	authorize SubscriptionAuthorization,
	options SubscriptionMultiplexerOptions,
) (*SubscriptionMultiplexer, error) {
	if connector == nil {
		return nil, errors.New("mcp: subscription connector is required")
	}
	if authorize == nil {
		return nil, errors.New("mcp: subscription authorization is required")
	}
	if options.MaxListeners <= 0 || options.MaxPerOrigin <= 0 || options.QueueCapacity <= 0 {
		return nil, errors.New("mcp: subscription multiplexer capacities must be positive")
	}
	if options.ReconnectAttempts < 0 ||
		options.ReconnectBackoffMin <= 0 ||
		options.ReconnectBackoffMax <= 0 ||
		options.ReconnectBackoffMin > options.ReconnectBackoffMax {
		return nil, errors.New("mcp: invalid subscription reconnect bounds")
	}
	if options.AuthorizationTimeout <= 0 {
		options.AuthorizationTimeout = 5 * time.Second
	}
	if parent == nil {
		parent = context.Background()
	}
	if options.Waiter == nil {
		options.Waiter = timerSubscriptionWaiter{}
	}
	if options.Jitter == nil {
		options.Jitter = newSubscriptionJitter()
	}
	rootCtx, rootCancel := context.WithCancel(parent)
	return &SubscriptionMultiplexer{
		connector:  connector,
		authorize:  authorize,
		options:    options,
		rootCtx:    rootCtx,
		rootCancel: rootCancel,
		pool:       make(map[SubscriptionSourceKey]*subscriptionListener),
		origins:    make(map[[32]byte]int),
	}, nil
}

func newSubscriptionJitter() func(time.Duration) time.Duration {
	return func(delay time.Duration) time.Duration {
		var sample [8]byte
		if _, err := cryptorand.Read(sample[:]); err != nil {
			return delay
		}
		fraction := float64(binary.LittleEndian.Uint64(sample[:])>>11) / (1 << 53)
		factor := 0.8 + fraction*0.4
		return time.Duration(float64(delay) * factor)
	}
}

// Attach atomically binds one northbound handle to all eligible registry listeners.
func (m *SubscriptionMultiplexer) Attach(
	ctx context.Context,
	requests []SubscriptionRequest,
) (SubscriptionHandle, HonouredSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, HonouredSet{}, err
	}
	if m.rootCtx.Err() != nil {
		return nil, HonouredSet{}, ErrSubscriptionTerminal
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, HonouredSet{}, ErrSubscriptionTerminal
	}
	m.attachWG.Add(1)
	m.mu.Unlock()
	defer m.attachWG.Done()
	prepared, honoured, err := m.prepareBindings(ctx, requests)
	if err != nil {
		return nil, HonouredSet{}, err
	}
	if honoured.Empty() {
		return nil, honoured, nil
	}

	reservation := &subscriptionAttachReservation{}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, HonouredSet{}, ErrSubscriptionTerminal
		}
		owned, listeners, err := m.reserveListenersLocked(prepared, reservation)
		m.mu.Unlock()
		if err != nil {
			return nil, HonouredSet{}, err
		}
		if err := m.openReservedListeners(ctx, owned); err != nil {
			m.rollbackReservedListeners(owned, err)
			return nil, HonouredSet{}, err
		}
		if err := ctx.Err(); err != nil {
			m.rollbackReservedListeners(owned, err)
			return nil, HonouredSet{}, err
		}
		if err := waitForReservedListeners(ctx, listeners, owned); err != nil {
			m.rollbackReservedListeners(owned, err)
			if ctx.Err() != nil || m.rootCtx.Err() != nil {
				return nil, HonouredSet{}, err
			}
			continue
		}

		workerCtx, cancelWorker := context.WithCancel(m.rootCtx)
		handle := &subscriptionHandle{
			mux:          m,
			events:       make(chan SubscriptionEvent),
			done:         make(chan struct{}),
			work:         make(chan subscriptionAuthorizationWork, m.options.QueueCapacity),
			admission:    make(chan struct{}, m.options.QueueCapacity),
			workerCtx:    workerCtx,
			cancelWorker: cancelWorker,
			workerDone:   make(chan struct{}),
			listeners:    make(map[*subscriptionListener]struct{}),
		}
		m.attachMu.Lock()
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			m.attachMu.Unlock()
			cancelWorker()
			m.rollbackReservedListeners(owned, ErrSubscriptionTerminal)
			return nil, HonouredSet{}, ErrSubscriptionTerminal
		}
		valid := true
		for _, binding := range prepared {
			listener := m.pool[binding.prepared.Key]
			if listener == nil || listener.openErr != nil || listener.stopping ||
				(!listener.committed && listener.reserved != reservation) {
				valid = false
				break
			}
		}
		if !valid {
			m.mu.Unlock()
			m.attachMu.Unlock()
			cancelWorker()
			m.rollbackReservedListeners(owned, ErrSubscriptionTerminal)
			if ctx.Err() != nil || m.rootCtx.Err() != nil {
				return nil, HonouredSet{}, ErrSubscriptionTerminal
			}
			continue
		}
		for _, binding := range prepared {
			listener := m.pool[binding.prepared.Key]
			listener.bindings[handle] = append(listener.bindings[handle], subscriptionListenerBinding{
				identity:             binding.request.Identity,
				requested:            binding.kinds,
				authorizationContext: context.WithoutCancel(ctx),
				request:              cloneSubscriptionRequest(binding.request),
			})
			handle.listeners[listener] = struct{}{}
		}
		m.handleWG.Add(1)
		go m.runAuthorizationWorker(handle)
		for listener := range handle.listeners {
			if !listener.committed {
				listener.committed = true
				listener.reserved = nil
				listener.readyOnce.Do(func() { close(listener.ready) })
			}
			if listener.started {
				continue
			}
			listener.started = true
			m.wg.Add(1)
			go m.supervise(listener)
		}
		m.mu.Unlock()
		m.attachMu.Unlock()
		return handle, honoured, nil
	}
}

func (m *SubscriptionMultiplexer) prepareBindings(
	ctx context.Context,
	requests []SubscriptionRequest,
) ([]preparedSubscriptionBinding, HonouredSet, error) {
	prepared := make([]preparedSubscriptionBinding, 0, len(requests))
	honoured := NewHonouredSet()
	for _, request := range requests {
		result, err := m.connector.Prepare(ctx, request.Target)
		if errors.Is(err, ErrSubscriptionUnsupported) {
			m.recordLifecycle(ctx, subscriptionSourceLifecycleUnsupported)
			continue
		}
		if err != nil {
			return nil, HonouredSet{}, fmt.Errorf("mcp: prepare subscription source: %w", err)
		}
		kinds := request.Requested.Intersect(result.Capabilities.HonouredSet())
		if kinds.Empty() {
			continue
		}
		prepared = append(prepared, preparedSubscriptionBinding{
			request:  request,
			prepared: result,
			kinds:    kinds,
		})
		honoured = unionHonouredSets(honoured, kinds)
	}
	return prepared, honoured, nil
}

func unionHonouredSets(left, right HonouredSet) HonouredSet {
	kinds := append(left.Kinds(), right.Kinds()...)
	return NewHonouredSet(kinds...)
}

func (m *SubscriptionMultiplexer) reserveListenersLocked(
	bindings []preparedSubscriptionBinding,
	reservation *subscriptionAttachReservation,
) ([]*subscriptionListener, []*subscriptionListener, error) {
	newByKey := make(map[SubscriptionSourceKey]*subscriptionListener)
	reused := make(map[SubscriptionSourceKey]struct{})
	newListeners := make([]*subscriptionListener, 0, len(bindings))
	listeners := make([]*subscriptionListener, 0, len(bindings))
	addedPerOrigin := make(map[[32]byte]int)
	for _, binding := range bindings {
		key := binding.prepared.Key
		if existing, exists := m.pool[key]; exists {
			if existing.stopping {
				return nil, nil, ErrSubscriptionTerminal
			}
			if existing.committed {
				if _, recorded := reused[key]; !recorded {
					m.recordLifecycle(m.rootCtx, subscriptionSourceLifecycleReused)
					reused[key] = struct{}{}
				}
			}
			listeners = append(listeners, existing)
			continue
		}
		if _, exists := newByKey[key]; exists {
			continue
		}
		if m.live+len(newListeners)+1 > m.options.MaxListeners ||
			m.origins[key.OriginDigest]+addedPerOrigin[key.OriginDigest]+1 > m.options.MaxPerOrigin {
			return nil, nil, ErrSubscriptionListenerCapacity
		}
		listenerCtx, cancel := context.WithCancel(m.rootCtx)
		listener := &subscriptionListener{
			mux:      m,
			key:      key,
			target:   cloneSubscriptionTarget(binding.request.Target),
			prepared: binding.prepared,
			ctx:      listenerCtx,
			cancel:   cancel,
			done:     make(chan struct{}),
			ready:    make(chan struct{}),
			reserved: reservation,
			bindings: make(map[*subscriptionHandle][]subscriptionListenerBinding),
			joining:  make(map[*subscriptionHandle]struct{}),
		}
		newByKey[key] = listener
		newListeners = append(newListeners, listener)
		listeners = append(listeners, listener)
		addedPerOrigin[key.OriginDigest]++
	}
	for _, listener := range newListeners {
		m.pool[listener.key] = listener
		m.live++
		m.origins[listener.key.OriginDigest]++
	}
	return newListeners, listeners, nil
}

func (m *SubscriptionMultiplexer) openReservedListeners(
	attachCtx context.Context,
	listeners []*subscriptionListener,
) error {
	opened := make([]SubscriptionStream, 0, len(listeners))
	for _, listener := range listeners {
		stopAttach := context.AfterFunc(attachCtx, listener.cancel)
		stream, err := m.connector.Open(listener.ctx, listener.target, listener.prepared)
		stopped := stopAttach()
		if err == nil && (!stopped || listener.ctx.Err() != nil) {
			if stream != nil {
				stream.Close()
			}
			err = attachCtx.Err()
		}
		if err != nil {
			for _, openedStream := range opened {
				openedStream.Close()
			}
			m.recordLifecycle(attachCtx, subscriptionSourceLifecycleOpenFailed)
			return fmt.Errorf("mcp: open subscription source: %w", err)
		}
		if stream == nil {
			for _, openedStream := range opened {
				openedStream.Close()
			}
			m.recordLifecycle(attachCtx, subscriptionSourceLifecycleOpenFailed)
			return fmt.Errorf("%w: connector returned a nil stream", ErrSubscriptionProtocol)
		}
		if !stream.Acknowledged().Equal(listener.prepared.Capabilities) {
			stream.Close()
			for _, openedStream := range opened {
				openedStream.Close()
			}
			m.recordLifecycle(attachCtx, subscriptionSourceLifecycleOpenFailed)
			return ErrSubscriptionSourceChanged
		}
		listener.initial = stream
		opened = append(opened, stream)
	}
	return nil
}

func waitForReservedListeners(
	ctx context.Context,
	listeners []*subscriptionListener,
	owned []*subscriptionListener,
) error {
	ownedSet := make(map[*subscriptionListener]struct{}, len(owned))
	for _, listener := range owned {
		ownedSet[listener] = struct{}{}
	}
	for _, listener := range listeners {
		if _, ok := ownedSet[listener]; ok {
			continue
		}
		select {
		case <-listener.ready:
			if listener.openErr != nil {
				return listener.openErr
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (m *SubscriptionMultiplexer) rollbackReservedListeners(
	listeners []*subscriptionListener,
	openErr error,
) {
	streams := make([]SubscriptionStream, 0, len(listeners))
	m.mu.Lock()
	for _, listener := range listeners {
		if listener.initial != nil {
			streams = append(streams, listener.initial)
			listener.initial = nil
		}
		listener.openErr = openErr
		if current := m.pool[listener.key]; current == listener {
			delete(m.pool, listener.key)
			m.releaseListenerSlotLocked(listener)
		}
		listener.readyOnce.Do(func() { close(listener.ready) })
	}
	m.mu.Unlock()
	for _, listener := range listeners {
		listener.cancel()
	}
	for _, stream := range streams {
		stream.Close()
	}
}

func (m *SubscriptionMultiplexer) supervise(listener *subscriptionListener) {
	sourceCtx := context.WithoutCancel(listener.ctx)
	m.recordListenerLive(sourceCtx, 1)
	m.recordLifecycle(sourceCtx, subscriptionSourceLifecycleOpened)
	defer m.wg.Done()
	defer func() {
		m.finishListener(listener)
		m.recordLifecycle(sourceCtx, subscriptionSourceLifecycleJoined)
		m.recordListenerLive(sourceCtx, -1)
	}()

	stream := listener.initial
	listener.initial = nil
	attempts := 0
	terminal := subscriptionSourceTerminalTransportFailure
	defer func() { m.recordTerminal(sourceCtx, terminal) }()
	for {
		if stream == nil {
			terminal = subscriptionSourceTerminalProtocolFailure
			m.terminateListenerBindings(listener, ErrSubscriptionProtocol)
			return
		}
		validEvent, err := m.readSubscriptionStream(listener, stream)
		if stream != nil {
			stream.Close()
		}
		if validEvent {
			attempts = 0
		}
		if listener.ctx.Err() != nil {
			terminal = m.listenerTerminal(listener)
			m.terminateListenerBindings(listener, ErrSubscriptionTerminal)
			return
		}
		if !IsSubscriptionReconnectable(err) {
			terminal = subscriptionSourceTerminalOutcome(err)
			m.terminateListenerBindings(listener, err)
			return
		}
		var reconnectErr error
		stream, attempts, reconnectErr = m.reconnect(listener, attempts)
		if reconnectErr != nil {
			terminal = subscriptionSourceTerminalOutcome(reconnectErr)
			if listener.ctx.Err() == nil {
				m.terminateListenerBindings(listener, reconnectErr)
			}
			return
		}
	}
}

func (m *SubscriptionMultiplexer) readSubscriptionStream(
	listener *subscriptionListener,
	stream SubscriptionStream,
) (bool, error) {
	validEvent := false
	for {
		event, err := stream.Next(listener.ctx)
		if err != nil {
			return validEvent, err
		}
		validEvent = true
		m.fanOut(listener, event)
		if listener.ctx.Err() != nil {
			return validEvent, listener.ctx.Err()
		}
	}
}

func (m *SubscriptionMultiplexer) reconnect(
	listener *subscriptionListener,
	attempts int,
) (SubscriptionStream, int, error) {
	for {
		if attempts >= m.options.ReconnectAttempts {
			m.recordReconnect(listener.ctx, subscriptionSourceReconnectExhausted)
			return nil, attempts, ErrSubscriptionReconnectExhausted
		}
		attempts++
		m.recordReconnect(listener.ctx, subscriptionSourceReconnectAttempted)
		delay := m.options.Jitter(m.reconnectDelay(attempts))
		if delay < 0 {
			delay = 0
		}
		if delay > m.options.ReconnectBackoffMax {
			delay = m.options.ReconnectBackoffMax
		}
		if err := m.options.Waiter.Wait(listener.ctx, delay); err != nil {
			m.recordReconnect(listener.ctx, subscriptionSourceReconnectCancelled)
			return nil, attempts, err
		}
		fresh, prepared, err := m.refreshReconnectBindings(listener)
		if err != nil {
			if IsSubscriptionReconnectable(err) && listener.ctx.Err() == nil {
				m.recordReconnect(listener.ctx, subscriptionSourceReconnectFailed)
				continue
			}
			m.recordReconnect(listener.ctx, subscriptionSourceReconnectTerminal)
			return nil, attempts, err
		}
		stream, err := m.connector.Open(listener.ctx, fresh.Target, prepared)
		if err != nil {
			if IsSubscriptionReconnectable(err) {
				m.recordReconnect(listener.ctx, subscriptionSourceReconnectFailed)
				continue
			}
			m.recordReconnect(listener.ctx, subscriptionSourceReconnectTerminal)
			return nil, attempts, err
		}
		if stream == nil {
			m.recordReconnect(listener.ctx, subscriptionSourceReconnectTerminal)
			return nil, attempts, fmt.Errorf("%w: connector returned a nil stream", ErrSubscriptionProtocol)
		}
		if !stream.Acknowledged().Equal(listener.prepared.Capabilities) {
			stream.Close()
			m.recordReconnect(listener.ctx, subscriptionSourceReconnectSourceChanged)
			return nil, attempts, ErrSubscriptionSourceChanged
		}
		m.mu.Lock()
		clearTargetHeaders(&listener.target)
		listener.target = cloneSubscriptionTarget(fresh.Target)
		m.mu.Unlock()
		m.recordReconnect(listener.ctx, subscriptionSourceReconnectSucceeded)
		return stream, attempts, nil
	}
}

type reconnectHandleBindings struct {
	handle   *subscriptionHandle
	bindings []subscriptionListenerBinding
}

func (m *SubscriptionMultiplexer) refreshReconnectBindings(
	listener *subscriptionListener,
) (SubscriptionRequest, PreparedSubscription, error) {
	if m.options.Refresher == nil {
		return SubscriptionRequest{}, PreparedSubscription{}, ErrSubscriptionSourceChanged
	}
	m.mu.Lock()
	snapshot := make([]reconnectHandleBindings, 0, len(listener.bindings))
	for handle, bindings := range listener.bindings {
		snapshot = append(snapshot, reconnectHandleBindings{
			handle:   handle,
			bindings: append([]subscriptionListenerBinding(nil), bindings...),
		})
	}
	m.mu.Unlock()
	sort.Slice(snapshot, func(i, j int) bool {
		return reconnectBindingSortKey(snapshot[i].bindings) <
			reconnectBindingSortKey(snapshot[j].bindings)
	})

	var (
		candidate         SubscriptionRequest
		candidatePrepared PreparedSubscription
		found             bool
		lastTerminal      = ErrSubscriptionSourceChanged
	)
	for _, current := range snapshot {
		valid := true
		terminalErr := ErrSubscriptionSourceChanged
		var currentRequest SubscriptionRequest
		var currentPrepared PreparedSubscription
		for _, binding := range current.bindings {
			bindingCtx := subscriptionBindingContext{
				Context: listener.ctx,
				values:  binding.authorizationContext,
			}
			if err := m.authorizeReconnectBinding(listener, binding); err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					valid = false
					terminalErr = ErrSubscriptionTerminal
				} else if errors.Is(err, ErrSubscriptionRevoked) ||
					errors.Is(err, ErrSubscriptionSourceChanged) ||
					errors.Is(err, ErrSubscriptionAuthentication) {
					valid = false
					terminalErr = err
				} else {
					return SubscriptionRequest{}, PreparedSubscription{}, ErrSubscriptionTransportClosed
				}
			}
			if !valid {
				break
			}
			fresh, err := m.options.Refresher.Refresh(bindingCtx, binding.request)
			if err != nil {
				if errors.Is(err, ErrSubscriptionRevoked) ||
					errors.Is(err, ErrSubscriptionSourceChanged) ||
					errors.Is(err, ErrSubscriptionAuthentication) {
					valid = false
					terminalErr = err
					break
				}
				return SubscriptionRequest{}, PreparedSubscription{}, ErrSubscriptionTransportClosed
			}
			prepared, err := m.connector.Prepare(bindingCtx, fresh.Target)
			if err != nil {
				if IsSubscriptionReconnectable(err) {
					return SubscriptionRequest{}, PreparedSubscription{}, err
				}
				if errors.Is(err, ErrSubscriptionSourceChanged) ||
					errors.Is(err, ErrSubscriptionAuthentication) ||
					errors.Is(err, ErrSubscriptionUnsupported) {
					valid = false
					terminalErr = err
					break
				}
				return SubscriptionRequest{}, PreparedSubscription{}, err
			}
			if prepared.Key != listener.key ||
				!prepared.Capabilities.Equal(listener.prepared.Capabilities) {
				valid = false
				terminalErr = ErrSubscriptionSourceChanged
				break
			}
			if currentRequest.Identity.RegistryID == "" {
				currentRequest = fresh
				currentPrepared = prepared
			}
		}
		if !valid {
			lastTerminal = terminalErr
			m.terminateHandle(current.handle, terminalErr, false)
			continue
		}
		if !found && currentRequest.Identity.RegistryID != "" {
			candidate = currentRequest
			candidatePrepared = currentPrepared
			found = true
		}
	}
	if !found {
		return SubscriptionRequest{}, PreparedSubscription{}, lastTerminal
	}
	return candidate, candidatePrepared, nil
}

func (m *SubscriptionMultiplexer) authorizeReconnectBinding(
	listener *subscriptionListener,
	binding subscriptionListenerBinding,
) error {
	ctx, cancel := context.WithTimeout(listener.ctx, m.options.AuthorizationTimeout)
	defer cancel()
	bindingCtx := subscriptionBindingContext{
		Context: ctx,
		values:  binding.authorizationContext,
	}
	for _, kind := range binding.requested.Kinds() {
		allowed, err := m.authorize(bindingCtx, binding.identity, listener.key, kind)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !allowed {
			return ErrSubscriptionRevoked
		}
	}
	return nil
}

func reconnectBindingSortKey(bindings []subscriptionListenerBinding) string {
	if len(bindings) == 0 {
		return ""
	}
	identity := bindings[0].identity
	return identity.GatewayID + "\x00" +
		identity.ConsumerID + "\x00" +
		identity.PrincipalFingerprint + "\x00" +
		identity.AuthID + "\x00" +
		identity.RegistryID + "\x00" +
		identity.RoleScopeFingerprint
}

func (m *SubscriptionMultiplexer) reconnectDelay(attempt int) time.Duration {
	delay := m.options.ReconnectBackoffMin
	for current := 1; current < attempt && delay < m.options.ReconnectBackoffMax; current++ {
		if delay > m.options.ReconnectBackoffMax/2 {
			return m.options.ReconnectBackoffMax
		}
		delay *= 2
	}
	if delay > m.options.ReconnectBackoffMax {
		return m.options.ReconnectBackoffMax
	}
	return delay
}

func (m *SubscriptionMultiplexer) fanOut(listener *subscriptionListener, event SubscriptionEvent) {
	if !listener.prepared.Capabilities.HonouredSet().Has(event.Kind) {
		m.recordFanOut(listener.ctx, event.Kind, subscriptionSourceFanOutRejected)
		return
	}
	m.mu.Lock()
	snapshot := make(map[*subscriptionHandle][]subscriptionListenerBinding, len(listener.bindings))
	for handle, bindings := range listener.bindings {
		snapshot[handle] = append([]subscriptionListenerBinding(nil), bindings...)
	}
	m.mu.Unlock()

	for handle, bindings := range snapshot {
		requested := false
		for _, binding := range bindings {
			if binding.requested.Has(event.Kind) {
				requested = true
				break
			}
		}
		if !requested {
			m.recordFanOut(listener.ctx, event.Kind, subscriptionSourceFanOutDenied)
			continue
		}
		work := subscriptionAuthorizationWork{
			listener: listener,
			event:    event,
			bindings: bindings,
		}
		select {
		case handle.admission <- struct{}{}:
		default:
			m.recordQueue(listener.ctx, event.Kind, subscriptionSourceQueueFull)
			m.terminateHandle(handle, ErrSubscriptionSlowConsumer, false)
			continue
		}
		accepted, running := handle.tryEnqueueAuthorizationWork(work)
		if accepted {
			continue
		}
		handle.releaseAdmission()
		if running {
			m.recordQueue(listener.ctx, event.Kind, subscriptionSourceQueueFull)
			m.terminateHandle(handle, ErrSubscriptionSlowConsumer, false)
		}
	}
}

func (m *SubscriptionMultiplexer) runAuthorizationWorker(handle *subscriptionHandle) {
	defer close(handle.workerDone)
	defer handle.stopAuthorizationWorker()
	for {
		select {
		case <-handle.workerCtx.Done():
			return
		case work := <-handle.work:
			allowed, err := m.authorizeWork(handle.workerCtx, work)
			if err != nil {
				handle.releaseAdmission()
				if errors.Is(err, ErrSubscriptionRevoked) ||
					errors.Is(err, ErrSubscriptionSourceChanged) {
					m.recordFanOut(work.listener.ctx, work.event.Kind, subscriptionSourceFanOutRevoked)
					m.terminateHandle(handle, err, false)
					return
				}
				m.recordFanOut(work.listener.ctx, work.event.Kind, subscriptionSourceFanOutTransient)
				if handle.recordWorkerTransientFailure() {
					m.terminateHandle(handle, ErrSubscriptionTerminal, false)
					return
				}
				continue
			}
			handle.resetWorkerTransientFailures()
			if !allowed {
				handle.releaseAdmission()
				m.recordFanOut(work.listener.ctx, work.event.Kind, subscriptionSourceFanOutRevoked)
				m.terminateHandle(handle, ErrSubscriptionRevoked, false)
				return
			}
			m.recordFanOut(work.listener.ctx, work.event.Kind, subscriptionSourceFanOutAuthorized)
			work.event.Source = work.listener.key
			select {
			case handle.events <- work.event:
				handle.releaseAdmission()
				m.recordQueue(work.listener.ctx, work.event.Kind, subscriptionSourceQueueEnqueued)
			case <-handle.workerCtx.Done():
				handle.releaseAdmission()
				return
			}
		}
	}
}

func (m *SubscriptionMultiplexer) authorizeWork(
	ctx context.Context,
	work subscriptionAuthorizationWork,
) (bool, error) {
	authorizationCtx, cancel := context.WithTimeout(ctx, m.options.AuthorizationTimeout)
	defer cancel()
	matched := false
	for _, binding := range work.bindings {
		if !binding.requested.Has(work.event.Kind) {
			continue
		}
		matched = true
		bindingCtx := subscriptionBindingContext{
			Context: authorizationCtx,
			values:  binding.authorizationContext,
		}
		ok, err := m.authorize(bindingCtx, binding.identity, work.listener.key, work.event.Kind)
		if err != nil || !ok {
			return false, err
		}
	}
	return matched, nil
}

func (h *subscriptionHandle) releaseAdmission() {
	<-h.admission
}

func (h *subscriptionHandle) tryEnqueueAuthorizationWork(
	work subscriptionAuthorizationWork,
) (bool, bool) {
	h.workMu.Lock()
	defer h.workMu.Unlock()
	if h.workerStopped {
		return false, false
	}
	select {
	case h.work <- work:
		return true, true
	default:
		return false, true
	}
}

func (h *subscriptionHandle) stopAuthorizationWorker() {
	h.workMu.Lock()
	defer h.workMu.Unlock()
	h.workerStopped = true
	for {
		select {
		case <-h.work:
			h.releaseAdmission()
		default:
			return
		}
	}
}

func (h *subscriptionHandle) recordWorkerTransientFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.workerTransientFailures++
	return h.workerTransientFailures >= maxTransientAuthorizationFailures
}

func (h *subscriptionHandle) resetWorkerTransientFailures() {
	h.mu.Lock()
	h.workerTransientFailures = 0
	h.mu.Unlock()
}

func (h *subscriptionHandle) recordEmitTransientFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emitTransientFailures++
	return h.emitTransientFailures >= maxTransientAuthorizationFailures
}

func (h *subscriptionHandle) resetEmitTransientFailures() {
	h.mu.Lock()
	h.emitTransientFailures = 0
	h.mu.Unlock()
}

func (m *SubscriptionMultiplexer) terminateListenerBindings(
	listener *subscriptionListener,
	err error,
) {
	m.mu.Lock()
	listener.stopping = true
	listener.cancel()
	handles := make([]*subscriptionHandle, 0, len(listener.bindings))
	for handle := range listener.bindings {
		handles = append(handles, handle)
	}
	m.mu.Unlock()
	for _, handle := range handles {
		m.terminateHandle(handle, err, false)
	}
}

func (m *SubscriptionMultiplexer) terminateHandle(
	handle *subscriptionHandle,
	err error,
	wait bool,
) {
	handle.mu.Lock()
	if !handle.terminal {
		handle.terminal = true
		handle.err = err
	}
	handle.mu.Unlock()
	handle.cancelWorker()
	waitFor := m.detachHandle(handle)
	handle.completionOnce.Do(func() {
		go func() {
			defer handle.finishLifecycle()
			<-handle.workerDone
			for _, listener := range waitFor {
				<-listener.done
			}
			handle.signalDone()
		}()
	})
	if wait {
		<-handle.done
	}
}

func (m *SubscriptionMultiplexer) detachHandle(
	handle *subscriptionHandle,
) []*subscriptionListener {
	m.attachMu.Lock()
	m.mu.Lock()
	waitFor := make([]*subscriptionListener, 0, len(handle.listeners))
	for listener := range handle.listeners {
		bindings := listener.bindings[handle]
		for i := range bindings {
			clearTargetHeaders(&bindings[i].request.Target)
		}
		delete(listener.bindings, handle)
		if len(listener.bindings) == 0 || listener.stopping {
			listener.stopping = true
			if listener.terminal == "" {
				listener.terminal = subscriptionSourceTerminalLastDetach
			}
			listener.cancel()
			listener.joining[handle] = struct{}{}
			waitFor = append(waitFor, listener)
			continue
		}
		delete(handle.listeners, listener)
	}
	m.mu.Unlock()
	m.attachMu.Unlock()
	return waitFor
}

func (m *SubscriptionMultiplexer) finishListener(listener *subscriptionListener) {
	m.mu.Lock()
	for handle, bindings := range listener.bindings {
		for i := range bindings {
			clearTargetHeaders(&bindings[i].request.Target)
		}
		delete(handle.listeners, listener)
	}
	for handle := range listener.joining {
		delete(handle.listeners, listener)
	}
	listener.bindings = nil
	listener.joining = nil
	clearTargetHeaders(&listener.target)
	if current := m.pool[listener.key]; current == listener {
		delete(m.pool, listener.key)
		m.releaseListenerSlotLocked(listener)
	}
	close(listener.done)
	m.mu.Unlock()
}

func clearTargetHeaders(target *Target) {
	if target == nil {
		return
	}
	clear(target.Headers)
	target.Headers = nil
}

func cloneSubscriptionRequest(request SubscriptionRequest) SubscriptionRequest {
	request.Target = cloneSubscriptionTarget(request.Target)
	return request
}

func cloneSubscriptionTarget(target Target) Target {
	if target.Headers == nil {
		return target
	}
	headers := make(map[string]string, len(target.Headers))
	for name, value := range target.Headers {
		headers[name] = value
	}
	target.Headers = headers
	return target
}

func (m *SubscriptionMultiplexer) releaseListenerSlotLocked(listener *subscriptionListener) {
	m.live--
	origin := listener.key.OriginDigest
	m.origins[origin]--
	if m.origins[origin] == 0 {
		delete(m.origins, origin)
	}
}

// Close cancels and joins every listener or returns when ctx expires.
func (m *SubscriptionMultiplexer) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	m.rootCancel()
	m.mu.Unlock()
	if err := waitForWaitGroup(ctx, &m.attachWG); err != nil {
		return err
	}

	m.attachMu.Lock()
	m.mu.Lock()
	listeners := make([]*subscriptionListener, 0, len(m.pool))
	handles := make(map[*subscriptionHandle]struct{})
	for _, listener := range m.pool {
		if listener.started {
			listeners = append(listeners, listener)
		}
		for handle := range listener.bindings {
			handles[handle] = struct{}{}
		}
		for handle := range listener.joining {
			handles[handle] = struct{}{}
		}
	}
	for handle := range handles {
		handle.mu.Lock()
		if !handle.terminal {
			handle.terminal = true
			handle.err = ErrSubscriptionTerminal
		}
		handle.mu.Unlock()
		handle.cancelWorker()
	}
	for _, listener := range listeners {
		if listener.terminal == "" {
			listener.terminal = subscriptionSourceTerminalShutdown
		}
		listener.cancel()
	}
	m.mu.Unlock()
	m.attachMu.Unlock()

	for _, listener := range listeners {
		select {
		case <-listener.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for handle := range handles {
		select {
		case <-handle.workerDone:
			handle.signalDone()
			handle.finishLifecycle()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return waitForWaitGroup(ctx, &m.handleWG)
}

func waitForWaitGroup(ctx context.Context, group *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *subscriptionHandle) Events() <-chan SubscriptionEvent {
	return h.events
}

func (h *subscriptionHandle) Done() <-chan struct{} {
	return h.done
}

func (h *subscriptionHandle) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

func (h *subscriptionHandle) Authorize(ctx context.Context, event SubscriptionEvent) error {
	h.mux.mu.Lock()
	listener := h.mux.pool[event.Source]
	if listener == nil {
		h.mux.mu.Unlock()
		return ErrSubscriptionRevoked
	}
	bindings := append([]subscriptionListenerBinding(nil), listener.bindings[h]...)
	h.mux.mu.Unlock()
	if len(bindings) == 0 {
		return ErrSubscriptionRevoked
	}
	allowed, err := h.mux.authorizeWork(ctx, subscriptionAuthorizationWork{
		listener: listener,
		event:    event,
		bindings: bindings,
	})
	if err != nil {
		if errors.Is(err, ErrSubscriptionRevoked) ||
			errors.Is(err, ErrSubscriptionSourceChanged) {
			h.mux.terminateHandle(h, err, false)
			return err
		}
		if h.recordEmitTransientFailure() {
			h.mux.terminateHandle(h, ErrSubscriptionTerminal, false)
			return ErrSubscriptionTerminal
		}
		return err
	}
	h.resetEmitTransientFailures()
	if !allowed {
		h.mux.terminateHandle(h, ErrSubscriptionRevoked, false)
		return ErrSubscriptionRevoked
	}
	return nil
}

func (h *subscriptionHandle) Close() {
	h.mux.terminateHandle(h, h.Err(), true)
}

func (h *subscriptionHandle) signalDone() {
	h.doneOnce.Do(func() { close(h.done) })
}

func (h *subscriptionHandle) finishLifecycle() {
	h.lifecycleOnce.Do(func() { h.mux.handleWG.Done() })
}

func (m *SubscriptionMultiplexer) listenerTerminal(listener *subscriptionListener) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if listener.terminal != "" {
		return listener.terminal
	}
	return subscriptionSourceTerminalShutdown
}

func subscriptionSourceTerminalOutcome(err error) string {
	switch {
	case errors.Is(err, ErrSubscriptionReconnectExhausted):
		return subscriptionSourceTerminalReconnectExhausted
	case errors.Is(err, ErrSubscriptionSourceChanged):
		return subscriptionSourceTerminalSourceChanged
	case errors.Is(err, ErrSubscriptionAuthentication):
		return subscriptionSourceTerminalAuthentication
	case errors.Is(err, ErrSubscriptionProtocol):
		return subscriptionSourceTerminalProtocolFailure
	default:
		return subscriptionSourceTerminalTransportFailure
	}
}

func (m *SubscriptionMultiplexer) recordListenerLive(ctx context.Context, delta int64) {
	if m.options.Recorder != nil {
		m.options.Recorder.ListenerLive(ctx, delta)
	}
}

func (m *SubscriptionMultiplexer) recordLifecycle(ctx context.Context, outcome string) {
	if m.options.Recorder != nil {
		m.options.Recorder.Lifecycle(ctx, outcome)
	}
}

func (m *SubscriptionMultiplexer) recordFanOut(
	ctx context.Context,
	kind NotificationKind,
	outcome string,
) {
	if m.options.Recorder != nil {
		m.options.Recorder.FanOut(ctx, kind, outcome)
	}
}

func (m *SubscriptionMultiplexer) recordReconnect(ctx context.Context, outcome string) {
	if m.options.Recorder != nil {
		m.options.Recorder.Reconnect(ctx, outcome)
	}
}

func (m *SubscriptionMultiplexer) recordQueue(
	ctx context.Context,
	kind NotificationKind,
	outcome string,
) {
	if m.options.Recorder != nil {
		m.options.Recorder.Queue(ctx, kind, outcome)
	}
}

func (m *SubscriptionMultiplexer) recordTerminal(ctx context.Context, outcome string) {
	if m.options.Recorder != nil {
		m.options.Recorder.Terminal(ctx, outcome)
	}
}

type subscriptionBindingContext struct {
	context.Context
	values context.Context
}

func (c subscriptionBindingContext) Value(key any) any {
	if value := c.values.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}
