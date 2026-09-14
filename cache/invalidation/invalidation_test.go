package invalidation

import (
	"context"
	"testing"
	"time"
)

func TestInProcessBus_PublishFansOutToSubscribers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInProcessBus()

	ch1, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe 1 failed: %v", err)
	}
	ch2, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe 2 failed: %v", err)
	}

	if err := bus.Publish(ctx, "perm:user_1"); err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	for i, ch := range []<-chan string{ch1, ch2} {
		select {
		case got := <-ch:
			if got != "perm:user_1" {
				t.Errorf("subscriber %d: expected key perm:user_1, got %q", i, got)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for published key", i)
		}
	}
}

func TestInProcessBus_SubscribeClosesOnContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bus := NewInProcessBus()

	ch, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe failed: %v", err)
	}

	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel to be closed after context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for channel to close")
	}
}

func TestInProcessBus_PublishWithNoSubscribersDoesNotBlock(t *testing.T) {
	bus := NewInProcessBus()
	if err := bus.Publish(context.Background(), "no-subscribers"); err != nil {
		t.Fatalf("expected no error publishing with no subscribers, got %v", err)
	}
}
