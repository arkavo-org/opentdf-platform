package jev

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestObserveWithoutCollectorIsNoop(t *testing.T) {
	assert.NotPanics(t, func() {
		Observe(context.Background(), Observation{Seam: "obligations"})
	})
	assert.Nil(t, Observations(context.Background()))
}

func TestCollectAccumulatesObservations(t *testing.T) {
	ctx := Collect(context.Background())

	Observe(ctx, Observation{Seam: "obligations", Applied: true})
	Observe(ctx, Observation{Seam: "ers_claims", Applied: false})

	got := Observations(ctx)
	assert.Len(t, got, 2)
	assert.Equal(t, "obligations", got[0].Seam)
}

func TestCollectIsIdempotent(t *testing.T) {
	ctx := Collect(context.Background())
	Observe(ctx, Observation{Seam: "a"})

	// Re-collecting must not discard what is already recorded.
	again := Collect(ctx)
	assert.Len(t, Observations(again), 1)
}

func TestObserveIsConcurrencySafe(t *testing.T) {
	ctx := Collect(context.Background())

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Observe(ctx, Observation{Seam: "obligations", Question: string(rune('a' + i%26))})
		}()
	}
	wg.Wait()

	assert.Len(t, Observations(ctx), 50)
}
