//go:build race

package storage_test

// raceDetectorEnabled is true when the test binary was built with -race.
// The instrumentation it adds is heavy enough to blow past a wall-clock
// performance budget on its own, unrelated to any real regression -- see
// TestMigrateTrafficSamplesToMetricSamplesAtProductionScale.
const raceDetectorEnabled = true
