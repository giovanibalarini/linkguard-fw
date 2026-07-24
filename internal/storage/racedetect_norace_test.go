//go:build !race

package storage_test

// raceDetectorEnabled is false in a normal (non -race) test build. See
// racedetect_race_test.go.
const raceDetectorEnabled = false
