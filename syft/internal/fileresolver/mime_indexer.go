package fileresolver

import (
	"os"
	"runtime"
	"sync"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/internal/windows"
)

type mimeJob struct {
	ref  file.Reference
	path string
}

// mimeIndexer asynchronously computes MIME types for file references and updates the shared file index.
// This is used to overlap directory walking with MIME detection, which otherwise requires serial file opens/reads.
type mimeIndexer struct {
	index filetree.Index

	jobs chan mimeJob
	wg   sync.WaitGroup
}

func defaultMIMEWorkerCount() int {
	// MIME detection is mostly IO-bound (open + read small header), so allow a bit more than GOMAXPROCS.
	n := runtime.GOMAXPROCS(0) * 2
	if n < 4 {
		return 4
	}
	if n > 64 {
		return 64
	}
	return n
}

func defaultMIMEQueueSize() int {
	// Small buffer to allow walkers to get ahead without unbounded memory growth.
	return 4096
}

func newMimeIndexer(index filetree.Index, workers, queueSize int) *mimeIndexer {
	if workers <= 0 {
		workers = 1
	}
	if queueSize <= 0 {
		queueSize = 1
	}

	m := &mimeIndexer{
		index: index,
		jobs:  make(chan mimeJob, queueSize),
	}

	for i := 0; i < workers; i++ {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for job := range m.jobs {
				m.process(job)
			}
		}()
	}

	return m
}

func (m *mimeIndexer) Enqueue(ref file.Reference, path string) {
	// Block when the queue is full to provide backpressure and avoid unbounded memory usage.
	m.jobs <- mimeJob{ref: ref, path: path}
}

func (m *mimeIndexer) CloseAndWait() {
	close(m.jobs)
	m.wg.Wait()
}

func (m *mimeIndexer) process(job mimeJob) {
	entry, err := m.index.Get(job.ref)
	if err != nil {
		return
	}
	if entry.Metadata.MIMEType != "" {
		// Already set (or updated by another run); skip.
		return
	}

	usablePath := job.path
	if windows.HostRunningOnWindows() {
		usablePath = windows.FromPosix(usablePath)
	}

	f, err := os.Open(usablePath)
	if err != nil {
		// Inaccessible files are not fatal for indexing; keep MIME empty.
		return
	}
	defer internal.CloseAndLogError(f, usablePath)

	mimeType := file.MIMEType(f)
	if mimeType == "" {
		return
	}

	md := entry.Metadata
	md.MIMEType = mimeType

	// Index has no explicit update API; Add() overwrites the entry and will also populate the byMIMEType map.
	m.index.Add(job.ref, md)
}
