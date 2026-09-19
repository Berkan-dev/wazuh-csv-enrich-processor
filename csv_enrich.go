// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Package csv_enrich implements a libbeat processor that enriches events by
// looking up a field's value in a CSV file and copying matching columns
// onto the event. This file targets the libbeat API at elastic/beats tag
// v7.10.2 -- see the note in config.go for why that specific version, and
// verify import paths/symbols against your own v7.10.2 checkout before
// building, since I ported this from reference rather than compiling it
// against the real module graph.
package csv_enrich

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/processors"
)

const processorName = "csv_enrich"

func init() {
	processors.RegisterPlugin(processorName, New)
}

// csvEnrich is a libbeat processor that enriches events from a CSV lookup
// table, with the CSV file reloaded from disk on a poll interval so that
// edits take effect without restarting Filebeat.
type csvEnrich struct {
	config config
	log    *logp.Logger

	mu      sync.RWMutex
	table   map[string]map[string]string
	modTime time.Time

	done     chan struct{}
	closeErr sync.Once
}

// New constructs a csv_enrich processor from the given configuration.
// Signature matches processors.Constructor for v7.10.2:
// func(*common.Config) (processors.Processor, error).
func New(cfg *common.Config) (processors.Processor, error) {
	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("fail to unpack %s config: %w", processorName, err)
	}

	p := &csvEnrich{
		config: c,
		log:    logp.NewLogger(processorName),
		done:   make(chan struct{}),
	}

	if err := p.load(); err != nil {
		return nil, fmt.Errorf("%s: initial load of %q failed: %w", processorName, c.File, err)
	}

	if c.ReloadInterval > 0 {
		go p.watch()
	}

	return p, nil
}

func (p *csvEnrich) load() error {
	info, err := os.Stat(p.config.File)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	f, err := os.Open(p.config.File)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return fmt.Errorf("reading header row: %w", err)
	}

	colIdx := make(map[string]int, len(headers))
	for i, h := range headers {
		colIdx[strings.TrimSpace(h)] = i
	}

	if _, ok := colIdx[p.config.LookupField]; !ok {
		return fmt.Errorf("lookup_field %q not found in CSV headers %v", p.config.LookupField, headers)
	}
	for _, field := range p.config.Fields {
		if _, ok := colIdx[field]; !ok {
			return fmt.Errorf("field %q not found in CSV headers %v", field, headers)
		}
	}

	table := make(map[string]map[string]string)
	lookupIdx := colIdx[p.config.LookupField]
	rowNum := 1
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading row %d: %w", rowNum+1, err)
		}
		rowNum++

		key := record[lookupIdx]
		if p.config.IgnoreCase {
			key = strings.ToUpper(key)
		}

		row := make(map[string]string, len(p.config.Fields))
		for _, field := range p.config.Fields {
			row[field] = record[colIdx[field]]
		}
		table[key] = row
	}

	p.mu.Lock()
	p.table = table
	p.modTime = info.ModTime()
	p.mu.Unlock()

	p.log.Infof("loaded %d entries from %s", len(table), p.config.File)
	return nil
}

func (p *csvEnrich) watch() {
	ticker := time.NewTicker(p.config.ReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			info, err := os.Stat(p.config.File)
			if err != nil {
				p.log.Warnf("could not stat %s: %v", p.config.File, err)
				continue
			}

			p.mu.RLock()
			changed := info.ModTime().After(p.modTime)
			p.mu.RUnlock()

			if changed {
				if err := p.load(); err != nil {
					p.log.Warnf("reload of %s failed, keeping previous table: %v", p.config.File, err)
				}
			}
		}
	}
}

// Run implements processors.Processor (v7.10.2). event.GetValue/PutValue are
// available on *beat.Event in this version, backed by common.MapStr.
func (p *csvEnrich) Run(event *beat.Event) (*beat.Event, error) {
	v, err := event.GetValue(p.config.KeyField)
	if err != nil {
		if p.config.IgnoreMissing {
			return event, nil
		}
		return event, fmt.Errorf("%s: key_field %q not found: %w", processorName, p.config.KeyField, err)
	}

	key, ok := v.(string)
	if !ok {
		return event, nil
	}
	if p.config.IgnoreCase {
		key = strings.ToUpper(key)
	}

	p.mu.RLock()
	row, found := p.table[key]
	p.mu.RUnlock()

	if !found {
		return event, nil
	}

	for _, field := range p.config.Fields {
		target := field
		if p.config.TargetPrefix != "" {
			target = p.config.TargetPrefix + "." + field
		}

		if !p.config.OverwriteKeys {
			if _, err := event.GetValue(target); err == nil {
				continue
			}
		}

		if _, err := event.PutValue(target, row[field]); err != nil {
			return event, fmt.Errorf("%s: failed to set field %q: %w", processorName, target, err)
		}
	}

	return event, nil
}

// Close implements processors.Closer so the framework stops the file
// watcher goroutine during shutdown/reload.
func (p *csvEnrich) Close() error {
	p.closeErr.Do(func() {
		close(p.done)
	})
	return nil
}

func (p *csvEnrich) String() string {
	return fmt.Sprintf("%s=[file=%s, key_field=%s, lookup_field=%s, fields=%v]",
		processorName, p.config.File, p.config.KeyField, p.config.LookupField, p.config.Fields)
}
