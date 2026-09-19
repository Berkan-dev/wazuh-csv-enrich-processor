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

// NOTE: this file targets the libbeat API as it existed at elastic/beats
// tag v7.10.2, which is what Wazuh's filebeat-oss package is built from
// (see https://github.com/wazuh/wazuh/issues/26712). This is an older API
// than current elastic/beats main -- it predates the split into
// elastic-agent-libs, so config/logging/mapstr types come from
// "github.com/elastic/beats/v7/libbeat/common" rather than
// "github.com/elastic/elastic-agent-libs/...". Diff this against your own
// checkout of the v7.10.2 tag before building; I ported this from
// documentation and other v7.10.2-era processors rather than compiling it
// myself.

package csv_enrich

import (
	"errors"
	"time"
)

// config holds the user-supplied configuration for the csv_enrich processor.
//
// Example:
//
//	processors:
//	  - csv_enrich:
//	      file: /etc/filebeat/enrich/users.csv
//	      lookup_field: si_user
//	      key_field: parsed_message.data.si_user
//	      fields: ["Department", "vlan_address", "Role"]
//	      target_prefix: user
//	      ignore_case: true
//	      ignore_missing: true
//	      reload_interval: 30s
type config struct {
	File           string        `config:"file" validate:"required"`
	LookupField    string        `config:"lookup_field" validate:"required"`
	KeyField       string        `config:"key_field" validate:"required"`
	Fields         []string      `config:"fields" validate:"required"`
	TargetPrefix   string        `config:"target_prefix"`
	IgnoreMissing  bool          `config:"ignore_missing"`
	IgnoreCase     bool          `config:"ignore_case"`
	OverwriteKeys  bool          `config:"overwrite_keys"`
	ReloadInterval time.Duration `config:"reload_interval"`
}

func defaultConfig() config {
	return config{
		IgnoreMissing:  true,
		IgnoreCase:     true,
		OverwriteKeys:  true,
		ReloadInterval: 30 * time.Second,
	}
}

func (c *config) Validate() error {
	if len(c.Fields) == 0 {
		return errors.New("csv_enrich: fields must contain at least one column name")
	}
	if c.ReloadInterval < 0 {
		return errors.New("csv_enrich: reload_interval must not be negative")
	}
	return nil
}
