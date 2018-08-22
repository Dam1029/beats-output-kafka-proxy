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
// +build !windows,!nacl,!plan9

// based on fileout plugin from Elasticsearch B.V.
// simple remote syslog shipper
// Rémi Laurent - <remi.laurent@data-essential.com>

package syslogout

import (
	"fmt"
	gsyslog "github.com/hashicorp/go-syslog"
	"log/syslog"
	"strings"

	"github.com/elastic/beats/libbeat/outputs/codec"
)

// somehow borrowed from github.com/hashicorp/go-syslog - unix.go
func severityPriority(severity string) (gsyslog.Priority, error) {
	severity = strings.ToUpper(severity)
	switch severity {
	case "EMERG":
		return gsyslog.LOG_EMERG, nil
	case "ALERT":
		return gsyslog.LOG_ALERT, nil
	case "CRIT":
		return gsyslog.LOG_CRIT, nil
	case "ERR":
		return gsyslog.LOG_ERR, nil
	case "WARNING":
		return gsyslog.LOG_WARNING, nil
	case "NOTICE":
		return gsyslog.LOG_NOTICE, nil
	case "INFO":
		return gsyslog.LOG_INFO, nil
	case "DEBUG":
		return gsyslog.LOG_DEBUG, nil
	default:
		return 0, fmt.Errorf("invalid syslog severity: %s", severity)
	}
}

// borrowed from github.com/hashicorp/go-syslog - unix.go - facilityPriority
func facilityPriority(facility string) (syslog.Priority, error) {
	facility = strings.ToUpper(facility)
	switch facility {
	case "KERN":
		return syslog.LOG_KERN, nil
	case "USER":
		return syslog.LOG_USER, nil
	case "MAIL":
		return syslog.LOG_MAIL, nil
	case "DAEMON":
		return syslog.LOG_DAEMON, nil
	case "AUTH":
		return syslog.LOG_AUTH, nil
	case "SYSLOG":
		return syslog.LOG_SYSLOG, nil
	case "LPR":
		return syslog.LOG_LPR, nil
	case "NEWS":
		return syslog.LOG_NEWS, nil
	case "UUCP":
		return syslog.LOG_UUCP, nil
	case "CRON":
		return syslog.LOG_CRON, nil
	case "AUTHPRIV":
		return syslog.LOG_AUTHPRIV, nil
	case "FTP":
		return syslog.LOG_FTP, nil
	case "LOCAL0":
		return syslog.LOG_LOCAL0, nil
	case "LOCAL1":
		return syslog.LOG_LOCAL1, nil
	case "LOCAL2":
		return syslog.LOG_LOCAL2, nil
	case "LOCAL3":
		return syslog.LOG_LOCAL3, nil
	case "LOCAL4":
		return syslog.LOG_LOCAL4, nil
	case "LOCAL5":
		return syslog.LOG_LOCAL5, nil
	case "LOCAL6":
		return syslog.LOG_LOCAL6, nil
	case "LOCAL7":
		return syslog.LOG_LOCAL7, nil
	default:
		return 0, fmt.Errorf("invalid syslog facility: %s", facility)
	}
}

type config struct {
	Host            string `config:"host"`
	Port            int    `config:"port"`
	Proto           string `config:"proto"`
	Facility        string `config:"facility"`
	Severity        string `config:"severity"`
	GSyslogSeverity gsyslog.Priority
	Codec           codec.Config `config:"codec"`
}

var (
	defaultConfig = config{
		Host:     "127.0.0.1",
		Proto:    "udp",
		Port:     514,
		Facility: "LOCAL0",
		Severity: "WARNING",
	}
)

func (c *config) Validate() error {
	var err error
	if _, err = facilityPriority(c.Facility); err != nil {
		return fmt.Errorf("Unkown facility: %s", c.Facility)
	}
	if c.GSyslogSeverity, err = severityPriority(c.Severity); err != nil {
		return fmt.Errorf("Unkown severity: %s", c.Severity)
	}

	return nil
}
