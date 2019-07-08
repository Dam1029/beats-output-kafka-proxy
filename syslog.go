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

// based on fileout plugin from Elasticsearch B.V.
// simple remote syslog shipper
// Rémi Laurent - <remi.laurent@data-essential.com>

package syslogout

import (
	gsyslog "github.com/hashicorp/go-syslog"
	"strconv"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/outputs"
	"github.com/elastic/beats/libbeat/outputs/codec"
	"github.com/elastic/beats/libbeat/publisher"
)

func init() {
	outputs.RegisterType("syslog", makeSyslogout)
}

type syslogOutput struct {
	host     string
	port     string
	proto    string
	sysLog   gsyslog.Syslogger
	beat     beat.Info
	observer outputs.Observer
	codec    codec.Codec
}

// makeSyslogout instantiates a new syslog output instance.
func makeSyslogout(
	_ outputs.IndexManager,
	beat beat.Info,
	observer outputs.Observer,
	cfg *common.Config,
) (outputs.Group, error) {
	config := defaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return outputs.Fail(err)
	}

	// disable bulk support in publisher pipeline
	cfg.SetInt("bulk_max_size", -1, -1)

	fo := &syslogOutput{
		beat:     beat,
		observer: observer,
	}
	if err := fo.init(beat, config); err != nil {
		return outputs.Fail(err)
	}

	return outputs.Success(-1, 0, fo)
}

func (out *syslogOutput) init(beat beat.Info, c config) error {
	out.host = c.Host
	out.port = strconv.Itoa(c.Port)
	out.proto = c.Proto

	// TODO severity, currently hardcoded to LOG_INFO
	var err error
	out.sysLog, err = gsyslog.DialLogger(out.proto, out.host+":"+out.port,
		c.GSyslogSeverity, c.Facility, "filebeat-syslog")
	if err != nil {
		return err
	}

	out.codec, err = codec.CreateEncoder(beat, c.Codec)
	if err != nil {
		return err
	}

	logp.Info("Initialized syslog output. "+
		"proto=%v host=%v port=%v severity=%v facility=%v",
		out.proto, out.host, out.port, c.Severity, c.Facility)

	return nil
}

// Implement Outputer
func (out *syslogOutput) Close() error {
	return out.sysLog.Close()
}

func (out *syslogOutput) Publish(
	batch publisher.Batch,
) error {
	defer batch.ACK()

	st := out.observer
	events := batch.Events()
	st.NewBatch(len(events))

	dropped := 0
	for i := range events {
		event := &events[i]

		serializedEvent, err := out.codec.Encode(out.beat.Beat, &event.Content)
		if err != nil {
			if event.Guaranteed() {
				logp.Critical("Failed to serialize the event: %v", err)
			} else {
				logp.Warn("Failed to serialize the event: %v", err)
			}

			dropped++
			continue
		}

		if _, err = out.sysLog.Write(append(serializedEvent, '\n')); err != nil {
			st.WriteError(err)

			if event.Guaranteed() {
				logp.Critical("Sending event to remote syslog failed with: %v", err)
			} else {
				logp.Warn("Sending event to remote syslog failed failed with: %v", err)
			}

			dropped++
			continue
		}

		st.WriteBytes(len(serializedEvent) + 1)
	}

	st.Dropped(dropped)
	st.Acked(len(events) - dropped)

	return nil
}

func (out *syslogOutput) String() string {
	return "syslog(" + out.proto + "://" + out.host + ":" + out.port + ")"
}
