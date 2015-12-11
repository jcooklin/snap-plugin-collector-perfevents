/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2015 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package perfevents

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/intelsdi-x/pulse/control/plugin"
	"github.com/intelsdi-x/pulse/control/plugin/cpolicy"
	"github.com/intelsdi-x/pulse/core/ctypes"
)

const (
	// Name of plugin
	name = "perfevents"
	// Version of plugin
	version = 3
	// Type of plugin
	pluginType = plugin.CollectorPluginType
	// Namespace definition
	ns_vendor  = "intel"
	ns_class   = "linux"
	ns_type    = "perfevents"
	ns_subtype = "cgroup"

	defaultLogLevel = log.WarnLevel
)

type event struct {
	id    string
	etype string
	value float64
}

type Perfevents struct {
	cgroup_events []event
	Init          func() error
}

var CGROUP_EVENTS = []string{"cycles", "instructions", "cache-references", "cache-misses",
	"branch-instructions", "branch-misses", "stalled-cycles-frontend",
	"stalled-cycles-backend", "ref-cycles"}

func Meta() *plugin.PluginMeta {
	return plugin.NewPluginMeta(name, version, pluginType, []string{plugin.PulseGOBContentType}, []string{plugin.PulseGOBContentType})
}

// CollectMetrics returns HW metrics from perf events subsystem
// for Cgroups present on the host.
func (p *Perfevents) CollectMetrics(mts []plugin.PluginMetricType) ([]plugin.PluginMetricType, error) {
	if len(mts) == 0 {
		return nil, nil
	}
	logger := getLogger(mts[0].Config().Table())
	events := []string{}
	cgroups := []string{}

	allCgroups, err := list_cgroups()
	if err != nil {
		return nil, err
	}

	// Building events and cgroups arguments for perf stat.
	// Each cgroup is applied to the corresponding event, i.e., first cgroup to
	// first event, second cgroup to second event and so on.
	for _, cgroup := range allCgroups {
		for _, m := range mts {
			err := validateNamespace(m.Namespace())
			if err != nil {
				return nil, err
			}
			events = append(events, m.Namespace()[5])
			cgroups = append(cgroups, cgroup)
		}
	}

	// Prepare events (-e) and Cgroups (-G) switches for "perf stat"
	cgroups_switch := "-G" + strings.Join(cgroups, ",")
	events_switch := "-e" + strings.Join(events, ",")

	// TODO enable the sleep to be configured
	// Prepare "perf stat" command
	// logger.Debug("RUNNING: ", "perf", "stat", "--log-fd", "1", `-x;`, "-a", events_switch, cgroups_switch, "--", "sleep", "4")
	fmt.Println("RUNNING: ", "perf", "stat", "--log-fd", "1", `-x;`, "-a", events_switch, cgroups_switch, "--", "sleep", "4")
	cmd := exec.Command("perf", "stat", "--log-fd", "1", `-x;`, "-a", events_switch, cgroups_switch, "--", "sleep", "4")

	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		logger.WithField("err", err).Error("Error creating StdoutPipe")
		return nil, err
	}

	// Parse "perf stat" output
	// p.cgroup_events = make([]event, len(allCgroups)*len(mts))
	p.cgroup_events = []event{}
	scanner := bufio.NewScanner(cmdReader)
	done := make(chan struct{})
	timer := time.After(5 * time.Second)
	go func() {
		for i := 0; scanner.Scan(); i++ {
			line := strings.Split(scanner.Text(), ";")
			if len(line) < 3 {
				logger.WithFields(log.Fields{
					"line":        line,
					"line-number": i,
				}).Errorf("unexpected output - skipping result")
				continue
			}
			value, err := strconv.ParseFloat(line[0], 64)
			if err != nil {
				logger.WithField("err", err).Error("invalid metric value")
				value = 0
			}
			etype := line[1]
			id := line[2]
			e := event{id: id, etype: etype, value: value}
			logger.WithFields(log.Fields{
				"line-number": i,
				"line":        line,
			}).Debugf("event processed")
			// p.cgroup_events[i] = e
			p.cgroup_events = append(p.cgroup_events, e)
		}
		close(done)
	}()

	// Run command and wait (up to 2 secs) for completion
	err = cmd.Start()
	if err != nil {
		logger.WithField("err", err).Error("starting perf stat")
		return nil, err
	}
	select {
	case <-timer:
		return nil, fmt.Errorf("Timed out waiting for metrics from perf stat")
	case <-done:
		break
	}
	err = cmd.Wait()
	if err != nil {
		logger.WithFields(log.Fields{
			"err": err,
		}).Error("Error waiting for perf stat")
		return nil, err
	}

	// Populate metrics
	metrics := []plugin.PluginMetricType{}
	for idx := range p.cgroup_events {
		hostname, err := os.Hostname()
		if err != nil {
			panic(err)
		}
		if p.cgroup_events[idx].id == "" {
			continue
		}
		metric := plugin.PluginMetricType{
			Namespace_: []string{
				ns_vendor,
				ns_class,
				ns_type,
				ns_subtype,
				p.cgroup_events[idx].id,
				p.cgroup_events[idx].etype,
			},
			Data_:      p.cgroup_events[idx].value,
			Timestamp_: time.Now(),
			Source_:    hostname,
			Labels_: []plugin.Label{
				plugin.Label{Index: 4, Name: "cgroup"}, //todo define the label in getMetricTypes
			},
		}
		metrics = append(metrics, metric)
	}
	// logger.WithFields(log.Fields{
	// 	"containers-len": len(allCgroups),
	// 	"events-len":     len(events),
	// 	"metrics-len":    len(metrics),
	// }).Debugf("metrics: %+v\n", metrics)
	for idx := range metrics {
		logger.Debugf("metric[%d] %+v\n", idx, metrics[idx])
	}
	return metrics, nil
}

// GetMetricTypes returns the metric types exposed by perf events subsystem
func (p *Perfevents) GetMetricTypes(cfg plugin.PluginConfigType) ([]plugin.PluginMetricType, error) {
	err := p.Init()
	if err != nil {
		return nil, err
	}
	cgroups, err := list_cgroups()
	if err != nil {
		return nil, err
	}
	if len(cgroups) == 0 {
		return nil, nil
	}
	mts := []plugin.PluginMetricType{}
	mts = append(mts, set_supported_metrics(ns_subtype, cgroups, CGROUP_EVENTS)...)

	return mts, nil
}

// GetConfigPolicy returns a ConfigPolicy
func (p *Perfevents) GetConfigPolicy() (*cpolicy.ConfigPolicy, error) {
	c := cpolicy.New()
	return c, nil
}

// New initializes Perfevents plugin
func NewPerfeventsCollector() *Perfevents {
	return &Perfevents{Init: initialize}
}

func getLogger(cfg map[string]ctypes.ConfigValue) *log.Entry {
	logLevel := defaultLogLevel
	if d, ok := cfg["debug"]; ok {
		switch v := d.(type) {
		case ctypes.ConfigValueBool:
			if v.Value {
				logLevel = log.DebugLevel
			}
		default:
			log.WithFields(log.Fields{
				"field": "debug",
				"hint":  "provide a bool",
			}).Error("unsupported type")
		}
	}
	log.SetLevel(logLevel)
	return log.WithField("module", "perfevents")
}

func initialize() error {
	file, err := os.Open("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		if os.IsExist(err) {
			return errors.New("perf_event_paranoid file exists but couldn't be opened")
		}
		return errors.New("perf event system not enabled")
	}

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return errors.New("cannot read from perf_event_paranoid")
	}

	i, err := strconv.ParseInt(scanner.Text(), 10, 64)
	if err != nil {
		return errors.New("invalid value in perf_event_paranoid file")
	}

	if i >= 1 {
		return errors.New("insufficient perf event subsystem capabilities")
	}
	return nil
}

func set_supported_metrics(source string, cgroups []string, events []string) []plugin.PluginMetricType {
	mts := []plugin.PluginMetricType{}
	for _, e := range events {
		// for _, c := range flatten_cg_name(cgroups) {
		// 	mts = append(mts, plugin.PluginMetricType{Namespace_: []string{ns_vendor, ns_class, ns_type, source, e, c}})
		// }
		mt := plugin.PluginMetricType{
			Namespace_: []string{ns_vendor, ns_class, ns_type, source, "*", e},
		}
		mts = append(mts, mt)
	}
	log.Debugf("supported metric types: %+v\n", mts)
	return mts
}
func flatten_cg_name(cg []string) []string {
	flat_cg := []string{}
	for _, c := range cg {
		flat_cg = append(flat_cg, strings.Replace(c, "/", "_", -1))
	}
	return flat_cg
}

func list_cgroups() ([]string, error) {
	cgroups := []string{}
	base_path := "/sys/fs/cgroup/perf_event/"
	err := filepath.Walk(base_path, func(path string, info os.FileInfo, _ error) error {
		if info.IsDir() {
			cgroup_name := strings.TrimPrefix(path, base_path)
			if len(cgroup_name) > 0 && !strings.EqualFold(cgroup_name, "docker") {
				cgroups = append(cgroups, cgroup_name)
			}
		}
		return nil

	})
	if err != nil {
		return nil, err
	}
	return cgroups, nil
}

// TODO compliment this method... nice! we should do this on all plugins making debugging an invalid task easier.
func validateNamespace(namespace []string) error {
	if len(namespace) != 6 {
		return errors.New(fmt.Sprintf("unknown metricType %s (should containt exactly 6 segments)", namespace))
	}
	if namespace[0] != ns_vendor {
		return errors.New(fmt.Sprintf("unknown metricType %s (expected 1st segment %s)", namespace, ns_vendor))
	}

	if namespace[1] != ns_class {
		return errors.New(fmt.Sprintf("unknown metricType %s (expected 2nd segment %s)", namespace, ns_class))
	}
	if namespace[2] != ns_type {
		return errors.New(fmt.Sprintf("unknown metricType %s (expected 3rd segment %s)", namespace, ns_type))
	}
	if namespace[3] != ns_subtype {
		return errors.New(fmt.Sprintf("unknown metricType %s (expected 4th segment %s)", namespace, ns_subtype))
	}
	if !namespaceContains(namespace[5], CGROUP_EVENTS) {
		return errors.New(fmt.Sprintf("unknown metricType %s (expected 6th segment %v)", namespace, CGROUP_EVENTS))
	}
	return nil
}

func namespaceContains(element string, slice []string) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}
	return false
}
