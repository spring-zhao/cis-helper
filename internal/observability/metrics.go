package observability

import (
	"time"
)

type Metric struct {
	Name     string
	Result   string
	Version  string
	Duration time.Duration
	Labels   map[string]string
}

type MetricsRecorder interface {
	Record(Metric)
}

type NopMetrics struct{}

func (NopMetrics) Record(Metric) {}

type Recorder struct {
	version string
	sink    MetricsRecorder
}

func NewRecorder(version string, sink MetricsRecorder) Recorder {
	if sink == nil {
		sink = NopMetrics{}
	}
	return Recorder{
		version: version,
		sink:    sink,
	}
}

func (r Recorder) Duration(name, result string, duration time.Duration, labels map[string]string) {
	if r.sink == nil {
		return
	}
	merged := cloneLabels(labels)
	merged["version"] = r.version
	r.sink.Record(Metric{
		Name:     name,
		Result:   result,
		Version:  r.version,
		Duration: duration,
		Labels:   merged,
	})
}

func (r Recorder) Event(name, result string, labels map[string]string) {
	r.Duration(name, result, 0, labels)
}

func (r Recorder) Error(name, code string, err error) {
	labels := map[string]string{
		"code": code,
	}
	if err != nil {
		labels["error"] = err.Error()
	}
	r.Event(name, "error", labels)
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}
