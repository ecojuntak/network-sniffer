package emit

import "github.com/ecojuntak/network-sniffer/internal/model"

// Multi returns a Sink that forwards every edge to each of sinks in order. A
// single sink is returned unchanged.
func Multi(sinks ...Sink) Sink {
	if len(sinks) == 1 {
		return sinks[0]
	}
	return multi(sinks)
}

type multi []Sink

func (m multi) Emit(sc model.ServiceCall) {
	for _, s := range m {
		s.Emit(sc)
	}
}
