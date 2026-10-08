package processor

import (
	"context"
	"math"
	"net/netip"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
	"github.com/ecojuntak/network-sniffer/internal/model"
)

// Server implements the ProcessorService gRPC API on top of a Pipeline.
type Server struct {
	snifferv1.UnimplementedProcessorServiceServer
	pipeline *Pipeline
	m        *Metrics
}

// NewServer returns a Server feeding received records into p.
func NewServer(p *Pipeline, m *Metrics) *Server {
	return &Server{pipeline: p, m: m}
}

// Report runs every record of the batch through the pipeline. Malformed
// records are counted and skipped rather than failing the batch, which the
// collector would otherwise retry forever.
func (s *Server) Report(_ context.Context, req *snifferv1.ReportRequest) (*snifferv1.ReportResponse, error) {
	s.m.Batches.Inc()
	for _, r := range req.GetRecords() {
		ev, ok := toEvent(r)
		if !ok {
			s.m.Records.WithLabelValues(resultInvalid).Inc()
			continue
		}
		s.pipeline.Handle(ev)
	}
	return &snifferv1.ReportResponse{}, nil
}

// toEvent converts a wire record into the canonical event the pipeline
// consumes. It reports false for addresses or numbers out of range.
func toEvent(r *snifferv1.FlowRecord) (model.ConnectionEvent, bool) {
	src, ok := netip.AddrFromSlice(r.GetSrcIp())
	if !ok {
		return model.ConnectionEvent{}, false
	}
	dst, ok := netip.AddrFromSlice(r.GetDstIp())
	if !ok {
		return model.ConnectionEvent{}, false
	}
	if r.GetDstPort() > math.MaxUint16 || r.GetProtocol() > math.MaxUint8 {
		return model.ConnectionEvent{}, false
	}
	return model.ConnectionEvent{
		SrcIP:     src.Unmap(),
		DstIP:     dst.Unmap(),
		DstPort:   uint16(r.GetDstPort()),
		Protocol:  model.Protocol(r.GetProtocol()),
		Comm:      r.GetComm(),
		Outbound:  r.GetOutbound(),
		SrcPodUID: r.GetSrcPodUid(),
	}, true
}
