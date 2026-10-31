// Package snaprejoin is a local regression suite (no reference twin):
// a node whose pull cursor falls below the donor's GC watermark must
// rejoin via the automatic snapshot fallback, including across an
// in-process restart (which used to wedge the snapshot stream on a
// duplicate QUIC stream id).
package snaprejoin
