//go:build !linux

package net

import "net"

func applyPlatformOptions(_ *net.UDPConn, _ SocketConfig, _ *OptimizationReport) {}

func newBatchConn(_ *net.UDPConn, _ int) *batchConn { return nil }

type batchConn struct{}

func (bc *batchConn) ReadBatch(_ [][]byte) (int, error)                    { return 0, nil }
func (bc *batchConn) ReceivedN(_ int) int                                  { return 0 }
func (bc *batchConn) ReceivedFrom(_ int) *net.UDPAddr                      { return nil }
func (bc *batchConn) WriteBatch(_ [][]byte, _ []*net.UDPAddr) (int, error) { return 0, nil }
