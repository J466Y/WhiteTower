// Spike S2 (plan P0-05): can two core replicas push a halt to 1,000 connected
// enforcement points within the NFR-03 target, and do leases expire
// accurately?
//
// One binary with four commands. "run" is the only one you start: it prepares
// the database from the real migration, then starts the others as child
// processes and drives the scenarios.
//
//	run   the coordinator: scenarios and report
//	core  one core replica: the module API's Watch and Acknowledge, over
//	      TLS and HTTP/2, fed by PostgreSQL LISTEN/NOTIFY
//	lb    a TCP load balancer in front of the replicas
//	eps   the enforcement point simulator: one TLS connection per enforcement
//	      point, leases, acknowledgements, simulated network partitions
//
// See README.md for how to run it.
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: s2 run|core|lb|eps [flags]")
		os.Exit(2)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	var err error
	switch os.Args[1] {
	case "run":
		err = runCoordinator(os.Args[2:])
	case "core":
		err = runCore(os.Args[2:])
	case "lb":
		err = runLB(os.Args[2:])
	case "eps":
		err = runEPs(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "s2:", err)
		os.Exit(1)
	}
}
