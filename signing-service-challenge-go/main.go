package main

import (
	"flag"
	"log"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
	"k8s.io/klog"
)

const (
	ListenAddress = ":8080"
	// TODO: add further configuration parameters here ...
)

func main() {
	flag.Parse()
	defer klog.Flush()

	klog.Infof("Starting signing service on %s", ListenAddress)
	server := api.NewServer(ListenAddress)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
