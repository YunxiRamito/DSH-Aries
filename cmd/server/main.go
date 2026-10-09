package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"aries.local/aries/internal/kernel"
	"aries.local/aries/internal/store"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: aries-server serve --config <path>")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := flags.String("config", "", "path to JSON server config")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(2)
	}
	if err := run(*configPath); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	cfg, err := kernel.LoadConfig(absConfig)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	initialNodeID, err := randomNodeID()
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.json"), initialNodeID)
	if err != nil {
		return err
	}
	k, err := kernel.New(cfg, absConfig, st)
	if err != nil {
		_ = st.Close()
		return err
	}
	publicListener, err := net.Listen("tcp", cfg.PublicListen)
	if err != nil {
		_ = st.Close()
		return fmt.Errorf("listen on public address: %w", err)
	}
	adminListener, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		_ = publicListener.Close()
		_ = st.Close()
		return fmt.Errorf("listen on admin address: %w", err)
	}
	fileCleanupCtx, stopFileCleanup := context.WithCancel(context.Background())
	fileCleanupDone := make(chan struct{})
	go func() {
		defer close(fileCleanupDone)
		k.FileCleanupLoop(fileCleanupCtx)
	}()
	defer func() {
		stopFileCleanup()
		<-fileCleanupDone
	}()
	publicServer := &http.Server{Handler: k.PublicHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	adminServer := &http.Server{Handler: k.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	shutdown := make(chan struct{})
	var shutdownOnce sync.Once
	k.SetShutdown(func() { shutdownOnce.Do(func() { close(shutdown) }) })
	serveErrors := make(chan error, 2)
	go func() {
		if err := publicServer.Serve(publicListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- fmt.Errorf("public listener failed: %w", err)
		}
	}()
	go func() {
		if err := adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- fmt.Errorf("admin listener failed: %w", err)
		}
	}()
	log.Printf("server started node=%s server_code=%s public=%s admin=%s api=%s", nodeID(st), serverCode(st), cfg.PublicListen, cfg.AdminListen, kernel.APIVersion)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case sig := <-signals:
		log.Printf("shutdown requested signal=%s", sig)
	case <-shutdown:
	case err := <-serveErrors:
		stopFileCleanup()
		<-fileCleanupDone
		_ = st.Close()
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = publicServer.Shutdown(ctx)
	_ = adminServer.Shutdown(ctx)
	stopFileCleanup()
	<-fileCleanupDone
	if err := st.Close(); err != nil {
		return fmt.Errorf("flush state: %w", err)
	}
	log.Print("server stopped")
	return nil
}

func nodeID(st *store.Store) string {
	var v string
	_ = st.View(func(s store.State) error { v = s.NodeID; return nil })
	return v
}

func serverCode(st *store.Store) string {
	var v string
	_ = st.View(func(s store.State) error { v = s.ServerCode; return nil })
	return v
}

func randomNodeID() (string, error) {
	// A full node identity is separate from the four-character display prefix.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "node_" + hex.EncodeToString(b), nil
}
