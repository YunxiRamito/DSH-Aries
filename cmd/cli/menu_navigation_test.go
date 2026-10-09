package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadMenuActionArrowNavigation(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\x1b[B\r"))
	action, selected, err := readMenuAction(reader, nil, 0, 7, true)
	if err != nil {
		t.Fatalf("read down arrow: %v", err)
	}
	if action != "navigate" || selected != 1 {
		t.Fatalf("down arrow = (%q, %d), want (navigate, 1)", action, selected)
	}
	action, selected, err = readMenuAction(reader, nil, selected, 7, true)
	if err != nil {
		t.Fatalf("read enter: %v", err)
	}
	if action != "2" || selected != 1 {
		t.Fatalf("enter = (%q, %d), want (2, 1)", action, selected)
	}
}

func TestReadMenuActionWrapsUpArrow(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\x1b[A"))
	action, selected, err := readMenuAction(reader, nil, 0, 7, true)
	if err != nil {
		t.Fatalf("read up arrow: %v", err)
	}
	if action != "navigate" || selected != 6 {
		t.Fatalf("up arrow = (%q, %d), want (navigate, 6)", action, selected)
	}
}

func TestReadMenuActionQuitAndLineFallback(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("q"))
	action, _, err := readMenuAction(reader, nil, 2, 7, true)
	if err != nil || action != "q" {
		t.Fatalf("q = (%q, %v), want (q, nil)", action, err)
	}
	reader = bufio.NewReader(strings.NewReader("5\n"))
	action, selected, err := readMenuAction(reader, nil, 2, 7, false)
	if err != nil || action != "5" || selected != 2 {
		t.Fatalf("line fallback = (%q, %d, %v), want (5, 2, nil)", action, selected, err)
	}
}
