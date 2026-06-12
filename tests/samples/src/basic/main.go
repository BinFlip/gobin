// Command basic is the primary test fixture for the gobin test suite.
//
// It is intentionally rich enough to exercise the metadata surfaces the
// integration tests assert on, across every supported Go version:
//
//   - main.main, main.worker, main.(*TestStruct).DoSomething  (function names)
//   - a named struct type with methods                        (TestStruct)
//   - interfaces with multiple implementors                   (itab pairs)
//   - a goroutine and a channel                               (concurrency)
//   - a deferred call                                         (uses_defer)
//   - a closure                                               (main.main.func1)
//   - fmt / strings usage                                     (stdlib packages)
//
// Build with -trimpath so no local filesystem paths leak into the binary.
package main

import (
	"fmt"
	"reflect"
	"strings"
)

// Greeter is implemented by several concrete types so the linker emits a
// handful of itabs (interface, concrete-type) pairs.
type Greeter interface {
	Greet() string
}

// Stringerish is a second interface to broaden the itab set.
type Stringerish interface {
	fmt.Stringer
	Greeter
}

// TestStruct is a named type with both pointer and value receiver methods.
type TestStruct struct {
	Name  string
	Count int
}

// Config carries struct field tags so the type descriptor exercises the
// name-encoding tag path.
type Config struct {
	Name    string `json:"name" yaml:"name"`
	Count   int    `json:"count,omitempty"`
	Enabled bool   `json:"enabled"`
}

// DoSomething is a pointer-receiver method: main.(*TestStruct).DoSomething.
func (t *TestStruct) DoSomething() string {
	return fmt.Sprintf("%s:%d", t.Name, t.Count)
}

// Greet is a value-receiver method satisfying Greeter (and, with String,
// Stringerish).
func (t TestStruct) Greet() string { return "hi " + t.Name }

// String makes TestStruct satisfy fmt.Stringer.
func (t TestStruct) String() string { return t.Name }

// OtherImpl is a second Greeter implementor.
type OtherImpl struct{ x int }

func (o OtherImpl) Greet() string { return strings.Repeat("yo", o.x) }

// worker runs on its own goroutine, defers a close, and sends on a channel.
func worker(ch chan int, n int) {
	defer close(ch)
	ch <- n * 2
}

func main() {
	ts := &TestStruct{Name: "fixture", Count: 7}
	fmt.Println(ts.DoSomething())

	greeters := []Greeter{TestStruct{Name: "a"}, OtherImpl{x: 2}}
	for _, g := range greeters {
		fmt.Println(g.Greet())
	}

	var s Stringerish = TestStruct{Name: "b"}
	fmt.Println(s.String(), s.Greet())

	ch := make(chan int)
	go worker(ch, 21)
	fmt.Println(<-ch)

	upper := func() string { return strings.ToUpper("closure") }
	fmt.Println(upper())

	// Register Config's (tagged) struct descriptor in the type-link set via
	// reflection so the field tags are reachable to the parser.
	cfg := Config{Name: "x", Count: 1, Enabled: true}
	rt := reflect.TypeOf(cfg)
	fmt.Printf("%+v %d\n", cfg, rt.NumField())
}
