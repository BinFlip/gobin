// Command types is a fixture that exercises the full type-descriptor zoo so
// the gobin type extractor can be validated across every `TypeDetail` kind:
// struct (named/embedded/tagged), map, channel (all directions), slice, array,
// pointer, func (variadic, multi-return), interface (empty + methods), named
// primitives, and aliases.
//
// Go only emits a runtime type descriptor (and a typelink) for a type that is
// reachable through reflection or an interface conversion, so every type below
// is funnelled through reflect.TypeOf to force the linker to keep it.
//
// It compiles unchanged on every Go release from 1.2 onward (no generics).
package main

import (
	"fmt"
	"reflect"
)

// Celsius is a named primitive (distinct descriptor over float64).
type Celsius float64

// Embedded is embedded into Record to exercise the embedded-field flag.
type Embedded struct {
	Tag string `json:"tag"`
}

// Record is a tagged struct with a wide spread of field kinds so the struct
// descriptor, its field names/tags/offsets, and the referenced element
// descriptors are all reachable.
type Record struct {
	Embedded                       // embedded field
	Name     string                `json:"name" yaml:"name"`
	Values   []int                 `json:"values"`
	Lookup   map[string]float64    `json:"lookup"`
	Fixed    [8]byte               `json:"fixed"`
	Next     *Record               `json:"-"`
	Recv     <-chan int            // recv-only channel
	Send     chan<- int            // send-only channel
	Both     chan struct{}         // bidirectional channel
	Callback func(int, ...string) (bool, error)
	Temp     Celsius
}

// Shape is an interface with methods (non-empty interface descriptor).
type Shape interface {
	Area() float64
	Perimeter() float64
}

// Circle implements Shape so an (interface, concrete) itab is emitted.
type Circle struct{ R float64 }

func (c Circle) Area() float64      { return 3.14159 * c.R * c.R }
func (c Circle) Perimeter() float64 { return 2 * 3.14159 * c.R }

func main() {
	specimens := []interface{}{
		Celsius(0),                                // named primitive
		Record{},                                  // struct (embedded + tags)
		[]int(nil),                                // slice
		[8]byte{},                                 // array
		map[string]float64(nil),                   // map
		(*Record)(nil),                            // pointer
		make(chan int),                            // chan bidir
		(<-chan int)(make(chan int)),              // chan recv
		(chan<- int)(make(chan int)),              // chan send
		func(int, ...string) (bool, error) { return false, nil }, // func variadic
		Circle{R: 2},                              // Shape implementor (itab)
	}
	for _, v := range specimens {
		fmt.Println(reflect.TypeOf(v).String())
	}

	var s Shape = Circle{R: 1}
	fmt.Println(s.Area(), s.Perimeter())

	// Reflecting a concrete value only emits the concrete descriptor; the
	// Shape interface's own type descriptor needs explicit reflection so the
	// interface TypeDetail (method set) is reachable to the parser.
	shapeType := reflect.TypeOf((*Shape)(nil)).Elem()
	fmt.Println(shapeType.Kind(), shapeType.NumMethod())
}
