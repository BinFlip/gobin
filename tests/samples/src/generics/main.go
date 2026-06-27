// Command generics is a fixture for Go generics (type parameters), available
// from Go 1.18. It exercises generic functions and generic types instantiated
// at multiple concrete types so the linker emits the instantiated symbols and
// shape/dictionary metadata that the parser should be able to surface:
//
//   - generic function instantiations: main.Sum[...] for int and float64
//   - generic type methods:            main.(*Stack[...]).Push / .Pop
//   - a multi-parameter generic type:  main.Pair[...]
//
// Requires Go >= 1.18.
package main

import "fmt"

// Number is a type-set constraint using the ~ approximation operator and a
// union, exercising constraint-element metadata.
type Number interface {
	~int | ~int64 | ~float64
}

// Sum is a generic function; it is instantiated for int and float64 in main,
// so two shape-specialized symbols are emitted.
//go:noinline
func Sum[T Number](xs []T) T {
	var total T
	for _, x := range xs {
		total += x
	}
	return total
}

// Stack is a generic type with pointer-receiver methods. Instantiating it at
// string and int forces distinct method symbols.
type Stack[T any] struct {
	items []T
}

//go:noinline
func (s *Stack[T]) Push(v T) { s.items = append(s.items, v) }

//go:noinline
func (s *Stack[T]) Pop() (T, bool) {
	var zero T
	if len(s.items) == 0 {
		return zero, false
	}
	v := s.items[len(s.items)-1]
	s.items = s.items[:len(s.items)-1]
	return v, true
}

// Pair is a multi-type-parameter generic type with a comparable constraint.
type Pair[K comparable, V any] struct {
	Key K
	Val V
}

// Keys is a generic function over a generic type.
//go:noinline
func Keys[K comparable, V any](pairs []Pair[K, V]) []K {
	out := make([]K, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.Key)
	}
	return out
}

func main() {
	fmt.Println(Sum([]int{1, 2, 3}))
	fmt.Println(Sum([]float64{1.5, 2.5, 3.0}))

	var ss Stack[string]
	ss.Push("a")
	ss.Push("b")
	fmt.Println(ss.Pop())

	var si Stack[int]
	si.Push(42)
	fmt.Println(si.Pop())

	pairs := []Pair[string, int]{{Key: "x", Val: 1}, {Key: "y", Val: 2}}
	fmt.Printf("%+v keys=%v\n", pairs, Keys(pairs))
}
