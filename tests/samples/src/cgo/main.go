// Command cgo is a fixture that uses CGO so the parser can be checked against
// the extra symbols and sections a cgo build emits (the `_cgo_*` runtime
// shims, the C call wrappers, and a cgo-specific build configuration). It is
// built with CGO_ENABLED=1 for linux/amd64, which needs a host C compiler.
//
// It deliberately keeps the C surface tiny (one inline function plus a
// malloc/free round-trip) so the fixture stays small while still exercising
// the cgo code paths.
package main

/*
#include <stdlib.h>

static int cgo_add(int a, int b) {
	return a + b;
}
*/
import "C"

import "fmt"

func main() {
	sum := C.cgo_add(C.int(2), C.int(3))
	fmt.Println("cgo_add:", int(sum))

	// A heap round-trip through the C allocator exercises the cgo runtime
	// shims and the C.malloc/C.free wrappers.
	p := C.malloc(C.size_t(16))
	if p != nil {
		C.free(p)
	}
	fmt.Println("ok")
}
