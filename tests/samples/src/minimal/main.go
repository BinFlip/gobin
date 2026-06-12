// Command minimal is the smallest useful gobin fixture: a program that does
// not import fmt, so its function/type tables are as small as the Go runtime
// allows. Used to check the parser on a near-empty metadata surface.
//
// Build with -trimpath so no local filesystem paths leak into the binary.
package main

func main() {
	println("minimal")
}
