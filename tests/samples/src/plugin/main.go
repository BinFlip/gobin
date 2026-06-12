// A Go plugin (-buildmode=plugin) for exercising moduledata ptab / pkghashes /
// pluginpath extraction.
package main

import "fmt"

// Exported symbols land in moduledata.ptab.
var ExportedVar = 42

func ExportedFunc(name string) string {
	return fmt.Sprintf("hello %s", name)
}

func main() {}
