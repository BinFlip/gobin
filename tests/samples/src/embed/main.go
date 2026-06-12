package main

import (
	"embed"
	"fmt"
)

//go:embed assets/*
var assets embed.FS

//go:embed assets/hello.txt
var single string

func main() {
	entries, _ := assets.ReadDir("assets")
	for _, e := range entries {
		fmt.Println(e.Name())
	}
	fmt.Println(single)
}
