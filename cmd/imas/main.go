package main

import (
	"runtime"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/cmd/imas/cmd"
	"github.com/yogzblr/imas/internal/config"
)

func init() {
	log.SetLogLevel(log.LError)
}

const DocumentationURL = "https://docs.imas.dev"

var (
	GitCommit string
	Tag       string
)

func main() {
	defer log.Flush()
	cmd.Execute(config.Version{
		Arch:      runtime.GOOS,
		Compiler:  runtime.Version(),
		GitCommit: GitCommit,
		Tag:       Tag,
	})
}
