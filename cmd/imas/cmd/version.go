package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/config"
)

// testCmd represents the test command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Check the cli and farmer versions",
	Run: func(cmd *cobra.Command, _ []string) {
		imasVersion := BuildInfo
		serverVersion, err := client.GetVersion()
		cv := config.CombinedVersion{
			CLI:    imasVersion,
			Farmer: serverVersion,
		}
		if err != nil {
			cv.Error = err.Error()
		}
		switch outputMode {
		case "json":
			jw, _ := json.Marshal(cv)
			fmt.Println(string(jw))
			return
		case "":
			fallthrough
		case "text":
			formatter := "%s Version:\n\tTag: %s\n\tCommit: %s\n\tArch: %s\n\tCompiler: %s\n"
			fmt.Printf(formatter, "CLI", imasVersion.Tag, imasVersion.GitCommit, imasVersion.Arch, imasVersion.Compiler)
			if err != nil {
				log.Println("Error fetching Farmer version: " + err.Error())
				return
			}
			fmt.Printf(formatter, "Farmer", serverVersion.Tag, serverVersion.GitCommit, serverVersion.Arch, serverVersion.Compiler)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
