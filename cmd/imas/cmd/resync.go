package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/yogzblr/imas/cmd/imas/util"
	"github.com/yogzblr/imas/internal/api/client"
	apitypes "github.com/yogzblr/imas/internal/api/types"
)

// A top-level command rather than `cook resync`: cmdCook takes a recipe
// name as its argument, and a subcommand would shadow a recipe named
// "resync".
var cmdResync = &cobra.Command{
	Use:   "resync (-T <target> | -C <cohort>)",
	Short: "Nudge sprouts to pull their latest dispatched recipe and cook it if they missed it.",
	Long: `Nudge sprouts to pull the recipe farmer last dispatched to them.

A sprout cooks the pulled recipe only if it never received that job (for
example, it was disconnected when it was dispatched) and the job is no
older than the sprout's stagedrecipemaxage setting. Sprouts already do this
by themselves on startup and on every reconnect.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		effectiveTarget, err := resolveEffectiveTarget()
		if err != nil {
			util.OutputError(err, outputMode)
			return
		}
		results, err := client.Resync(effectiveTarget)
		if err != nil {
			util.OutputError(err, outputMode)
			return
		}
		if outputMode == "json" {
			jw, _ := json.Marshal(results)
			fmt.Println(string(jw))
			return
		}
		ids := make([]string, 0, len(results.Results))
		for id := range results.Results {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			var res apitypes.ResyncResult
			jw, _ := json.Marshal(results.Results[id])
			if err := json.Unmarshal(jw, &res); err != nil {
				color.Red("%s returned an invalid result\n", id)
				continue
			}
			if res.Nudged {
				fmt.Printf("%s: nudged\n", id)
			} else {
				color.Red("%s: %s\n", id, res.Error)
			}
		}
	},
}

func init() {
	addTargetFlags(cmdResync)
	rootCmd.AddCommand(cmdResync)
}
