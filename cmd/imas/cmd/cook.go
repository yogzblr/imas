package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/api/client"
	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/pki"
)

var (
	async       bool
	cookTimeout int
	testMode    bool
	targetState string
)

var cmdCook = &cobra.Command{
	Use:   "cook <recipe> (-T <target> | -C <cohort>) [flags]",
	Short: "Cook a recipe against a target or cohort and see the output locally.",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			cmd.Help()
			return
		}
		var cmdCook apitypes.CmdCook
		cmdCook.Recipe = cook.RecipeName(args[0])
		cmdCook.Async = async
		cmdCook.Env = environment
		cmdCook.Test = testMode
		cmdCook.State = targetState

		effectiveTarget, err := resolveEffectiveTarget()
		if err != nil {
			log.Fatal(err)
		}
		results, err := client.Cook(effectiveTarget, cmdCook)
		if err != nil {
			switch err {
			case pki.ErrSproutIDNotFound:
				log.Fatalf("A targeted Sprout does not exist or is not accepted.")
			default:
				log.Fatal(err)
			}
		}
		jid := results.JID
		nc, err := client.NewNatsClient()
		if err != nil {
			log.Fatal(err)
		}
		finished := make(chan struct{}, 1)
		completionSteps := make(map[string][]cook.StepCompletion)
		// Step events come from farmer over the sealed farmer-to-CLI leg
		// (jobs.follow): sprouts seal them to the tenant key, which this
		// CLI doesn't hold. Followed before the trigger, so no event is
		// missed; farmer's follow ends once it has been idle for as long
		// as this command waits (at most client.MaxFollow).
		stream, err := client.FollowJobs(nc, jid, client.FollowOptions{Idle: time.Duration(cookTimeout) * time.Second})
		if err != nil {
			log.Fatalf("Failed to follow job %s: %v", jid, err)
		}
		defer stream.Stop()
		// The trigger is sealed, and farmer takes it only from this user.
		targetedSprouts, err := client.TriggerCook(nc, jid)
		if err != nil {
			log.Fatalf("Failed to trigger cook: %v", err)
		}
		if len(targetedSprouts) > 0 {
			fmt.Printf("Cooking on %d sprout(s): %s\n", len(targetedSprouts), strings.Join(targetedSprouts, ", "))
		}

		// Record job locally with per-user tracking.
		var cliListener *jobs.CLIListener
		if cliStorePath, pathErr := jobs.DefaultCLIStorePath(); pathErr == nil {
			if cliStore, storeErr := jobs.NewCLIStore(cliStorePath); storeErr == nil {
				userKey, _ := auth.GetPubkey()
				cliListener = jobs.NewCLIListener(cliStore, userKey)
				cliListener.RecordJobInit(jid, string(cmdCook.Recipe), targetedSprouts)
			}
		}

		localTimeout := time.After(time.Duration(cookTimeout) * time.Second)
		dripTimeout := time.After(120 * time.Second)
		concurrent := 0
		defer nc.Flush()
	waitLoop:
		for {
			select {
			case ev, ok := <-stream.Events:
				if !ok {
					break waitLoop
				}
				completion := cook.SproutStepCompletion{SproutID: ev.SproutID, CompletedStep: ev.Step}
				if cliListener != nil {
					cliListener.Record(completion.SproutID, jid, completion.CompletedStep)
				}
				printCookStep(completion.SproutID, jid, completion.CompletedStep)
				if string(completion.CompletedStep.ID) == fmt.Sprintf("start-%s", jid) {
					concurrent++
				}
				if string(completion.CompletedStep.ID) == fmt.Sprintf("completed-%s", jid) {
					// waitgroups are not necesary here because we are looping sequentially over a channel
					concurrent--
				}
				if concurrent == 0 {
					dripTimeout = time.After(time.Second / 10)
				}

				completionSteps[completion.SproutID] = append(completionSteps[completion.SproutID], completion.CompletedStep)
				localTimeout = time.After(time.Duration(cookTimeout) * time.Second)
			case <-finished:
				break waitLoop
			case <-dripTimeout:
				finished <- struct{}{}
				break waitLoop
			case <-localTimeout:
				color.Red(fmt.Sprintf("Cooking timed out after %d seconds.", cookTimeout))
				finished <- struct{}{}
				break waitLoop
			}
		}
		switch outputMode {
		case "json":
			wrapper := map[string]interface{}{}
			wrapper["jid"] = jid
			wrapper["sprouts"] = completionSteps
			jsonBytes, err := json.Marshal(wrapper)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(jsonBytes))
		case "":
			fallthrough
		case "text":
			for k, v := range completionSteps {
				successes := -2 // -2 because we don't count the start and completed steps
				failures := 0
				skipped := 0
				errors := []string{}
				for _, step := range v {
					switch step.CompletionStatus {
					case cook.StepCompleted:
						successes++
					case cook.StepFailed:
						failures++
					case cook.StepSkipped:
						skipped++
					}
					if step.Error != nil {
						errors = append(errors, step.Error.Error())
					}
				}
				fmt.Printf("Summary for %s, JID %s:\n", k, jid)
				fmt.Printf("\tSuccesses:\t%d\n", successes)
				fmt.Printf("\tFailures:\t%d\n", failures)
				if skipped > 0 {
					fmt.Printf("\tSkipped:\t%d\n", skipped)
				}
				fmt.Printf("\tErrors:\t\t%d\n", len(errors))
				for _, err := range errors {
					fmt.Printf("\t\t%s\n", err)
				}
			}
		}
	},
}

// printCookStep prints one step event of job jid on sproutID, in text
// output mode; the start and completed bookends print nothing.
func printCookStep(sproutID, jid string, step cook.StepCompletion) {
	if string(step.ID) == fmt.Sprintf("completed-%s", jid) || string(step.ID) == fmt.Sprintf("start-%s", jid) {
		return
	}
	switch outputMode {
	case "", "text":
	default:
		return
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s::%s\n", sproutID, jid))
	b.WriteString(fmt.Sprintf("ID: %s\n", step.ID))
	switch step.CompletionStatus {
	case cook.StepCompleted:
		b.WriteString(color.GreenString(fmt.Sprintf("\tResult: %s\n", "Success")))
	case cook.StepFailed:
		b.WriteString(color.RedString(fmt.Sprintf("\tResult: %s\n", "Failure")))
	case cook.StepSkipped:
		b.WriteString(color.YellowString(fmt.Sprintf("\tResult: %s\n", "Skipped")))
	default:
		b.WriteString(color.YellowString(fmt.Sprintf("\tResult: %s\n", "Unknown")))
	}
	b.WriteString("\tExecution Notes: \n")
	for _, change := range step.Changes {
		b.WriteString(fmt.Sprintf("\t\t%s\n", change))
	}
	if !step.Started.IsZero() {
		b.WriteString(fmt.Sprintf("\tStarted:  %s\n", step.Started.Format(time.RFC3339)))
		b.WriteString(fmt.Sprintf("\tDuration: %s\n", step.Duration.Round(time.Millisecond)))
	}
	b.WriteString("----------\n")
	printTex.Lock()
	fmt.Print(b.String())
	printTex.Unlock()
}

func init() {
	cmdCook.Flags().StringVarP(&environment, "environment", "E", "", "")
	cmdCook.Flags().BoolVar(&async, "async", false, "Don't print any output, just return the JID to look up results later")
	addTargetFlags(cmdCook)
	cmdCook.Flags().IntVar(&cookTimeout, "cook-timeout", 30, "Cancel cook execution and return after X seconds")
	cmdCook.Flags().BoolVar(&testMode, "test", false, "Run in test mode (dry run without applying changes)")
	cmdCook.Flags().StringVarP(&targetState, "state", "s", "", "Run only the named state and its requisite dependencies")
	rootCmd.AddCommand(cmdCook)
}
