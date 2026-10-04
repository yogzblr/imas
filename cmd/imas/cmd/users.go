package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/yogzblr/imas/internal/api/client"
)

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage imas users",
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.Help()
	},
}

var usersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured users and their roles",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		result, err := client.ListUsersWithBoxKeys()
		switch outputMode {
		case "json":
			jw, _ := json.Marshal(result)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "", "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			if len(result.Users) == 0 {
				fmt.Println("No users configured.")
				return
			}
			fmt.Println("Users:")
			for pubkey, roleName := range result.Users {
				key := result.BoxKeys[pubkey]
				if key == "" {
					key = "no CLI box key: can't make requests"
				}
				fmt.Printf("  %s → %s (%s)\n", pubkey, roleName, key)
			}
		}
	},
}

var (
	usersAddBoxPub   string
	usersAddUsername string
	usersResetBoxPub string
)

var usersAddCmd = &cobra.Command{
	Use:   "add <role> <pubkey> --boxpub <box key>",
	Short: "Add a user with the given role, NKey public key and CLI box key",
	Long: `Registers a user: their NKey public key (imas auth pubkey) with a role,
and their CLI box public key (printed by their imas auth keygen), which
is what farmer opens their sealed requests with. Check the box key's
fingerprint with the user out of band before adding it.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		roleName := args[0]
		pubkey := args[1]
		result, err := client.AddUser(pubkey, roleName, usersAddUsername, usersAddBoxPub)
		switch outputMode {
		case "json":
			resp := struct {
				Success bool   `json:"success"`
				Message string `json:"message,omitempty"`
				Error   string `json:"error,omitempty"`
			}{Success: result.Success, Message: result.Message}
			if err != nil {
				resp.Error = err.Error()
			}
			jw, _ := json.Marshal(resp)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "", "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			fmt.Println(result.Message)
		}
	},
}

var usersRemoveCmd = &cobra.Command{
	Use:   "remove <pubkey>",
	Short: "Remove a user by public key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pubkey := args[0]
		result, err := client.RemoveUser(pubkey)
		switch outputMode {
		case "json":
			resp := struct {
				Success bool   `json:"success"`
				Message string `json:"message,omitempty"`
				Error   string `json:"error,omitempty"`
			}{Success: result.Success, Message: result.Message}
			if err != nil {
				resp.Error = err.Error()
			}
			jw, _ := json.Marshal(resp)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "", "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			fmt.Println(result.Message)
		}
	},
}

var usersResetKeyCmd = &cobra.Command{
	Use:   "reset-key <pubkey> --boxpub <box key>",
	Short: "Replace a user's CLI box key (a lost or stolen key)",
	Long: `Retires every CLI box key the user holds and registers the given one as
their only key: for a user who lost their key or whose key was stolen,
or a config-file user who has none. Check the new key's fingerprint with
the user out of band first. A user replacing their own working key
should use imas auth rotate-key instead.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		result, err := client.ResetUserKey(args[0], usersResetBoxPub)
		printUserMutation(result.Success, result.Message, err)
	},
}

// printUserMutation prints a users add/remove/reset-key result and exits 1
// on err.
func printUserMutation(success bool, message string, err error) {
	switch outputMode {
	case "json":
		resp := struct {
			Success bool   `json:"success"`
			Message string `json:"message,omitempty"`
			Error   string `json:"error,omitempty"`
		}{Success: success, Message: message}
		if err != nil {
			resp.Error = err.Error()
		}
		jw, _ := json.Marshal(resp)
		fmt.Println(string(jw))
		if err != nil {
			os.Exit(1)
		}
	case "", "text":
		if err != nil {
			log.Println("Error: " + err.Error())
			os.Exit(1)
		}
		fmt.Println(message)
	}
}

func init() {
	usersAddCmd.Flags().StringVar(&usersAddBoxPub, "boxpub", "", "the user's CLI box public key (from their imas auth keygen; required)")
	usersAddCmd.Flags().StringVar(&usersAddUsername, "username", "", "a name for the user in listings and audit entries")
	_ = usersAddCmd.MarkFlagRequired("boxpub")
	usersResetKeyCmd.Flags().StringVar(&usersResetBoxPub, "boxpub", "", "the user's new CLI box public key (required)")
	_ = usersResetKeyCmd.MarkFlagRequired("boxpub")
	usersCmd.AddCommand(usersListCmd)
	usersCmd.AddCommand(usersAddCmd)
	usersCmd.AddCommand(usersRemoveCmd)
	usersCmd.AddCommand(usersResetKeyCmd)
	rootCmd.AddCommand(usersCmd)
}
