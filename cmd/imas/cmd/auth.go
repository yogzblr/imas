package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/auth"
)

// authCmd groups the CLI's identity commands. There is no token command:
// the CLI's NKey signs only the bus's connection nonce, and every request
// to farmer is sealed with the CLI box key (imas auth keygen), so there is
// no bearer token to print (docs/design/imas-payload-encryption-design.md,
// Decision A).
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Commands for authentication information",
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.Help()
	},
}

func init() {
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authPrivKeyCmd)
	authCmd.AddCommand(authPubKeyCmd)
	authCmd.AddCommand(authWhoAmICmd)
	authCmd.AddCommand(authUsersCmd)
	authCmd.AddCommand(authRolesCmd)
	authCmd.AddCommand(authExplainCmd)
	rootCmd.AddCommand(authCmd)
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Verify the CLI key is recognized by the farmer and show identity",
	Long: `Presents the CLI's public key to the farmer over NATS for
authentication. The farmer validates the key against configured users
and returns the user's identity, role, and permissions.

This is useful to verify connectivity and auth before running commands.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		result, err := withNats(client.Login)
		switch outputMode {
		case "json":
			if err != nil {
				errResult := struct {
					Authenticated bool   `json:"authenticated"`
					Error         string `json:"error"`
				}{Authenticated: false, Error: err.Error()}
				jw, _ := json.Marshal(errResult)
				fmt.Println(string(jw))
				os.Exit(1)
			}
			jw, _ := json.Marshal(result)
			fmt.Println(string(jw))
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Printf("Login failed: %s", err.Error())
				os.Exit(1)
			}
			if !result.Authenticated {
				log.Printf("Login failed: %s", result.Message)
				os.Exit(1)
			}
			if result.Username != "" {
				fmt.Printf("User:    %s\n", result.Username)
			}
			fmt.Printf("Pubkey:  %s\n", result.Pubkey)
			fmt.Printf("Role:    %s\n", result.RoleName)
			if result.IsAdmin {
				fmt.Println("Admin:   yes")
			}
			if len(result.Actions) > 0 {
				fmt.Println("\nPermissions:")
				for _, a := range result.Actions {
					if a.Scope == "" || a.Scope == "*" {
						fmt.Printf("  %s (all)\n", a.Action)
					} else {
						fmt.Printf("  %s → %s\n", a.Action, a.Scope)
					}
				}
			}
			fmt.Printf("\n%s\n", result.Message)
		}
	},
}

var authWhoAmICmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the identity and role of the current CLI user",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		info, err := withNats(client.WhoAmI)
		switch outputMode {
		case "json":
			result := struct {
				Pubkey   string `json:"pubkey"`
				Role     string `json:"role"`
				Username string `json:"username,omitempty"`
				Error    string `json:"error,omitempty"`
			}{Pubkey: info.Pubkey, Role: info.RoleName, Username: info.Username}
			if err != nil {
				result.Error = err.Error()
			}
			jw, _ := json.Marshal(result)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			if info.Username != "" {
				fmt.Printf("User:   %s\n", info.Username)
			}
			fmt.Printf("Pubkey: %s\nRole:   %s\n", info.Pubkey, info.RoleName)
		}
	},
}

var authUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all configured users and their roles",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		result, err := withNats(client.ListUsers)
		switch outputMode {
		case "json":
			jw, _ := json.Marshal(result)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			fmt.Println("Users:")
			for pubkey, roleName := range result.Users {
				fmt.Printf("  %s → %s\n", pubkey, roleName)
			}
			if len(result.Roles) > 0 {
				fmt.Println("\nRoles:")
				for _, role := range result.Roles {
					fmt.Printf("  %s:\n", role.Name)
					for _, rule := range role.Rules {
						if rule.Scope == "" || rule.Scope == "*" {
							fmt.Printf("    - %s (all)\n", rule.Action)
						} else {
							fmt.Printf("    - %s → %s\n", rule.Action, rule.Scope)
						}
					}
				}
			}
		}
	},
}

var authRolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "List all configured role definitions",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		result, err := withNats(client.ListUsers)
		switch outputMode {
		case "json":
			jw, _ := json.Marshal(result.Roles)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			if len(result.Roles) == 0 {
				fmt.Println("No roles configured.")
				return
			}
			for _, role := range result.Roles {
				fmt.Printf("%s:\n", role.Name)
				for _, rule := range role.Rules {
					if rule.Scope == "" || rule.Scope == "*" {
						fmt.Printf("  - %s (all)\n", rule.Action)
					} else {
						fmt.Printf("  - %s → %s\n", rule.Action, rule.Scope)
					}
				}
			}
		}
	},
}

var authExplainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Show what the current user is allowed to do",
	Long:  "Displays a permission summary including actions, scopes, and any policy warnings for the authenticated user.",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		result, err := withNats(client.ExplainAccess)
		switch outputMode {
		case "json":
			jw, _ := json.Marshal(result)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			fmt.Printf("Pubkey: %s\nRole:   %s\n", result.Pubkey, result.RoleName)
			if result.IsAdmin {
				fmt.Println("Admin:  yes (all actions permitted)")
			}
			if len(result.Actions) > 0 {
				fmt.Println("\nPermissions:")
				for _, a := range result.Actions {
					if a.Scope == "" || a.Scope == "*" {
						fmt.Printf("  %s (all)\n", a.Action)
					} else {
						fmt.Printf("  %s → %s\n", a.Action, a.Scope)
					}
				}
			}
			if len(result.Warnings) > 0 {
				fmt.Println("\nWarnings:")
				for _, w := range result.Warnings {
					fmt.Printf("  [%s] %s\n", w.Kind, w.Message)
				}
			}
		}
	},
}

var authPrivKeyCmd = &cobra.Command{
	Use:   "privkey",
	Short: "Create a private key for the imas CLI",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		err := auth.CreatePrivkey()

		switch outputMode {
		case "json":
			status := struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
			}{Success: err == nil}
			if err != nil {
				status.Error = err.Error()
			}
			jw, _ := json.Marshal(status)
			fmt.Println(string(jw))
			os.Exit(1)
			return
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			fmt.Println("Private key saved to config")
		}
	},
}

var authPubKeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Get the public key of the imas CLI",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		pubKey, err := auth.GetPubkey()
		switch outputMode {
		case "json":
			pubkey := struct {
				Pubkey string `json:"pubkey"`
				Error  string `json:"error"`
			}{Pubkey: pubKey}
			if err != nil {
				pubkey.Error = err.Error()
			}
			jw, _ := json.Marshal(pubkey)
			fmt.Println(string(jw))
			if err != nil {
				os.Exit(1)
			}
			return
		case "":
			fallthrough
		case "text":
			if err != nil {
				log.Println("Error: " + err.Error())
				os.Exit(1)
			}
			fmt.Println(pubKey)
		}
	},
}

// ensureNats connects to the bus if root's PersistentPreRun didn't (it
// skips the auth commands, most of which work offline).
func ensureNats() error {
	if client.NatsConn != nil {
		return nil
	}
	return client.ConnectNats()
}

// withNats connects (ensureNats), then calls f.
func withNats[T any](f func() (T, error)) (T, error) {
	if err := ensureNats(); err != nil {
		var zero T
		return zero, err
	}
	return f()
}
