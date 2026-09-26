//go:build linux

package main

import (
	_ "github.com/yogzblr/imas/internal/ingredients/cron"
	_ "github.com/yogzblr/imas/internal/ingredients/firewall"
	_ "github.com/yogzblr/imas/internal/ingredients/mount"
	_ "github.com/yogzblr/imas/internal/ingredients/network"
	_ "github.com/yogzblr/imas/internal/ingredients/selinux"
	_ "github.com/yogzblr/imas/internal/ingredients/service/openrc"
	_ "github.com/yogzblr/imas/internal/ingredients/service/systemd"
)
