//go:build windows

package main

import (
	_ "github.com/yogzblr/imas/internal/ingredients/lgpo"
	_ "github.com/yogzblr/imas/internal/ingredients/registry"
	_ "github.com/yogzblr/imas/internal/ingredients/service/windows"
	_ "github.com/yogzblr/imas/internal/ingredients/winappx"
	_ "github.com/yogzblr/imas/internal/ingredients/winauditpol"
	_ "github.com/yogzblr/imas/internal/ingredients/wincertutil"
	_ "github.com/yogzblr/imas/internal/ingredients/windnsclient"
	_ "github.com/yogzblr/imas/internal/ingredients/windsc"
	_ "github.com/yogzblr/imas/internal/ingredients/winfirewall"
	_ "github.com/yogzblr/imas/internal/ingredients/winiis"
	_ "github.com/yogzblr/imas/internal/ingredients/winpki"
	_ "github.com/yogzblr/imas/internal/ingredients/winpowercfg"
	_ "github.com/yogzblr/imas/internal/ingredients/winpsget"
	_ "github.com/yogzblr/imas/internal/ingredients/winservermanager"
	_ "github.com/yogzblr/imas/internal/ingredients/winshortcut"
	_ "github.com/yogzblr/imas/internal/ingredients/winsmtpserver"
	_ "github.com/yogzblr/imas/internal/ingredients/winsnmp"
	_ "github.com/yogzblr/imas/internal/ingredients/wintaskscheduler"
	_ "github.com/yogzblr/imas/internal/ingredients/winupdate"
)
