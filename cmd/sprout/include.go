package main

import (
	_ "github.com/yogzblr/imas/internal/ingredients/cmd"
	_ "github.com/yogzblr/imas/internal/ingredients/file"
	_ "github.com/yogzblr/imas/internal/ingredients/file/http"
	_ "github.com/yogzblr/imas/internal/ingredients/file/local"
	_ "github.com/yogzblr/imas/internal/ingredients/group"
	_ "github.com/yogzblr/imas/internal/ingredients/pkg"
	_ "github.com/yogzblr/imas/internal/ingredients/probe"
	_ "github.com/yogzblr/imas/internal/ingredients/sdb/awssm"
	_ "github.com/yogzblr/imas/internal/ingredients/sdb/azurekv"
	_ "github.com/yogzblr/imas/internal/ingredients/sdb/gcpsm"
	_ "github.com/yogzblr/imas/internal/ingredients/sdb/openbao"
	_ "github.com/yogzblr/imas/internal/ingredients/selfupdate"
	_ "github.com/yogzblr/imas/internal/ingredients/user"
	_ "github.com/yogzblr/imas/internal/ingredients/wait"
)
