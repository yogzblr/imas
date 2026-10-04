package cook

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestCook(t *testing.T) {
	t.Run("apache", func(t *testing.T) {
		//	err := SendCookEvent("", "apache", "")
		//	if err != nil {
		//		t.Error(err)
		//	}
		// fmt.Println(jid)
	})
}

func TestResolveRecipeFilePath(t *testing.T) {
	testCases := []struct {
		id       string
		recipe   RecipeName
		filepath string
		err      error
	}{{
		id:       "file doesn't exist",
		recipe:   "",
		filepath: "",
		err:      ErrNoRecipe,
	}, {
		id:       "apache dot imas",
		recipe:   "apache.imas",
		filepath: "",
		err:      ErrNoRecipe,
	}, {
		id:       "apache dot apache dot imas",
		recipe:   "apache.apache.imas",
		filepath: filepath.Join(getBasePath(), "apache/apache.imas"),
		err:      nil,
	}, {
		id:       "apache slash path",
		recipe:   "apache/apache",
		filepath: filepath.Join(getBasePath(), "apache/apache.imas"),
		err:      nil,
	}, {
		id:       "apache dot path",
		recipe:   "apache.apache",
		filepath: filepath.Join(getBasePath(), "apache/apache.imas"),
		err:      nil,
	}, {
		id:       "dev",
		recipe:   "dev",
		filepath: filepath.Join(getBasePath(), "dev.imas"),
		err:      nil,
	}, {
		id:       "apache init",
		recipe:   "apache",
		filepath: filepath.Join(getBasePath(), "apache/init.imas"),
		err:      nil,
	}}
	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			filepath, err := ResolveRecipeFilePath(context.Background(), testPropsTenantID, getBasePath(), tc.recipe)
			if filepath != tc.filepath {
				t.Errorf("expected %s but got %s", tc.filepath, filepath)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("expected error %v but got %v", tc.err, err)
			}
		})
	}
}

// func TestParseRecipeFile(t *testing.T) {
// 	testCases := []struct {
// 		id          string
// 		recipe      RecipeName
// 		recipeSteps []RecipeCooker
// 	}{}
//
// 	for _, tc := range testCases {
// 		t.Run(tc.id, func(t *testing.T) {
// 			steps := ParseRecipeFile(tc.recipe)
// 			_ = steps
// 		})
// 	}
// }
