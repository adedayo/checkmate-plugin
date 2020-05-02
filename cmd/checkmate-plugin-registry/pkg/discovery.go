package host

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/hashicorp/go-plugin"
)

func discoverPlugins(globs, paths []string) (plugins []string) {
	plugs := make(map[string]bool)
	for _, p := range paths {
		filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				for _, glob := range globs {
					if pps, e := plugin.Discover(glob, path); e == nil {
						for _, pp := range pps {
							plugs[pp] = true
						}
					}
				}
				return nil
			}
			return nil
		})
	}
	for plugin := range plugs {
		plugins = append(plugins, plugin)
	}
	sort.Strings(plugins)
	return
}
