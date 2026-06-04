package gypscan

import (
	"path"
	"regexp"
	"strings"
)

var (
	includesArrayRe = regexp.MustCompile(`["']includes["']\s*:\s*\[([^\]]*)\]`)
	quotedPathRe    = regexp.MustCompile(`["']([^"']+)["']`)
)

// ParseIncludePaths extracts literal GYP includes paths from gypContent.
//
// Returned paths are cleaned and slash-normalized but are not resolved; GYP
// include paths are relative to the file that contains the includes array, so
// filesystem and tarball callers own resolution and confinement. Computed
// include entries containing `<!` are skipped because gypscan handles command
// expansion as a separate critical signal.
func ParseIncludePaths(gypContent []byte) []string {
	var out []string
	content := string(gypContent)
	for _, m := range includesArrayRe.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		for _, pathMatch := range quotedPathRe.FindAllStringSubmatch(m[1], -1) {
			if len(pathMatch) < 2 {
				continue
			}
			includePath := pathMatch[1]
			if strings.Contains(includePath, "<!") {
				continue
			}
			includePath = strings.ReplaceAll(includePath, "\\", "/")
			includePath = path.Clean(includePath)
			if includePath == "." || includePath == "" {
				continue
			}
			out = append(out, includePath)
		}
	}
	return out
}
