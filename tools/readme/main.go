// Command readme replaces a marked region of README.md with the content of a
// file. The benchmark table and the worked finding in the README are both
// real program output, pasted in by this tool rather than typed by hand:
//
//	spackle bench --table > table.md
//	go run ./tools/readme -marker bench -from table.md
//
// A region is delimited by "<!-- NAME:start -->" and "<!-- NAME:end -->".
// With -check nothing is written and the exit code is 1 when the region
// differs from the file. tools/demoassets regenerates the regions that hold
// output of a scan of the demo application.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	marker := flag.String("marker", "", "region name, for example bench or finding")
	from := flag.String("from", "", "file whose content replaces the region")
	target := flag.String("readme", "README.md", "file to update")
	check := flag.Bool("check", false, "write nothing; exit 1 when the region differs from the file")
	flag.Parse()
	if *marker == "" || *from == "" {
		fmt.Fprintln(os.Stderr, "readme: -marker and -from are required")
		os.Exit(2)
	}
	if err := run(*target, *marker, *from, *check); err != nil {
		fmt.Fprintln(os.Stderr, "readme:", err)
		os.Exit(1)
	}
}

func run(target, marker, from string, check bool) error {
	doc, err := os.ReadFile(target) //nolint:gosec // a maintainer tool run on the repository's own README
	if err != nil {
		return err
	}
	body, err := os.ReadFile(from) //nolint:gosec // the maintainer names the input file
	if err != nil {
		return err
	}
	start := "<!-- " + marker + ":start -->"
	end := "<!-- " + marker + ":end -->"
	text := strings.ReplaceAll(string(doc), "\r\n", "\n")
	i := strings.Index(text, start)
	j := strings.Index(text, end)
	if i < 0 || j < 0 || j < i {
		return fmt.Errorf("%s has no %s ... %s region", target, start, end)
	}
	content := strings.TrimSpace(strings.ReplaceAll(string(body), "\r\n", "\n"))
	out := text[:i+len(start)] + "\n" + content + "\n" + text[j:]
	if check {
		if out != text {
			return fmt.Errorf("the %s region of %s is stale: it differs from %s", marker, target, from)
		}
		return nil
	}
	return os.WriteFile(target, []byte(out), 0o644) //nolint:gosec // the README is a public file
}
