package seed

import (
	"regexp"
	"strings"
)

var (
	dockerNoUser = infraCheck{
		id: "docker-no-user", title: "Container runs as root because no USER is set",
		class: "container-hardening", cwe: "CWE-250", severity: "medium",
		detail: "The final image stage never switches away from root, so the application runs with root privileges inside the container and a compromise of the process is a compromise of everything the container can reach.",
		fix:    "Create an unprivileged user in the image and add a USER instruction before the entrypoint.",
	}
	dockerUserRoot = infraCheck{
		id: "docker-user-root", title: "Container explicitly runs as root",
		class: "container-hardening", cwe: "CWE-250", severity: "medium",
		detail: "The last USER instruction selects root, so the application runs with root privileges inside the container.",
		fix:    "Switch to an unprivileged user with a later USER instruction once the privileged build steps are done.",
	}
	dockerFromLatest = infraCheck{
		id: "docker-from-unpinned", title: "Base image is untagged or uses latest",
		class: "supply-chain", cwe: "CWE-1357", severity: "low",
		detail: "The base image is not pinned to a version, so every build may pull different contents and a compromised or broken upstream release enters the image unnoticed.",
		fix:    "Pin the base image to a specific version tag, and preferably to a digest.",
	}
	dockerAddRemote = infraCheck{
		id: "docker-add-remote", title: "ADD downloads a remote file without verification",
		class: "supply-chain", cwe: "CWE-494", severity: "medium",
		detail: "ADD with a URL fetches content at build time with no integrity check, so whoever controls that URL or the network path controls what goes into the image.",
		fix:    "Download with a pinned checksum (ADD --checksum, or curl followed by sha256sum -c), or copy the file from the build context.",
	}
	dockerCurlPipe = infraCheck{
		id: "docker-curl-pipe-shell", title: "Remote script piped into a shell",
		class: "supply-chain", cwe: "CWE-494", severity: "high",
		detail: "A script is downloaded and executed in one step with no integrity check, so whoever controls that URL or the network path runs code in the build.",
		fix:    "Download the script to a file, verify it against a pinned checksum, then run it. Prefer a packaged release of the tool.",
	}
	dockerEnvSecret = infraCheck{
		id: "docker-env-secret", title: "Secret written into the image by ENV or ARG",
		class: "hardcoded-secret", cwe: "CWE-798", severity: "high",
		detail: "ENV and ARG values are stored in the image metadata and history, so everyone who can pull the image can read this credential.",
		fix:    "Rotate the credential, then supply it at run time through the environment or a secret mount (RUN --mount=type=secret) instead of baking it into the image.",
	}
	dockerPrivileged = infraCheck{
		id: "docker-privileged", title: "Privileged mode requested in the image build",
		class: "container-hardening", cwe: "CWE-250", severity: "medium",
		detail: "The --privileged flag removes container isolation for the step that uses it, giving it full access to the host's devices and kernel interfaces.",
		fix:    "Remove --privileged and grant only the specific capability or mount the step needs.",
	}
	dockerChmod777 = infraCheck{
		id: "docker-chmod-777", title: "World-writable permissions set in the image",
		class: "container-hardening", cwe: "CWE-732", severity: "medium",
		detail: "chmod 777 lets every user in the container replace these files, which turns any low-privilege foothold into control of whatever executes them.",
		fix:    "Grant the narrowest mode that works, for example 755 for executables and 644 for data, owned by the user that needs them.",
	}

	dockerCurlPipeRe   = regexp.MustCompile(`\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh\b`)
	dockerPrivilegedRe = regexp.MustCompile(`(?:^|\s)--privileged\b`)
	dockerChmodRe      = regexp.MustCompile(`\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b`)
	dockerRemoteRe     = regexp.MustCompile(`(?i)\bhttps?://`)
	dockerEnvPairRe    = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S*)`)
)

// dockerInstr is one logical instruction with its continuation lines joined.
type dockerInstr struct {
	line int    // 1-based line where the instruction starts
	name string // upper-case instruction
	args string
	raw  string // first physical line, for snippets
}

func parseDockerfile(text string) []dockerInstr {
	var out []dockerInstr
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		start, raw := i, lines[i]
		joined := trimmed
		for strings.HasSuffix(joined, `\`) && i+1 < len(lines) {
			i++
			next := strings.TrimSpace(lines[i])
			joined = strings.TrimSuffix(joined, `\`)
			if strings.HasPrefix(next, "#") {
				// Comment lines inside a continuation are dropped by Docker.
				joined += `\`
				continue
			}
			joined += " " + next
		}
		joined = strings.TrimSuffix(joined, `\`)
		name, args := joined, ""
		if j := strings.IndexAny(joined, " \t"); j >= 0 {
			name, args = joined[:j], joined[j+1:]
		}
		out = append(out, dockerInstr{line: start + 1, name: strings.ToUpper(name), args: strings.TrimSpace(args), raw: raw})
	}
	return out
}

func dockerLeads(rel, text string) []Lead {
	var leads []Lead
	instrs := parseDockerfile(text)
	stages := map[string]bool{}
	var lastFrom, lastUser *dockerInstr
	for i := range instrs {
		in := &instrs[i]
		switch in.name {
		case "FROM":
			lastFrom, lastUser = in, nil
			image, alias := parseFrom(in.args)
			if fromUnpinned(image, stages) {
				leads = append(leads, dockerFromLatest.lead(rel, in.line, in.raw))
			}
			if alias != "" {
				stages[strings.ToLower(alias)] = true
			}
		case "USER":
			lastUser = in
		case "ADD":
			if dockerRemoteRe.MatchString(in.args) && !strings.Contains(in.args, "--checksum=") {
				leads = append(leads, dockerAddRemote.lead(rel, in.line, in.raw))
			}
		case "RUN":
			if dockerCurlPipeRe.MatchString(in.args) {
				leads = append(leads, dockerCurlPipe.lead(rel, in.line, in.raw))
			}
			if dockerPrivilegedRe.MatchString(in.args) {
				leads = append(leads, dockerPrivileged.lead(rel, in.line, in.raw))
			}
			if dockerChmodRe.MatchString(in.args) {
				leads = append(leads, dockerChmod777.lead(rel, in.line, in.raw))
			}
		case "ENV", "ARG":
			if name, value, ok := dockerSecretPair(in.args); ok {
				// The snippet is rebuilt from the name and a marker instead
				// of editing the source line, so no part of the value can
				// survive a missed replacement.
				leads = append(leads, dockerEnvSecret.lead(rel, in.line, in.name+" "+name+"="+redactedValue(dockerEnvSecret.id, value)))
			}
		}
	}
	// A file with no FROM is a fragment or not a Dockerfile; the USER
	// checks would only be noise there.
	if lastFrom != nil {
		switch {
		case lastUser == nil:
			leads = append(leads, dockerNoUser.lead(rel, lastFrom.line, lastFrom.raw))
		case isRootUser(lastUser.args):
			leads = append(leads, dockerUserRoot.lead(rel, lastUser.line, lastUser.raw))
		}
	}
	return leads
}

// parseFrom returns the image reference and the stage alias of a FROM line.
func parseFrom(args string) (image, alias string) {
	fields := strings.Fields(args)
	var rest []string
	for _, f := range fields {
		if strings.HasPrefix(f, "--") {
			continue
		}
		rest = append(rest, f)
	}
	if len(rest) == 0 {
		return "", ""
	}
	if len(rest) >= 3 && strings.EqualFold(rest[1], "AS") {
		alias = rest[2]
	}
	return rest[0], alias
}

func fromUnpinned(image string, stages map[string]bool) bool {
	low := strings.ToLower(image)
	// scratch has no versions, an earlier stage is local, and a reference
	// built from a build argument cannot be judged from the file alone.
	if image == "" || low == "scratch" || stages[low] || strings.Contains(image, "$") {
		return false
	}
	return imageUnpinned(image)
}

// imageUnpinned reports whether an image reference has no tag, or the
// latest tag, and no digest.
func imageUnpinned(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	name := image[strings.LastIndex(image, "/")+1:]
	_, tag, ok := strings.Cut(name, ":")
	return !ok || tag == "" || tag == "latest"
}

func isRootUser(args string) bool {
	user, _, _ := strings.Cut(strings.TrimSpace(args), ":")
	return user == "root" || user == "0"
}

// dockerSecretPair finds the first NAME=value (or the legacy "ENV NAME
// value") pair whose name looks like a credential and whose value is a
// literal.
func dockerSecretPair(args string) (name, value string, ok bool) {
	if first, rest, cut := strings.Cut(args, " "); !strings.Contains(first, "=") {
		if !cut {
			return "", "", false // ARG NAME with no default
		}
		value = unquote(strings.TrimSpace(rest))
		return first, value, looksLikeSecretPair(first, value)
	}
	for _, m := range dockerEnvPairRe.FindAllStringSubmatch(args, -1) {
		value = unquote(m[2])
		if looksLikeSecretPair(m[1], value) {
			return m[1], value, true
		}
	}
	return "", "", false
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
