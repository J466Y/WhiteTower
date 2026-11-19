package catalog

import (
	"regexp"
	"strings"
)

// What the core flags for reviewers (plan P1-16, step 2). Flags only inform:
// they never approve or deny anything.
const (
	// FlagUnpinnedPackage marks a local server launched through npx, uvx,
	// pipx run or bunx without an exact version, which another package can
	// take the place of (threat model, T-77).
	FlagUnpinnedPackage = "unpinned_package"
	// FlagSecretInPath marks a reference whose URL path has a segment that
	// looks like a secret, for which the administrator may add a redaction
	// rule (CAT-10, T-76).
	FlagSecretInPath = "secret_in_path"
)

// flags are the flags that the core knows, which a list may filter on.
var flags = []string{FlagUnpinnedPackage, FlagSecretInPath}

// launchers are the commands that fetch the package they run, by the
// language of its registry.
var launchers = map[string]string{"npx": "npm", "bunx": "npm", "uvx": "python", "pipx": "python"}

// The options of the launchers that take a value: packageOptions name the
// package that the command comes from, in place of the first argument;
// extraOptions add a package to it; and valueOptions take anything else,
// which is not read as the package.
var (
	packageOptions = map[string]bool{"-p": true, "--package": true, "--from": true, "--spec": true}
	extraOptions   = map[string]bool{"--with": true}
	valueOptions   = map[string]bool{
		"-c": true, "--call": true, "--registry": true, "--cache": true, "--prefix": true, "--userconfig": true,
		"-w": true, "--workspace": true, "--python": true, "-i": true, "--index": true, "--index-url": true,
		"--default-index": true, "--extra-index-url": true, "-f": true, "--find-links": true,
		"--with-requirements": true, "--with-editable": true, "--constraint": true, "--override": true,
		"--directory": true, "--project": true, "--config-file": true, "--cache-dir": true, "--pip-args": true,
		"--backend": true,
	}
)

// Exact versions, as each registry's launchers write them: name@1.2.3 for
// npm, and name==1.2.3, name===1.2.3 or uv's name@1.2.3 for Python, without
// a range, a tag such as latest, or a wildcard.
var (
	npmExact    = regexp.MustCompile(`^(@[^/@\s]+/)?[^/@\s]+@[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	pythonExact = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?(==|===|@)[0-9][0-9A-Za-z.!+_-]*$`)
)

// unpinnedPackage reports whether a local server's command line launches a
// package through npx, uvx, pipx run or bunx without an exact version. The
// launcher may follow a wrapper, as in cmd /c npx. A path is not a package,
// and anything the launcher fetches that is not exactly versioned, such as a
// URL, is unpinned.
func unpinnedPackage(command []string) bool {
	for i, arg := range command {
		lang := launchers[commandName(arg)]
		if lang == "" {
			continue
		}
		args := command[i+1:]
		if commandName(arg) == "pipx" {
			if len(args) == 0 || args[0] != "run" {
				return false
			}
			args = args[1:]
		}
		specs := packageSpecs(args)
		if len(specs) == 0 {
			return true
		}
		for _, spec := range specs {
			if !isPath(spec) && !exactVersion(lang, spec) {
				return true
			}
		}
		return false
	}
	return false
}

// commandName returns a command's name without its directory or a Windows
// extension: npx for /usr/bin/npx and C:\nodejs\npx.cmd.
func commandName(arg string) string {
	name := strings.ToLower(arg[strings.LastIndexAny(arg, `/\`)+1:])
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		name = strings.TrimSuffix(name, ext)
	}
	return name
}

// packageSpecs returns what a launcher's arguments fetch: the values of its
// package options and of the options that add packages, and, unless a
// package option names the package, its first argument that is neither an
// option nor an option's value.
func packageSpecs(args []string) []string {
	var specs []string
	named := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			if !named {
				specs = append(specs, arg)
			}
			return specs
		}
		option, value, inline := strings.Cut(arg, "=")
		switch {
		case !packageOptions[option] && !extraOptions[option] && !valueOptions[option]:
			continue
		case !inline && i+1 < len(args):
			i++
			value = args[i]
		case !inline:
			continue
		}
		if packageOptions[option] || extraOptions[option] {
			specs = append(specs, value)
			named = named || packageOptions[option]
		}
	}
	return specs
}

// isPath reports whether a launcher's argument is a path on the machine
// rather than a package of a registry.
func isPath(spec string) bool {
	return strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, `\`) ||
		strings.HasPrefix(spec, "~") || len(spec) >= 2 && spec[1] == ':' && !strings.Contains(spec, "://")
}

// exactVersion reports whether a package spec names an exact version, as its
// registry's launchers write one.
func exactVersion(lang, spec string) bool {
	if lang == "npm" {
		return npmExact.MatchString(spec)
	}
	return pythonExact.MatchString(spec)
}

// minSecretSegment is the length from which a path segment can look like a
// secret.
const minSecretSegment = 20

// secretInPath reports whether a URL's path has a segment that looks like a
// secret: at least 20 characters of a token's alphabet, with at least two
// letters and two digits, and with digits and uppercase letters making at
// least a fifth of it, as a random token's do and words' seldom do. A URL
// with a query or a fragment is read up to them.
func secretInPath(u string) bool {
	_, rest, ok := strings.Cut(u, "://")
	if !ok {
		return false
	}
	start := strings.IndexByte(rest, '/')
	if start < 0 {
		return false
	}
	path := rest[start:]
	if end := strings.IndexAny(path, "?#"); end >= 0 {
		path = path[:end]
	}
	for _, segment := range strings.Split(path, "/") {
		if looksRandom(segment) {
			return true
		}
	}
	return false
}

// looksRandom reports whether a path segment looks like a random token.
func looksRandom(segment string) bool {
	if len(segment) < minSecretSegment {
		return false
	}
	var letters, digits, upper int
	for i := 0; i < len(segment); i++ {
		switch c := segment[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			upper++
			letters++
		case c >= 'a' && c <= 'z':
			letters++
		case strings.IndexByte("-._~%+=", c) >= 0:
		default:
			return false
		}
	}
	return letters >= 2 && digits >= 2 && 5*(digits+upper) >= len(segment)
}
