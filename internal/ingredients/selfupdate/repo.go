package selfupdate

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/yogzblr/imas/internal/config"
)

// Where the package file is found in the configured repository. The
// repository is the one the sprout was installed from (the Ansible role
// imas_sprout sets the same apt, rpm or NuGet repository up), so the
// sprout reads that repository's own index, in the format its package
// manager reads it, and picks the entry whose SHA-256 is the signed
// checksum. No file layout is assumed, and an entry is found by the very
// hash the download is then checked against:
//
//   - apt: dists/<suite>/<component>/binary-<arch>/Packages(.gz), the
//     stanza whose SHA256 is the checksum; its Filename, under the
//     repository URL, at most its Size bytes.
//   - rpm: repodata/repomd.xml's primary index (gzip, bzip2, zstd or
//     uncompressed), the package whose sha256
//     checksum is the checksum; its location href, under the baseurl, at
//     most its size package bytes.
//   - nuget: the service index's PackageBaseAddress (flat container),
//     <id>/<version>/<id>.<version>.nupkg, which holds the MSI at its root
//     under the signed file name (build-winget-nupkg.sh).
//   - flat: <url>/<file name>, for a mirror that serves files by name.

// Repository formats (config.SproutUpdateRepoFormat).
const (
	repoApt   = "apt"
	repoRPM   = "rpm"
	repoNuGet = "nuget"
	repoFlat  = "flat"
)

// nativeRepoFormat is the repository format for each package type.
var nativeRepoFormat = map[string]string{pkgDeb: repoApt, pkgRPM: repoRPM, pkgMSI: repoNuGet}

const (
	defaultAptDist        = "any main"
	defaultNuGetPackageID = "imas.sprout.windows.msi"
	// maxZstdWindow caps a zstd frame's window size (zstd's own default
	// limit is 512 MiB), and the index limit lowers it further.
	// createrepo_c writes 8 MiB windows or smaller.
	maxZstdWindow = 64 << 20
	// minZstdWindow is zstd's smallest window (zstd.MinWindowSize).
	minZstdWindow = 1 << 10
)

var (
	reAptDistPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	reNuGetID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Architecture names in each repository format, from GOARCH.
var (
	debArch = map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "i386", "arm": "armhf"}
	rpmArch = map[string]string{"amd64": "x86_64", "arm64": "aarch64", "386": "i686", "arm": "armv7hl"}
)

// ErrNotInRepo: the repository's index has no entry with the signed
// checksum.
var ErrNotInRepo = errors.New("selfupdate: the package is not in the update repository")

// repo is the configured update repository.
type repo struct {
	format string
	// base is the repository URL. For apt, rpm and flat its path ends in
	// "/", so index paths resolve below it; for nuget it is the service
	// index.
	base             *url.URL
	token            string
	suite, component string
	packageID        string
	debArch, rpmArch string
	limits           limits
	client           *http.Client
}

// configuredRepo validates the sprout's repository settings for p. It
// makes no request.
func configuredRepo(p platform) (repo, error) {
	r := repo{format: config.SproutUpdateRepoFormat, token: config.SproutUpdateRepoToken,
		debArch: debArch[p.arch], rpmArch: rpmArch[p.arch], limits: currentLimits()}
	if r.format == "" {
		r.format = nativeRepoFormat[p.pkgType]
	}
	switch r.format {
	case repoFlat:
	case repoApt, repoRPM, repoNuGet:
		if nativeRepoFormat[p.pkgType] != r.format {
			return r, fmt.Errorf("%w: sproutupdaterepoformat %s can't hold a .%s", ErrRepoNotConfigured, r.format, p.pkgType)
		}
	default:
		return r, fmt.Errorf("%w: sproutupdaterepoformat %q is not apt, rpm, nuget or flat", ErrRepoNotConfigured, r.format)
	}

	raw := config.SproutUpdateRepoURL
	if raw == "" {
		return r, ErrRepoNotConfigured
	}
	if r.format == repoRPM {
		if r.rpmArch == "" {
			return r, fmt.Errorf("%w: no rpm architecture for %s", ErrUnsupportedPlatform, p.arch)
		}
		raw = strings.ReplaceAll(raw, "$basearch", r.rpmArch)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil, len(raw) > maxRepoURLLen, hasControl(raw):
		return r, fmt.Errorf("%w: sproutupdaterepourl is not a valid URL", ErrRepoNotConfigured)
	case u.Scheme != "https" || u.Host == "":
		return r, fmt.Errorf("%w: sproutupdaterepourl must be an https URL", ErrRepoNotConfigured)
	case u.User != nil:
		return r, fmt.Errorf("%w: sproutupdaterepourl must not carry credentials; use sproutupdaterepotoken", ErrRepoNotConfigured)
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return r, fmt.Errorf("%w: sproutupdaterepourl must not have a query or fragment", ErrRepoNotConfigured)
	}
	if r.format != repoNuGet && !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
		u.RawPath = ""
	}
	r.base = u

	switch r.format {
	case repoApt:
		dist := config.SproutUpdateRepoDist
		if dist == "" {
			dist = defaultAptDist
		}
		f := strings.Fields(dist)
		if len(f) != 2 || !reAptDistPart.MatchString(f[0]) || !reAptDistPart.MatchString(f[1]) {
			return r, fmt.Errorf("%w: sproutupdaterepodist %q is not \"<suite> <component>\"", ErrRepoNotConfigured, dist)
		}
		r.suite, r.component = f[0], f[1]
		if r.debArch == "" {
			return r, fmt.Errorf("%w: no Debian architecture for %s", ErrUnsupportedPlatform, p.arch)
		}
	case repoNuGet:
		r.packageID = config.SproutUpdateRepoPackageID
		if r.packageID == "" {
			r.packageID = defaultNuGetPackageID
		}
		if !reNuGetID.MatchString(r.packageID) {
			return r, fmt.Errorf("%w: sproutupdaterepopackageid %q is not a NuGet package id", ErrRepoNotConfigured, r.packageID)
		}
	}
	r.client = newRepoClient(r.limits.request)
	return r, nil
}

func (r repo) String() string {
	return r.format + " repository " + redact(r.base)
}

// fetchPackage finds m's package in the repository and writes it to dest,
// checked against the signed checksum. dir is a private staging
// directory for intermediate files.
func (r repo) fetchPackage(ctx context.Context, m release, dir, dest string) (*url.URL, error) {
	switch r.format {
	case repoFlat:
		u, err := resolveRef(r.base, m.FileName)
		if err != nil {
			return nil, err
		}
		return u, r.download(ctx, u, dest, m.ChecksumSHA256, r.limits.packageBytes)
	case repoApt:
		u, size, err := r.locateApt(ctx, m.ChecksumSHA256)
		if err != nil {
			return nil, err
		}
		if err := r.checkDeclared(u, size); err != nil {
			return nil, err
		}
		return u, r.download(ctx, u, dest, m.ChecksumSHA256, r.limits.declaredCap(size))
	case repoRPM:
		u, size, err := r.locateRPM(ctx, m.ChecksumSHA256)
		if err != nil {
			return nil, err
		}
		if err := r.checkDeclared(u, size); err != nil {
			return nil, err
		}
		return u, r.download(ctx, u, dest, m.ChecksumSHA256, r.limits.declaredCap(size))
	case repoNuGet:
		u, err := r.locateNuGet(ctx, m.Version)
		if err != nil {
			return nil, err
		}
		return u, r.downloadFromNupkg(ctx, u, dir, m.FileName, dest, m.ChecksumSHA256)
	}
	return nil, fmt.Errorf("%w: format %q", ErrRepoNotConfigured, r.format)
}

// checkDeclared refuses, before anything is downloaded, a package whose
// index entry declares more than the package limit.
func (r repo) checkDeclared(u *url.URL, declared int64) error {
	if declared > r.limits.packageBytes {
		return fmt.Errorf("%w: the index declares %s as %d bytes, over the %d byte limit", ErrTooLarge, redact(u), declared, r.limits.packageBytes)
	}
	return nil
}

// resolveRef resolves ref, a path or URL an index gave, against base. The
// result must be https and carry no credentials.
func resolveRef(base *url.URL, ref string) (*url.URL, error) {
	if ref == "" || len(ref) > maxRepoURLLen || hasControl(ref) {
		return nil, fmt.Errorf("selfupdate: the repository index names an invalid location %q", ref)
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: the repository index names an invalid location %q", ref)
	}
	u := base.ResolveReference(refURL)
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("selfupdate: the repository index names %s, which is not a plain https URL", redact(u))
	}
	return u, nil
}

// fetchIndex GETs base/rel and returns its body, decompressed by rel's
// extension (.gz, .bz2 or .zst), capped at r.limits.indexBytes both as
// downloaded and as decompressed: reading past either cap is an
// ErrTooLarge error, never a silently truncated index. The caller closes
// it.
func (r repo) fetchIndex(ctx context.Context, base *url.URL, rel string) (io.ReadCloser, error) {
	u, err := resolveRef(base, rel)
	if err != nil {
		return nil, err
	}
	maxBytes := r.limits.indexBytes
	resp, err := r.get(ctx, u, maxBytes)
	if err != nil {
		return nil, err
	}
	body := io.Reader(&cappedReader{r: resp.Body, left: maxBytes, limit: maxBytes, what: redact(u)})
	closer := io.Closer(resp.Body)
	switch path.Ext(u.Path) {
	case ".gz":
		zr, err := gzip.NewReader(body)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("selfupdate: %s: %w", redact(u), err)
		}
		body = zr
	case ".bz2":
		body = bzip2.NewReader(body)
	case ".zst":
		// createrepo_c's default for repodata since 1.0. One goroutine,
		// and a window and memory bounded by the index limit, so a
		// hostile frame header can't make the decoder allocate more.
		window := uint64(min(maxZstdWindow, maxBytes))
		zr, err := zstd.NewReader(body,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxWindow(max(window, minZstdWindow)),
			zstd.WithDecoderMaxMemory(uint64(maxBytes)))
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("selfupdate: %s: %w", redact(u), err)
		}
		body = zstdLimitErrors{zr}
		closer = closers{zr.IOReadCloser(), resp.Body}
	case ".xml", ".json", "":
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("selfupdate: %s: unsupported index compression %s (gzip, bzip2, zstd or none)", redact(u), path.Ext(u.Path))
	}
	return readCloser{&cappedReader{r: body, left: maxBytes, limit: maxBytes, what: redact(u) + " (decompressed)"}, closer}, nil
}

// zstdLimitErrors reports the zstd decoder's own memory and window
// refusals as ErrTooLarge, like every other index limit.
type zstdLimitErrors struct{ r io.Reader }

func (z zstdLimitErrors) Read(p []byte) (int, error) {
	n, err := z.r.Read(p)
	if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) {
		err = fmt.Errorf("%w: %w", ErrTooLarge, err)
	}
	return n, err
}

// cappedReader reads at most left bytes from r and then fails with
// ErrTooLarge if r has more: an index cut off at the cap would otherwise
// read as a shorter, valid one.
type cappedReader struct {
	r           io.Reader
	left, limit int64
	what        string
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, err := c.r.Read(one[:]); n > 0 {
			return 0, fmt.Errorf("%w: %s is over the %d byte index limit (sproutupdatemaxindexbytes)", ErrTooLarge, c.what, c.limit)
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

type readCloser struct {
	io.Reader
	io.Closer
}

// closers closes each of its members, in order.
type closers []io.Closer

func (c closers) Close() error {
	var errs []error
	for _, cl := range c {
		errs = append(errs, cl.Close())
	}
	return errors.Join(errs...)
}

// locateApt reads the repository's Packages index for this sprout's
// architecture and returns the URL of the entry whose SHA256 is sum, and
// the Size it declares (0 if none).
func (r repo) locateApt(ctx context.Context, sum string) (*url.URL, int64, error) {
	dir := "dists/" + r.suite + "/" + r.component + "/binary-" + r.debArch + "/"
	var lastErr error
	for _, name := range []string{"Packages.gz", "Packages"} {
		body, err := r.fetchIndex(ctx, r.base, dir+name)
		var status *httpStatusError
		if errors.As(err, &status) && status.status == http.StatusNotFound {
			lastErr = err
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		filename, size, err := aptFilenameFor(body, sum)
		body.Close()
		if err != nil {
			return nil, 0, err
		}
		if filename == "" {
			return nil, 0, fmt.Errorf("%w: no entry with sha256 %s in %s%s", ErrNotInRepo, sum, redact(r.base), dir+name)
		}
		u, err := resolveRef(r.base, filename)
		return u, size, err
	}
	return nil, 0, lastErr
}

// aptFilenameFor returns the Filename of the stanza in a Packages index
// whose SHA256 field is sum, or "" if there is none, and the Size that
// stanza declares (0 if it has none). A Size that is not a positive
// number is an error.
func aptFilenameFor(index io.Reader, sum string) (string, int64, error) {
	sc := bufio.NewScanner(index)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var filename, sha, size string
	flush := func() (string, int64, error) {
		defer func() { filename, sha, size = "", "", "" }()
		if sha != sum || filename == "" {
			return "", 0, nil
		}
		n, err := declaredSize(size)
		return filename, n, err
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if f, n, err := flush(); f != "" || err != nil {
				return f, n, err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // a continuation line
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "Filename":
			filename = strings.TrimSpace(v)
		case "SHA256":
			sha = strings.ToLower(strings.TrimSpace(v))
		case "Size":
			size = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, fmt.Errorf("selfupdate: reading the apt Packages index: %w", err)
	}
	return flush()
}

// declaredSize parses a package size an index declares: "" is 0 (none
// declared), anything else must be a positive decimal number.
func declaredSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("selfupdate: the repository index declares the package size %q, not a positive number", s)
	}
	return n, nil
}

// locateRPM reads the repository's primary index and returns the URL of
// the package whose sha256 checksum is sum, and the size it declares (0
// if none).
func (r repo) locateRPM(ctx context.Context, sum string) (*url.URL, int64, error) {
	body, err := r.fetchIndex(ctx, r.base, "repodata/repomd.xml")
	if err != nil {
		return nil, 0, err
	}
	var repomd struct {
		Data []struct {
			Type     string `xml:"type,attr"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	err = xml.NewDecoder(body).Decode(&repomd)
	body.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("selfupdate: parsing repomd.xml: %w", err)
	}
	primary := ""
	for _, d := range repomd.Data {
		if d.Type == "primary" {
			primary = d.Location.Href
		}
	}
	if primary == "" {
		return nil, 0, errors.New("selfupdate: repomd.xml lists no primary index")
	}
	body, err = r.fetchIndex(ctx, r.base, primary)
	if err != nil {
		return nil, 0, err
	}
	defer body.Close()
	href, base, size, err := rpmLocationFor(body, sum)
	if err != nil {
		return nil, 0, err
	}
	if href == "" {
		return nil, 0, fmt.Errorf("%w: no package with sha256 %s in %s", ErrNotInRepo, sum, redact(r.base))
	}
	against := r.base
	if base != "" {
		if against, err = resolveRef(r.base, base); err != nil {
			return nil, 0, err
		}
		if !strings.HasSuffix(against.Path, "/") {
			against.Path += "/"
		}
	}
	u, err := resolveRef(against, href)
	return u, size, err
}

// rpmLocationFor streams a primary.xml index and returns the location
// href (and xml:base, if any) of the package whose sha256 checksum is
// sum, or "" if there is none, and the size package the entry declares
// (0 if none).
func rpmLocationFor(index io.Reader, sum string) (href, base string, size int64, err error) {
	dec := xml.NewDecoder(index)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return "", "", 0, nil
		}
		if err != nil {
			return "", "", 0, fmt.Errorf("selfupdate: parsing the rpm primary index: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "package" {
			continue
		}
		var pkg struct {
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
				Base string `xml:"http://www.w3.org/XML/1998/namespace base,attr"`
			} `xml:"location"`
			Size struct {
				Package string `xml:"package,attr"`
			} `xml:"size"`
		}
		if err := dec.DecodeElement(&pkg, &se); err != nil {
			return "", "", 0, fmt.Errorf("selfupdate: parsing the rpm primary index: %w", err)
		}
		if pkg.Checksum.Type == "sha256" && strings.ToLower(strings.TrimSpace(pkg.Checksum.Value)) == sum {
			n, err := declaredSize(strings.TrimSpace(pkg.Size.Package))
			return pkg.Location.Href, pkg.Location.Base, n, err
		}
	}
}

// locateNuGet reads the NuGet v3 service index and returns the flat
// container URL of r.packageID at version (a manifest version, "v1.2.3").
func (r repo) locateNuGet(ctx context.Context, version string) (*url.URL, error) {
	body, err := r.fetchIndex(ctx, r.base, r.base.String())
	if err != nil {
		return nil, err
	}
	var index struct {
		Resources []struct {
			ID   string `json:"@id"`
			Type string `json:"@type"`
		} `json:"resources"`
	}
	err = json.NewDecoder(body).Decode(&index)
	body.Close()
	if err != nil {
		return nil, fmt.Errorf("selfupdate: parsing the NuGet service index: %w", err)
	}
	flat := ""
	for _, res := range index.Resources {
		if res.Type == "PackageBaseAddress/3.0.0" {
			flat = res.ID
			break
		}
	}
	if flat == "" {
		return nil, errors.New("selfupdate: the NuGet service index has no PackageBaseAddress/3.0.0")
	}
	base, err := resolveRef(r.base, flat)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	// NuGet's flat container uses the lower-cased id and normalized
	// version; a canonical semver without the "v" is already normalized.
	id := strings.ToLower(r.packageID)
	ver := strings.ToLower(strings.TrimPrefix(version, "v"))
	return resolveRef(base, id+"/"+ver+"/"+id+"."+ver+".nupkg")
}
