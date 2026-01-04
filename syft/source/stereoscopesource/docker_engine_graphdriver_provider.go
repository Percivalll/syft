package stereoscopesource

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// DockerEngineGraphDriver is a custom stereoscope image provider that reads image metadata and layer content
// directly from a Linux Docker Engine root directory (e.g. /var/lib/docker) using the graphdriver layout.
//
// User input format (two parameters only):
//
//	docker-engine:<imageID>|<engineRootDir>
//
// Where:
// - imageID: docker image config digest (accepts "sha256:<hex>" or "<hex>")
// - engineRootDir: docker engine root directory (must contain image/<driver>/... and <driver>/... directories)
//
// Only the overlay2 graphdriver layout is considered.
const DockerGraphdriverSource = "docker-graphdriver"
const DockerGraphDriver image.Source = DockerGraphdriverSource

type dockerGraphDriverProvider struct {
	tmpDirGen          *stereofile.TempDirGenerator
	path               string
	additionalMetadata []image.AdditionalMetadata
}

func NewDockerEngineGraphDriverProvider(tmpDirGen *file.TempDirGenerator, path string, additionalMetadata ...image.AdditionalMetadata) image.Provider {
	return &dockerGraphDriverProvider{
		tmpDirGen:          tmpDirGen,
		path:               path,
		additionalMetadata: additionalMetadata,
	}
}

func (p *dockerGraphDriverProvider) Name() string {
	return DockerGraphDriver
}

func (p *dockerGraphDriverProvider) Provide(_ context.Context) (*image.Image, error) {
	imageID, engineRoot, err := parseDockerEngineUserInput(p.path)
	if err != nil {
		// user explicitly selected this provider scheme; surface a clear error
		return nil, err
	}

	// Currently we only consider overlay2, but we detect it explicitly to provide better errors.
	const driver = "overlay2"
	if err := validateDockerEngineOverlay2Root(engineRoot); err != nil {
		// user explicitly selected this provider scheme, so do NOT hide the error behind os.ErrNotExist
		return nil, err
	}

	resolvedImageID, err := resolveDockerEngineImageID(engineRoot, driver, imageID)
	if err != nil {
		return nil, err
	}
	imageID = resolvedImageID

	configPath := dockerEngineImageConfigPath(engineRoot, driver, imageID)
	rawConfig, err := os.ReadFile(configPath)
	if err != nil {
		// user explicitly selected this provider scheme, so do NOT hide the error behind os.ErrNotExist
		// also do NOT preserve os.ErrNotExist via wrapping, since syft will suppress it
		return nil, fmt.Errorf("docker engine image config not found/readable at %q: %v", configPath, err)
	}

	var cfg v1.ConfigFile
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("unable to parse docker engine image config %q: %w", configPath, err)
	}

	// Build layers based on config.rootfs.diff_ids and layerdb cache-id mappings.
	layers, err := dockerEngineOverlay2Layers(engineRoot, driver, cfg.RootFS.DiffIDs)
	if err != nil {
		return nil, err
	}

	v1img := &dockerEngineV1Image{
		rawConfig: rawConfig,
		cfg:       &cfg,
		layers:    layers,
		mediaType: types.DockerManifestSchema2,
	}

	// Best-effort tags from repositories.json (optional).
	var metadata []image.AdditionalMetadata
	if tags, err := dockerEngineRepoTags(engineRoot, driver, imageID); err == nil && len(tags) > 0 {
		metadata = append(metadata, image.WithTags(tags...))
	}

	metadata = append(metadata, p.additionalMetadata...)

	contentTempDir, err := p.tmpDirGen.NewDirectory("docker-engine-image")
	if err != nil {
		return nil, err
	}

	out := image.New(v1img, p.tmpDirGen, contentTempDir, metadata...)
	if err := out.Read(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseDockerEngineUserInput(userInput string) (imageID string, engineRoot string, err error) {
	sepIdx := strings.IndexAny(userInput, "|")
	if sepIdx <= 0 || sepIdx >= len(userInput)-1 {
		return "", "", fmt.Errorf("invalid docker-engine user input: expected %q<imageID>|<engineRootDir>", DockerGraphdriverSource)
	}

	imageID = strings.TrimSpace(userInput[:sepIdx])
	engineRoot = strings.TrimSpace(userInput[sepIdx+1:])
	if imageID == "" || engineRoot == "" {
		return "", "", fmt.Errorf("invalid docker-engine user input: expected %q<imageID>|<engineRootDir>", DockerGraphdriverSource)
	}

	// normalize image id
	imageID = strings.TrimPrefix(imageID, "sha256:")
	if len(imageID) < 12 || len(imageID) > 64 {
		return "", "", fmt.Errorf("invalid docker-engine imageID %q: expected 12-64 characters", imageID)
	}
	if _, err := hex.DecodeString(imageID); err != nil {
		return "", "", fmt.Errorf("invalid docker-engine imageID %q: expected hex characters", imageID)
	}

	if !filepath.IsAbs(engineRoot) {
		return "", "", fmt.Errorf("invalid docker-engine engineRoot %q: expected absolute path", engineRoot)
	}

	return imageID, filepath.Clean(engineRoot), nil
}

func validateDockerEngineOverlay2Root(engineRoot string) error {
	overlay2ImageRoot := filepath.Join(engineRoot, "image", "overlay2")
	if _, err := os.Stat(overlay2ImageRoot); err == nil {
		return nil
	}

	// Provide a useful error message: list available driver directories under engineRoot/image.
	imageRoot := filepath.Join(engineRoot, "image")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return fmt.Errorf("unable to access docker engine rootDir %q (expected %q): %v", engineRoot, imageRoot, err)
	}

	var drivers []string
	for _, e := range entries {
		if e.IsDir() {
			drivers = append(drivers, e.Name())
		}
	}
	sort.Strings(drivers)

	return fmt.Errorf("docker engine rootDir %q does not appear to use overlay2 graphdriver (expected %q); found drivers under %q: %v",
		engineRoot,
		overlay2ImageRoot,
		imageRoot,
		drivers,
	)
}

func resolveDockerEngineImageID(engineRoot, driver, imageID string) (string, error) {
	// If the config blob exists for the given ID, accept it.
	if len(imageID) == 64 {
		p := dockerEngineImageConfigPath(engineRoot, driver, imageID)
		if _, err := os.Stat(p); err == nil {
			return imageID, nil
		}
	}

	// Otherwise treat as a prefix and try to resolve uniquely.
	contentDir := filepath.Join(engineRoot, "image", driver, "imagedb", "content", "sha256")
	entries, err := os.ReadDir(contentDir)
	if err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return "", fmt.Errorf("unable to read docker engine image content dir %q: %v", contentDir, err)
	}

	var matches []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, imageID) {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("docker engine imageID %q not found under %q (expected a config digest)", imageID, contentDir)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("docker engine imageID prefix %q is ambiguous under %q: %v", imageID, contentDir, matches)
	}
}

func dockerEngineImageConfigPath(engineRoot, driver, imageIDHex string) string {
	// image/overlay2/imagedb/content/sha256/<hex>
	return filepath.Join(engineRoot, "image", driver, "imagedb", "content", "sha256", imageIDHex)
}

func dockerEngineOverlay2Layers(engineRoot, driver string, diffIDs []v1.Hash) ([]v1.Layer, error) {
	if len(diffIDs) == 0 {
		// images with no layers are possible; stereoscope can handle this.
		return nil, nil
	}

	chainIDs, err := dockerEngineChainIDs(diffIDs)
	if err != nil {
		return nil, err
	}

	// Only build this index if we fail to resolve cache-id directly (can be large on real systems).
	var layerdbByDiffID map[string]string

	out := make([]v1.Layer, 0, len(diffIDs))
	for idx, diffID := range diffIDs {
		if diffID.Algorithm != "sha256" || diffID.Hex == "" {
			return nil, fmt.Errorf("unexpected diffID in config: %s", diffID.String())
		}

		// Docker's on-disk layerdb is keyed by chainID (not diffID) after the first layer.
		// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
		chainIDHex := chainIDs[idx]
		cacheIDBytes, cacheIDPath, err := dockerEngineReadLayerCacheID(engineRoot, driver, diffID.Hex, chainIDHex, &layerdbByDiffID)
		if err != nil {
			return nil, err
		}
		cacheID := strings.TrimSpace(string(cacheIDBytes))
		if cacheID == "" {
			return nil, fmt.Errorf("empty layer cache-id at %q", cacheIDPath)
		}

		diffDir := filepath.Join(engineRoot, driver, cacheID, "diff")
		if _, err := os.Stat(diffDir); err != nil {
			// do not preserve os.ErrNotExist through wrapping
			return nil, fmt.Errorf("docker engine layer diff directory not found/readable at %q: %v", diffDir, err)
		}

		out = append(out, &overlay2DiffLayer{
			diffID:    diffID,
			diffDir:   diffDir,
			mediaType: types.OCIUncompressedLayer,
		})
	}

	return out, nil
}

func dockerEngineReadLayerCacheID(engineRoot, driver, diffIDHex, chainIDHex string, layerdbByDiffID *map[string]string) ([]byte, string, error) {
	layerdbRoot := filepath.Join(engineRoot, "image", driver, "layerdb", "sha256")

	// 1) try chainID key
	cacheIDPath := filepath.Join(layerdbRoot, chainIDHex, "cache-id")
	if b, err := os.ReadFile(cacheIDPath); err == nil {
		return b, cacheIDPath, nil
	}

	// 2) try diffID key (some installations / versions may differ)
	cacheIDPath2 := filepath.Join(layerdbRoot, diffIDHex, "cache-id")
	if b, err := os.ReadFile(cacheIDPath2); err == nil {
		return b, cacheIDPath2, nil
	}

	// 3) slow-path: build (or reuse) an index of diffID -> layerdb directory name by reading layerdb/*/diff files
	if layerdbByDiffID == nil {
		return nil, "", fmt.Errorf("internal error: layerdbByDiffID is nil")
	}
	if *layerdbByDiffID == nil {
		idx, err := dockerEngineIndexLayerdbByDiffID(layerdbRoot)
		if err != nil {
			return nil, "", err
		}
		*layerdbByDiffID = idx
	}

	if dirHex, ok := (*layerdbByDiffID)[diffIDHex]; ok {
		cacheIDPath3 := filepath.Join(layerdbRoot, dirHex, "cache-id")
		b, err := os.ReadFile(cacheIDPath3)
		if err == nil {
			return b, cacheIDPath3, nil
		}
		// do not preserve os.ErrNotExist through wrapping
		return nil, "", fmt.Errorf("docker engine layer cache-id not found/readable at %q (diffID=sha256:%s chainID=sha256:%s resolvedLayerdbKey=sha256:%s): %v",
			cacheIDPath3, diffIDHex, chainIDHex, dirHex, err)
	}

	// do not preserve os.ErrNotExist through wrapping
	return nil, "", fmt.Errorf("docker engine layer cache-id not found (tried chainID and diffID) and diffID could not be resolved via layerdb index (diffID=sha256:%s chainID=sha256:%s); tried: %q and %q; scanned: %q",
		diffIDHex, chainIDHex, cacheIDPath, cacheIDPath2, layerdbRoot)
}

func dockerEngineIndexLayerdbByDiffID(layerdbRoot string) (map[string]string, error) {
	entries, err := os.ReadDir(layerdbRoot)
	if err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return nil, fmt.Errorf("unable to read docker engine layerdb root %q: %v", layerdbRoot, err)
	}

	out := make(map[string]string)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirHex := e.Name()
		if len(dirHex) != 64 {
			continue
		}
		if _, err := hex.DecodeString(dirHex); err != nil {
			continue
		}

		diffPath := filepath.Join(layerdbRoot, dirHex, "diff")
		b, err := os.ReadFile(diffPath)
		if err != nil {
			continue
		}
		diff := strings.TrimSpace(string(b))
		diff = strings.TrimPrefix(diff, "sha256:")
		if len(diff) != 64 {
			continue
		}
		if _, err := hex.DecodeString(diff); err != nil {
			continue
		}
		// First match wins; collisions are unexpected.
		if _, exists := out[diff]; !exists {
			out[diff] = dirHex
		}
	}

	return out, nil
}

func dockerEngineChainIDs(diffIDs []v1.Hash) ([]string, error) {
	if len(diffIDs) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(diffIDs))

	// chainID(L0) = diffID(L0)
	prev := diffIDs[0]
	if prev.Algorithm != "sha256" || prev.Hex == "" {
		return nil, fmt.Errorf("unexpected diffID in config: %s", prev.String())
	}
	out = append(out, prev.Hex)

	// chainID(Li) = sha256( diffID(Li) + " " + chainID(Li-1) )
	for _, d := range diffIDs[1:] {
		if d.Algorithm != "sha256" || d.Hex == "" {
			return nil, fmt.Errorf("unexpected diffID in config: %s", d.String())
		}
		// IMPORTANT: order matters and is defined by the OCI image-spec.
		// chainID(Li) = sha256( diffID(Li) + " " + chainID(Li-1) )
		s := prev.String() + " " + d.String()
		sum := sha256.Sum256([]byte(s))
		hexSum := hex.EncodeToString(sum[:])
		out = append(out, hexSum)
		prev = v1.Hash{Algorithm: "sha256", Hex: hexSum}
	}

	return out, nil
}

// dockerEngineRepoTags reads image/<driver>/repositories.json and returns all tags that resolve to imageIDHex.
// This is best-effort: failures return an error but the provider can continue without tags.
func dockerEngineRepoTags(engineRoot, driver, imageIDHex string) ([]string, error) {
	path := filepath.Join(engineRoot, "image", driver, "repositories.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	type repositories struct {
		Repositories map[string]map[string]string `json:"Repositories"`
	}
	var r repositories
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}

	var tags []string
	for _, tagMap := range r.Repositories {
		for tag, id := range tagMap {
			id = strings.TrimPrefix(strings.TrimSpace(id), "sha256:")
			if id == imageIDHex {
				// NOTE: in most docker installations, tagMap keys are simple tags like "latest".
				// However, in some environments we've seen unexpected values that already include ":".
				// If the key already looks like a full reference (contains ":" or "@"), use it as-is to
				// avoid producing invalid strings like "mongo:mongo:6.0.5".
				if strings.ContainsAny(tag, ":@") {
					tags = append(tags, tag)
				} else {
					tags = append(tags, tag)
				}
			}
		}
	}
	sort.Strings(tags)
	return tags, nil
}

// dockerEngineV1Image implements v1.Image using docker engine on-disk metadata + custom layers.
type dockerEngineV1Image struct {
	rawConfig []byte
	cfg       *v1.ConfigFile
	layers    []v1.Layer
	mediaType types.MediaType
}

var _ v1.Image = (*dockerEngineV1Image)(nil)

func (i *dockerEngineV1Image) Layers() ([]v1.Layer, error) {
	return i.layers, nil
}

func (i *dockerEngineV1Image) MediaType() (types.MediaType, error) {
	return i.mediaType, nil
}

func (i *dockerEngineV1Image) Size() (int64, error) {
	// best-effort: manifest size is unknown; return 0.
	return 0, nil
}

func (i *dockerEngineV1Image) ConfigName() (v1.Hash, error) {
	sum := sha256.Sum256(i.rawConfig)
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(sum[:])}, nil
}

func (i *dockerEngineV1Image) ConfigFile() (*v1.ConfigFile, error) {
	return i.cfg, nil
}

func (i *dockerEngineV1Image) RawConfigFile() ([]byte, error) {
	return i.rawConfig, nil
}

func (i *dockerEngineV1Image) Digest() (v1.Hash, error) {
	// best-effort digest over our synthesized manifest bytes.
	m, err := i.RawManifest()
	if err != nil {
		return v1.Hash{}, err
	}
	sum := sha256.Sum256(m)
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(sum[:])}, nil
}

func (i *dockerEngineV1Image) Manifest() (*v1.Manifest, error) {
	// Minimal manifest; layer digests are best-effort (we don't have compressed digests in graphdriver).
	cfgHash, err := i.ConfigName()
	if err != nil {
		return nil, err
	}

	layers := make([]v1.Descriptor, 0, len(i.layers))
	for _, l := range i.layers {
		d, err := l.Digest()
		if err != nil {
			// fallback to diffID
			d, _ = l.DiffID()
		}
		mt, _ := l.MediaType()
		layers = append(layers, v1.Descriptor{
			MediaType: mt,
			Digest:    d,
			Size:      0,
		})
	}

	return &v1.Manifest{
		SchemaVersion: 2,
		Config: v1.Descriptor{
			MediaType: types.OCIConfigJSON,
			Digest:    cfgHash,
			Size:      int64(len(i.rawConfig)),
		},
		Layers: layers,
	}, nil
}

func (i *dockerEngineV1Image) RawManifest() ([]byte, error) {
	m, err := i.Manifest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func (i *dockerEngineV1Image) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	// best-effort: our layer digest == diffID (or unknown), so allow matching on either.
	for _, l := range i.layers {
		d, _ := l.Digest()
		if d == h {
			return l, nil
		}
		dd, _ := l.DiffID()
		if dd == h {
			return l, nil
		}
	}
	return nil, fmt.Errorf("layer not found by digest %s", h.String())
}

func (i *dockerEngineV1Image) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	for _, l := range i.layers {
		dd, _ := l.DiffID()
		if dd == h {
			return l, nil
		}
	}
	return nil, fmt.Errorf("layer not found by diffID %s", h.String())
}

// overlay2DiffLayer implements v1.Layer by tarring the overlay2 "diff" directory on demand (uncompressed).
// This avoids docker save/export and avoids decompressing compressed blobs.
type overlay2DiffLayer struct {
	diffID    v1.Hash
	diffDir   string
	mediaType types.MediaType
}

var _ v1.Layer = (*overlay2DiffLayer)(nil)

func (l *overlay2DiffLayer) Digest() (v1.Hash, error) {
	// graphdriver doesn't preserve compressed digests; best-effort use diffID.
	return l.diffID, nil
}

func (l *overlay2DiffLayer) DiffID() (v1.Hash, error) {
	return l.diffID, nil
}

func (l *overlay2DiffLayer) Compressed() (io.ReadCloser, error) {
	return nil, errors.New("compressed layer stream is not available from docker graphdriver")
}

func (l *overlay2DiffLayer) Uncompressed() (io.ReadCloser, error) {
	pr, pw := io.Pipe()

	go func() {
		tw := tar.NewWriter(pw)
		defer func() {
			_ = tw.Close()
			_ = pw.Close()
		}()

		// WalkDir order can vary; stabilize with a full path collection then sort.
		var paths []string
		err := filepath.WalkDir(l.diffDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}

		sort.Strings(paths)

		for _, fullPath := range paths {
			if fullPath == l.diffDir {
				continue
			}
			rel, err := filepath.Rel(l.diffDir, fullPath)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			rel = filepath.ToSlash(rel)

			fi, err := os.Lstat(fullPath)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}

			var linkname string
			if fi.Mode()&os.ModeSymlink != 0 {
				linkname, err = os.Readlink(fullPath)
				if err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			}

			hdr, err := tar.FileInfoHeader(fi, linkname)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			hdr.Name = rel
			if fi.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
				hdr.Name += "/"
			}

			if err := tw.WriteHeader(hdr); err != nil {
				_ = pw.CloseWithError(err)
				return
			}

			// Write file contents
			if fi.Mode().IsRegular() {
				f, err := os.Open(fullPath)
				if err != nil {
					_ = pw.CloseWithError(err)
					return
				}
				_, cpErr := io.Copy(tw, f)
				_ = f.Close()
				if cpErr != nil {
					_ = pw.CloseWithError(cpErr)
					return
				}
			}
		}
	}()

	return pr, nil
}

func (l *overlay2DiffLayer) Size() (int64, error) {
	// Size is not needed by stereoscope's reader; return 0.
	return 0, nil
}

func (l *overlay2DiffLayer) MediaType() (types.MediaType, error) {
	return l.mediaType, nil
}
