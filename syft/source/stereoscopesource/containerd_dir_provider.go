package stereoscopesource

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

// ContainerdDirSource is a custom stereoscope image provider that reads image metadata and content
// directly from a Linux containerd root directory (e.g. /var/lib/containerd) and assembles an OCI image layout.
//
// User input format:
//
//	containerd-dir:<image>|<containerdRootDir>[|<namespace>]
//
// Where:
// - image: containerd image name (e.g. "docker.io/library/alpine:latest") OR a digest (e.g. "sha256:<hex>")
// - containerdRootDir: containerd root directory (must contain io.containerd.content.v1.content and io.containerd.metadata.v1.bolt)
// - namespace: optional containerd namespace (default: "default")
const ContainerdDirSource = "containerd-dir"
const ContainerdDir image.Source = ContainerdDirSource

type containerdDirProvider struct {
	tmpDirGen          *file.TempDirGenerator
	path               string
	platform           *image.Platform
	additionalMetadata []image.AdditionalMetadata
}

func NewContainerdDirProvider(tmpDirGen *file.TempDirGenerator, path string, platform *image.Platform, additionalMetadata ...image.AdditionalMetadata) image.Provider {
	return &containerdDirProvider{
		tmpDirGen:          tmpDirGen,
		path:               path,
		platform:           platform,
		additionalMetadata: additionalMetadata,
	}
}

func (p *containerdDirProvider) Name() string {
	return ContainerdDir
}

func (p *containerdDirProvider) Provide(ctx context.Context) (*image.Image, error) {
	imageRef, rootDir, namespace, err := parseContainerdDirUserInput(p.path)
	if err != nil {
		// user explicitly selected this provider scheme; surface a clear error
		return nil, err
	}

	if err := validateContainerdRoot(rootDir); err != nil {
		return nil, err
	}

	targetDesc, tags, err := containerdResolveTargetDescriptor(ctx, rootDir, namespace, imageRef)
	if err != nil {
		return nil, err
	}

	manifestDesc, manifestBytes, configBytes, layerDescs, err := containerdResolveManifestAndRefs(rootDir, targetDesc, p.platform)
	if err != nil {
		return nil, err
	}

	layoutTempDir, err := p.tmpDirGen.NewDirectory("containerd-dir-oci-layout")
	if err != nil {
		return nil, err
	}

	if err := writeOCILayout(layoutTempDir, manifestDesc, layerDescs, rootDir, manifestBytes, configBytes); err != nil {
		return nil, err
	}

	pathObj, err := layout.FromPath(layoutTempDir)
	if err != nil {
		return nil, fmt.Errorf("unable to read image from OCI directory path %q: %w", layoutTempDir, err)
	}

	manifestHash, err := v1.NewHash(manifestDesc.Digest.String())
	if err != nil {
		return nil, fmt.Errorf("unable to parse manifest digest %q: %w", manifestDesc.Digest.String(), err)
	}

	v1img, err := pathObj.Image(manifestHash)
	if err != nil {
		return nil, fmt.Errorf("unable to parse OCI directory as an image: %w", err)
	}

	// Route 1 optimization: wrap v1.Image layers so DiffID is returned from config.rootfs.diff_ids
	// instead of being computed by decompress+hash.
	if len(configBytes) > 0 {
		var cfg v1.ConfigFile
		if err := json.Unmarshal(configBytes, &cfg); err == nil && len(cfg.RootFS.DiffIDs) > 0 {
			v1img = fastDiffIDImage{
				Image:   v1img,
				diffIDs: cfg.RootFS.DiffIDs,
			}
		}
	}

	contentTempDir, err := p.tmpDirGen.NewDirectory("containerd-dir-image")
	if err != nil {
		return nil, err
	}

	// apply best-effort metadata overrides after read
	var meta []image.AdditionalMetadata
	if len(tags) > 0 {
		meta = append(meta, image.WithTags(tags...))
	}
	if manifestDesc.Digest != "" {
		meta = append(meta, image.WithManifestDigest(manifestDesc.Digest.String()))
	}
	if len(manifestBytes) > 0 {
		meta = append(meta, image.WithManifest(manifestBytes))
	}
	if len(configBytes) > 0 {
		meta = append(meta, image.WithConfig(configBytes))
	}
	if p.platform != nil {
		meta = append(meta, image.WithOS(p.platform.OS), image.WithArchitecture(p.platform.Architecture, p.platform.Variant))
	}
	meta = append(meta, p.additionalMetadata...)

	out := image.New(v1img, p.tmpDirGen, contentTempDir, meta...)
	if err := out.Read(); err != nil {
		return nil, err
	}

	return out, nil
}

func parseContainerdDirUserInput(userInput string) (imageRef string, rootDir string, namespace string, err error) {
	// Accept either:
	// - containerd-dir:<image>|<containerdRootDir>[|<namespace>]  (preferred)
	// - <image>|<containerdRootDir>[|<namespace>]                 (legacy / internal callers)
	userInput = strings.TrimPrefix(userInput, ContainerdDirSource)

	sepIdx := strings.Index(userInput, "|")
	if sepIdx <= 0 || sepIdx >= len(userInput)-1 {
		return "", "", "", fmt.Errorf("invalid containerd-dir user input: expected %q<image>|<containerdRootDir>[|<namespace>]", ContainerdDirSource)
	}

	imageRef = strings.TrimSpace(userInput[:sepIdx])
	rest := strings.TrimSpace(userInput[sepIdx+1:])
	if imageRef == "" || rest == "" {
		return "", "", "", fmt.Errorf("invalid containerd-dir user input: expected %q<image>|<containerdRootDir>[|<namespace>]", ContainerdDirSource)
	}

	namespace = "default"
	// optional third parameter
	if sepIdx2 := strings.Index(rest, "|"); sepIdx2 >= 0 {
		rootDir = strings.TrimSpace(rest[:sepIdx2])
		ns := strings.TrimSpace(rest[sepIdx2+1:])
		if ns != "" {
			namespace = ns
		}
	} else {
		rootDir = rest
	}

	if !filepath.IsAbs(rootDir) {
		return "", "", "", fmt.Errorf("invalid containerd-dir rootDir %q: expected absolute path", rootDir)
	}

	return imageRef, filepath.Clean(rootDir), namespace, nil
}

type fastDiffIDLayer struct {
	v1.Layer
	diffID v1.Hash
}

func (l fastDiffIDLayer) DiffID() (v1.Hash, error) {
	return l.diffID, nil
}

type fastDiffIDImage struct {
	v1.Image
	diffIDs []v1.Hash
}

func (i fastDiffIDImage) Layers() ([]v1.Layer, error) {
	ls, err := i.Image.Layers()
	if err != nil {
		return nil, err
	}

	// Only apply wrapping when the lengths match; otherwise fall back to upstream behavior.
	if len(i.diffIDs) == 0 || len(ls) != len(i.diffIDs) {
		return ls, nil
	}

	out := make([]v1.Layer, 0, len(ls))
	for idx, l := range ls {
		out = append(out, fastDiffIDLayer{
			Layer:  l,
			diffID: i.diffIDs[idx],
		})
	}
	return out, nil
}

func validateContainerdRoot(rootDir string) error {
	contentRoot := filepath.Join(rootDir, "io.containerd.content.v1.content", "blobs")
	metaDB := filepath.Join(rootDir, "io.containerd.metadata.v1.bolt", "meta.db")

	if _, err := os.Stat(contentRoot); err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return fmt.Errorf("containerd rootDir %q does not have expected content store at %q: %v", rootDir, contentRoot, err)
	}
	if _, err := os.Stat(metaDB); err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return fmt.Errorf("containerd rootDir %q does not have expected metadata db at %q: %v", rootDir, metaDB, err)
	}
	return nil
}

func containerdResolveTargetDescriptor(ctx context.Context, rootDir, namespace, imageRef string) (ocispec.Descriptor, []string, error) {
	// If the user provided a digest, treat it as the target (best-effort mediaType discovery happens later).
	if d, ok := parseDigest(imageRef); ok {
		return ocispec.Descriptor{Digest: d}, nil, nil
	}

	metaDBPath := filepath.Join(rootDir, "io.containerd.metadata.v1.bolt", "meta.db")
	db, err := bolt.Open(metaDBPath, 0o444, &bolt.Options{ReadOnly: true})
	if err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return ocispec.Descriptor{}, nil, fmt.Errorf("unable to open containerd meta db at %q: %v", metaDBPath, err)
	}
	defer func() {
		_ = db.Close()
	}()

	mdb := metadata.NewDB(db, nil, nil)
	store := metadata.NewImageStore(mdb)

	// containerd image store requires a namespace in context
	ctx = namespaces.WithNamespace(ctx, namespace)
	img, err := store.Get(ctx, imageRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, fmt.Errorf("unable to resolve containerd image %q in namespace %q: %w", imageRef, namespace, err)
	}

	// Best-effort: treat the containerd image name as a tag (if it includes a tag separator).
	var tags []string
	if strings.Contains(img.Name, ":") {
		tags = append(tags, img.Name)
	}

	return img.Target, tags, nil
}

func containerdResolveManifestAndRefs(rootDir string, target ocispec.Descriptor, platform *image.Platform) (manifestDesc ocispec.Descriptor, manifestBytes []byte, configBytes []byte, layerDescs []ocispec.Descriptor, err error) {
	if target.Digest == "" {
		return ocispec.Descriptor{}, nil, nil, nil, fmt.Errorf("containerd target descriptor digest is empty")
	}

	targetBytes, err := readContainerdBlob(rootDir, target.Digest)
	if err != nil {
		return ocispec.Descriptor{}, nil, nil, nil, err
	}

	// If the mediaType is unknown (e.g. user provided only a digest), try to detect it.
	if target.MediaType == "" {
		target.MediaType = detectOCIMediaType(targetBytes)
	}

	// 1) resolve to a single image manifest descriptor
	switch target.MediaType {
	case ocispec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.list.v2+json":
		var idx ocispec.Index
		if err := json.Unmarshal(targetBytes, &idx); err != nil {
			return ocispec.Descriptor{}, nil, nil, nil, fmt.Errorf("unable to parse containerd image index %s: %w", target.Digest, err)
		}
		if len(idx.Manifests) == 0 {
			return ocispec.Descriptor{}, nil, nil, nil, fmt.Errorf("containerd image index %s has no manifests", target.Digest)
		}
		manifestDesc = selectManifestFromIndex(idx.Manifests, platform)
	default:
		manifestDesc = target
	}

	manifestBytes, err = readContainerdBlob(rootDir, manifestDesc.Digest)
	if err != nil {
		return ocispec.Descriptor{}, nil, nil, nil, err
	}

	// 2) parse manifest and collect referenced blobs
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, nil, nil, nil, fmt.Errorf("unable to parse containerd image manifest %s: %w", manifestDesc.Digest, err)
	}

	if manifest.Config.Digest != "" {
		configBytes, err = readContainerdBlob(rootDir, manifest.Config.Digest)
		if err != nil {
			return ocispec.Descriptor{}, nil, nil, nil, err
		}
	}

	layerDescs = append(layerDescs, manifest.Config)
	layerDescs = append(layerDescs, manifest.Layers...)

	// Ensure the manifest has a media type when writing index.json (important for some readers).
	if manifestDesc.MediaType == "" {
		manifestDesc.MediaType = detectOCIMediaType(manifestBytes)
	}
	if manifestDesc.MediaType == "" {
		manifestDesc.MediaType = ocispec.MediaTypeImageManifest
	}

	return manifestDesc, manifestBytes, configBytes, layerDescs, nil
}

func selectManifestFromIndex(manifests []ocispec.Descriptor, platform *image.Platform) ocispec.Descriptor {
	if platform == nil {
		return manifests[0]
	}

	for _, m := range manifests {
		if m.Platform == nil {
			continue
		}
		if m.Platform.OS != "" && platform.OS != "" && m.Platform.OS != platform.OS {
			continue
		}
		if m.Platform.Architecture != "" && platform.Architecture != "" && m.Platform.Architecture != platform.Architecture {
			continue
		}
		// variant is optional (may be empty on either side)
		if m.Platform.Variant != "" && platform.Variant != "" && m.Platform.Variant != platform.Variant {
			continue
		}
		return m
	}

	// fallback
	return manifests[0]
}

func writeOCILayout(layoutDir string, manifestDesc ocispec.Descriptor, refDescs []ocispec.Descriptor, containerdRoot string, manifestBytes, configBytes []byte) error {
	// OCI layout files
	if err := os.MkdirAll(filepath.Join(layoutDir, "blobs", "sha256"), 0o755); err != nil {
		return fmt.Errorf("unable to create OCI layout blob directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(layoutDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`+"\n"), 0o644); err != nil {
		return fmt.Errorf("unable to write OCI layout header: %w", err)
	}

	// index.json (single-manifest)
	idx := ocispec.Index{
		Versioned: ocispecs.Versioned{SchemaVersion: 2},
		Manifests: []ocispec.Descriptor{manifestDesc},
	}
	indexBytes, err := json.Marshal(&idx)
	if err != nil {
		return fmt.Errorf("unable to marshal OCI index: %w", err)
	}
	if err := os.WriteFile(filepath.Join(layoutDir, "index.json"), indexBytes, 0o644); err != nil {
		return fmt.Errorf("unable to write OCI index.json: %w", err)
	}

	// Ensure all required blobs exist by creating symlinks into the containerd content store.
	needed := []digest.Digest{manifestDesc.Digest}
	for _, d := range refDescs {
		if d.Digest != "" {
			needed = append(needed, d.Digest)
		}
	}

	seen := map[string]struct{}{}
	for _, dgst := range needed {
		if dgst == "" {
			continue
		}
		if _, ok := seen[dgst.String()]; ok {
			continue
		}
		seen[dgst.String()] = struct{}{}

		if err := linkBlobIntoLayout(layoutDir, containerdRoot, dgst); err != nil {
			return err
		}
	}

	// Best-effort: if manifest/config bytes are present, overwrite the linked blobs with actual bytes.
	// This is useful when the containerd content store uses hardlink protections or symlinks are disallowed.
	if len(manifestBytes) > 0 && manifestDesc.Digest != "" {
		_ = os.WriteFile(ociBlobPath(layoutDir, manifestDesc.Digest), manifestBytes, 0o644)
	}
	_ = configBytes // present for callers that want to validate they can read config; blobs are still linked via descriptors.

	return nil
}

func linkBlobIntoLayout(layoutDir, containerdRoot string, dgst digest.Digest) error {
	if dgst == "" {
		return nil
	}
	algo := dgst.Algorithm().String()
	if algo == "" {
		return fmt.Errorf("unsupported digest %q: empty algorithm", dgst.String())
	}

	src := containerdBlobPath(containerdRoot, dgst)
	if _, err := os.Stat(src); err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return fmt.Errorf("containerd blob not found/readable at %q for digest %s: %v", src, dgst, err)
	}

	dst := ociBlobPath(layoutDir, dgst)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("unable to create OCI blob directory for %s: %w", dgst, err)
	}

	// If the destination already exists, do nothing.
	if _, err := os.Lstat(dst); err == nil {
		return nil
	}

	// Prefer symlinks (fast, no copy). Fall back to hardlinks. As a last resort, copy.
	if err := os.Symlink(src, dst); err == nil {
		return nil
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

func containerdBlobPath(containerdRoot string, dgst digest.Digest) string {
	// io.containerd.content.v1.content/blobs/<algo>/<hex>
	return filepath.Join(containerdRoot, "io.containerd.content.v1.content", "blobs", dgst.Algorithm().String(), dgst.Encoded())
}

func ociBlobPath(layoutDir string, dgst digest.Digest) string {
	return filepath.Join(layoutDir, "blobs", dgst.Algorithm().String(), dgst.Encoded())
}

func readContainerdBlob(containerdRoot string, dgst digest.Digest) ([]byte, error) {
	p := containerdBlobPath(containerdRoot, dgst)
	b, err := os.ReadFile(p)
	if err != nil {
		// do not preserve os.ErrNotExist through wrapping
		return nil, fmt.Errorf("unable to read containerd blob %s from %q: %v", dgst, p, err)
	}
	return b, nil
}

func detectOCIMediaType(b []byte) string {
	// best-effort heuristics: try index first, then manifest
	var idx struct {
		Manifests []json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(b, &idx); err == nil && idx.Manifests != nil {
		return ocispec.MediaTypeImageIndex
	}
	var mf struct {
		Config json.RawMessage   `json:"config"`
		Layers []json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(b, &mf); err == nil && mf.Config != nil && mf.Layers != nil {
		return ocispec.MediaTypeImageManifest
	}
	return ""
}

func parseDigest(s string) (digest.Digest, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "sha256:") {
		d, err := digest.Parse(s)
		return d, err == nil
	}
	// allow raw hex sha256
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			d, err := digest.Parse("sha256:" + s)
			return d, err == nil
		}
	}
	return "", false
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("unable to open %q: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("unable to create %q: %w", dst, err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("unable to copy %q -> %q: %w", src, dst, err)
	}
	return nil
}

var _ image.Provider = (*containerdDirProvider)(nil)
