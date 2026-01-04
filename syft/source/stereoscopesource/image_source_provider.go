package stereoscopesource

import (
	"context"

	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

const ImageTag = "image"

var rootTempDirGenerator = file.NewTempDirGenerator("stereoscope")

type ProviderConfig struct {
	StereoscopeImageProviderConfig stereoscope.ImageProviderConfig
	Exclude                        source.ExcludeConfig
	Alias                          source.Alias
}

type stereoscopeImageSourceProvider struct {
	stereoscopeProvider image.Provider
	cfg                 ProviderConfig
}

var _ source.Provider = (*stereoscopeImageSourceProvider)(nil)

func (l stereoscopeImageSourceProvider) Name() string {
	return l.stereoscopeProvider.Name()
}

func (l stereoscopeImageSourceProvider) Provide(ctx context.Context) (source.Source, error) {
	img, err := l.stereoscopeProvider.Provide(ctx)
	if err != nil {
		return nil, err
	}
	cfg := ImageConfig{
		Reference:       l.cfg.StereoscopeImageProviderConfig.UserInput,
		Platform:        l.cfg.StereoscopeImageProviderConfig.Platform,
		RegistryOptions: &l.cfg.StereoscopeImageProviderConfig.Registry,
		Exclude:         l.cfg.Exclude,
		Alias:           l.cfg.Alias,
	}
	return New(img, cfg), nil
}

func Providers(cfg ProviderConfig) []collections.TaggedValue[source.Provider] {
	stereoscopeProviders := collections.TaggedValueSet[source.Provider]{}
	tempDirGenerator := rootTempDirGenerator.NewGenerator()
	stereoscopeProviders = append(stereoscopeProviders,
		collections.NewTaggedValue[source.Provider](
			stereoscopeImageSourceProvider{
				stereoscopeProvider: NewDockerEngineGraphDriverProvider(
					tempDirGenerator,
					cfg.StereoscopeImageProviderConfig.UserInput),
				cfg: cfg,
			},
			DockerGraphDriver,
			stereoscope.DirTag,
			ImageTag,
		),
		collections.NewTaggedValue[source.Provider](
			stereoscopeImageSourceProvider{
				stereoscopeProvider: NewContainerdDirProvider(
					tempDirGenerator,
					cfg.StereoscopeImageProviderConfig.UserInput,
					cfg.StereoscopeImageProviderConfig.Platform,
				),
				cfg: cfg,
			},
			ContainerdDir,
			stereoscope.DirTag,
			ImageTag,
		),
	)

	return stereoscopeProviders
}
