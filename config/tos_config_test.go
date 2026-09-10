package config

import (
	"testing"

	"github.com/pingcap/metering_sdk/storage"
	"github.com/stretchr/testify/require"
)

func TestTOSConfigToProviderConfig(t *testing.T) {
	cfg := NewMeteringConfig().
		WithTOSAssumeRole("cn-beijing", "nextgen-metering-dev-cn-beijing-ng", "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo").
		WithPrefix("premium")

	providerCfg := cfg.ToProviderConfig()
	require.Equal(t, storage.ProviderTypeTOS, providerCfg.Type)
	require.Equal(t, "cn-beijing", providerCfg.Region)
	require.Equal(t, "nextgen-metering-dev-cn-beijing-ng", providerCfg.Bucket)
	require.Equal(t, "premium", providerCfg.Prefix)
	require.NotNil(t, providerCfg.TOS)
	require.Equal(t, "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo", providerCfg.TOS.AssumeRoleARN)
}

func TestTOSConfigURI(t *testing.T) {
	cfg, err := NewFromURI("tos://nextgen-metering-dev-cn-beijing-ng/premium?region-id=cn-beijing&assume-role-arn=trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo")
	require.NoError(t, err)
	require.Equal(t, storage.ProviderTypeTOS, cfg.Type)
	require.Equal(t, "nextgen-metering-dev-cn-beijing-ng", cfg.Bucket)
	require.Equal(t, "premium", cfg.Prefix)
	require.Equal(t, "cn-beijing", cfg.Region)
	require.NotNil(t, cfg.TOS)
	require.Equal(t, "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo", cfg.TOS.AssumeRoleARN)

	require.Equal(t, "tos://nextgen-metering-dev-cn-beijing-ng/premium?assume-role-arn=trn%3Aiam%3A%3A2121942738%3Arole%2Fdev-seed-cn-beijing-ng-metering-wo&region-id=cn-beijing", cfg.ToURI())
}

func TestTOSConfigURIAssumeRoleTRNAlias(t *testing.T) {
	cfg, err := NewFromURI("tos://metering-bucket/data?region-id=cn-beijing&assume-role-trn=trn:iam::1:role/metering")
	require.NoError(t, err)
	require.NotNil(t, cfg.TOS)
	require.Equal(t, "trn:iam::1:role/metering", cfg.TOS.AssumeRoleARN)
}
