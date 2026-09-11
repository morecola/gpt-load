package control

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"gpt-load/internal/channel"
	"gpt-load/internal/outboundproxy"
	app_errors "gpt-load/internal/platform/errors"
	"gpt-load/internal/platform/response"
	"gpt-load/internal/state"
	"gpt-load/internal/storage/models"
)

// 用户侧（访问密钥）「最近常用」订阅账号。与管理端 home_subscription_accounts.go
// 的差异只有两点：排行与账号只统计密钥有权访问的分组；账号身份脱敏——只保留
// 打码邮箱，不透出完整邮箱与上游代理地址。排行 SQL 与组装循环在此刻意保留一份
// 副本，换取管理端接口与其测试零改动。

func (s *Server) handleMySubscriptionAccounts(c *gin.Context) {
	if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		writeServiceError(c, "home_my_subscription_accounts", app_errors.ErrBadRequest)
		return
	}
	if accessKeyID, scoped := currentAccessKeyID(c); scoped {
		result, err := s.service.ReadMySubscriptionAccounts(c.Request.Context(), accessKeyID)
		if err != nil {
			writeServiceError(c, "home_my_subscription_accounts", err)
			return
		}
		response.SuccessI18n(c, "common.success", result)
		return
	}
	// 管理员请求委托给管理端读取，保证两个端点呈现同一份管理视图。
	result, err := s.service.ReadHomeSubscriptionAccounts(c.Request.Context())
	if err != nil {
		writeServiceError(c, "home_my_subscription_accounts", err)
		return
	}
	response.SuccessI18n(c, "common.success", result)
}

func (s *Service) ReadMySubscriptionAccounts(
	ctx context.Context,
	accessKeyID uint,
) (HomeSubscriptionAccountsResponse, error) {
	if s == nil || s.db == nil || s.manager == nil || s.registry == nil || s.registrySnapshot == nil ||
		s.stats == nil || s.channelRegistry == nil || s.encryption == nil || s.now == nil {
		return HomeSubscriptionAccountsResponse{}, app_errors.ErrInternalServer
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return HomeSubscriptionAccountsResponse{}, err
	}
	if accessKeyID == 0 {
		return HomeSubscriptionAccountsResponse{}, app_errors.ErrUnauthorized
	}
	observedAt := s.now().UTC()
	snapshot := s.manager.Current()
	if snapshot == nil {
		return HomeSubscriptionAccountsResponse{}, app_errors.ErrInternalServer
	}
	accessKey, exists := snapshot.AccessKeysByID[accessKeyID]
	if !exists || accessKey.Status != state.AccessKeyStatusActive {
		return HomeSubscriptionAccountsResponse{}, app_errors.ErrUnauthorized
	}
	allowedGroups := accessibleHomeGroups(snapshot, accessKey)
	if len(allowedGroups) == 0 {
		return HomeSubscriptionAccountsResponse{
			ObservedAtMS: observedAt.UnixMilli(),
			Items:        []HomeSubscriptionAccountResponse{},
		}, nil
	}
	return s.readMySubscriptionAccounts(ctx, allowedGroups, observedAt)
}

func (s *Service) readMySubscriptionAccounts(
	ctx context.Context,
	allowedGroups map[uint]struct{},
	observedAt time.Time,
) (HomeSubscriptionAccountsResponse, error) {
	observedAtMS, err := safeEpochMilliseconds(observedAt)
	if err != nil {
		return HomeSubscriptionAccountsResponse{}, err
	}
	allowedGroupIDs := make([]uint, 0, len(allowedGroups))
	for groupID := range allowedGroups {
		allowedGroupIDs = append(allowedGroupIDs, groupID)
	}
	slices.Sort(allowedGroupIDs)

	s.writeMu.RLock()
	defer s.writeMu.RUnlock()
	rows, err := s.readMySubscriptionRows(ctx, observedAt, allowedGroupIDs)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return HomeSubscriptionAccountsResponse{}, contextErr
		}
		var apiErr *app_errors.APIError
		if errors.As(err, &apiErr) {
			return HomeSubscriptionAccountsResponse{}, err
		}
		return HomeSubscriptionAccountsResponse{}, app_errors.ParseDBError(err)
	}
	if len(rows.activity) == 0 {
		return HomeSubscriptionAccountsResponse{
			ObservedAtMS: observedAtMS,
			Items:        []HomeSubscriptionAccountResponse{},
		}, nil
	}

	runtimeByID := make(map[uint]state.CredentialRuntimeView)
	for _, view := range s.registrySnapshot() {
		runtimeByID[view.ID] = view
	}
	observationByID := make(map[uint]models.CredentialObservation, len(rows.observations))
	for _, observation := range rows.observations {
		observationByID[observation.CredentialID] = observation
	}
	memberships := make(map[string][]homeSubscriptionMembership, len(rows.activity))
	for _, credential := range rows.credentials {
		if credential.Group == nil ||
			normalizeGroupConnectionType(credential.Group.ConnectionType) != models.ConnectionTypeSubscription {
			return HomeSubscriptionAccountsResponse{}, app_errors.ErrInternalServer
		}
		view, exists := runtimeByID[credential.ID]
		if !exists || view.GroupID != credential.GroupID ||
			view.Status != state.CredentialStatus(credential.Status) ||
			view.AuthState != normalizeRuntimeCredentialAuthState(credential.AuthState) ||
			view.Version != groupCollectionCredentialVersion(credential.SecretVersion) ||
			view.IdentityGeneration != groupCollectionCredentialIdentity(
				credential.IdentityFingerprint,
				*credential.Group,
			) {
			return HomeSubscriptionAccountsResponse{}, app_errors.ErrInternalServer
		}
		catalog := state.GroupCatalogView{
			ID: credential.Group.ID, Name: credential.Group.Name,
			Enabled: credential.Group.Enabled, WeightManual: cloneInt(credential.Group.WeightManual),
		}
		key := homeSubscriptionIdentityKey(
			credential.Group.ChannelID,
			credential.IdentityFingerprint,
		)
		memberships[key] = append(memberships[key], homeSubscriptionMembership{
			credential:  credential,
			observation: observationByID[credential.ID],
			view:        view,
			bucket:      classifyHealthKey(catalog, view, observedAt),
		})
	}

	items := make([]HomeSubscriptionAccountResponse, 0, len(rows.activity))
	for _, activity := range rows.activity {
		key := homeSubscriptionIdentityKey(activity.ChannelID, activity.IdentityFingerprint)
		accountMemberships := memberships[key]
		if len(accountMemberships) == 0 || activity.SuccessCount < 1 {
			return HomeSubscriptionAccountsResponse{}, app_errors.ErrInternalServer
		}
		item, err := s.mapMySubscriptionAccount(accountMemberships, observedAt)
		if err != nil {
			return HomeSubscriptionAccountsResponse{}, err
		}
		descriptor, exists := s.channelRegistry.Get(channel.ID(activity.ChannelID))
		if !exists || descriptor.Connection.Type != string(models.ConnectionTypeSubscription) {
			return HomeSubscriptionAccountsResponse{}, app_errors.ErrInternalServer
		}
		item.ChannelID = activity.ChannelID
		item.ChannelName = descriptor.Name
		item.ChannelMark = descriptor.Mark
		item.ChannelIcon = descriptor.Icon
		item.Capabilities = descriptor.Capabilities
		items = append(items, item)
	}
	return HomeSubscriptionAccountsResponse{ObservedAtMS: observedAtMS, Items: items}, nil
}

func (s *Service) readMySubscriptionRows(
	ctx context.Context,
	observedAt time.Time,
	allowedGroupIDs []uint,
) (homeSubscriptionRows, error) {
	rows := homeSubscriptionRows{}
	err := s.withReadSnapshot(ctx, func(tx *gorm.DB) error {
		activityScope := mySubscriptionActivityScope(
			tx,
			observedAt.Add(-homeSubscriptionAccountWindow).UnixMilli(),
			observedAt.UnixMilli(),
			allowedGroupIDs,
		)
		if err := activityScope.Find(&rows.activity).Error; err != nil {
			return fmt.Errorf("query my subscription activity: %w", err)
		}
		if len(rows.activity) == 0 {
			return nil
		}
		identities := make([]string, 0, len(rows.activity))
		for _, activity := range rows.activity {
			if activity.IdentityFingerprint == "" || activity.ChannelID == "" ||
				activity.SuccessCount < 1 || validateSafeMilliseconds(activity.LastSuccessAtMS) != nil {
				return fmt.Errorf("validate my subscription activity: %w", app_errors.ErrInternalServer)
			}
			identities = append(identities, activity.IdentityFingerprint)
		}
		subscriptionGroups := tx.Session(&gorm.Session{NewDB: true}).
			Model(&models.Group{}).
			Select("id").
			Where("connection_type = ?", models.ConnectionTypeSubscription).
			Where("id IN ?", allowedGroupIDs)
		if err := tx.Preload("Group").
			Where("identity_fingerprint IN ?", identities).
			Where("group_id IN (?)", subscriptionGroups).
			Order("id ASC").
			Find(&rows.credentials).Error; err != nil {
			return fmt.Errorf("query my subscription credentials: %w", err)
		}
		credentialIDs := make([]uint, 0, len(rows.credentials))
		for _, credential := range rows.credentials {
			credentialIDs = append(credentialIDs, credential.ID)
		}
		if len(credentialIDs) == 0 {
			return nil
		}
		if err := tx.Where("credential_id IN ?", credentialIDs).
			Find(&rows.observations).Error; err != nil {
			return fmt.Errorf("query my subscription observations: %w", err)
		}
		return nil
	})
	return rows, err
}

func mySubscriptionActivityScope(
	db *gorm.DB,
	fromMS, toMS int64,
	allowedGroupIDs []uint,
) *gorm.DB {
	subscriptionGroups := db.Session(&gorm.Session{NewDB: true}).
		Model(&models.Group{}).
		Select("id, channel_id").
		Where("connection_type = ?", models.ConnectionTypeSubscription).
		Where("id IN ?", allowedGroupIDs)
	return db.Table("credential_attempt_stats").
		Select(
			"credentials.identity_fingerprint, subscription_groups.channel_id, "+
				"SUM(credential_attempt_stats.success_count) AS success_count, "+
				"MAX(credential_attempt_stats.bucket_start_ms) AS last_success_at_ms",
		).
		Joins("JOIN credentials ON credentials.id = credential_attempt_stats.credential_id").
		Joins(
			"JOIN (?) AS subscription_groups ON subscription_groups.id = credentials.group_id",
			subscriptionGroups,
		).
		Where("credential_attempt_stats.bucket_start_ms >= ?", fromMS).
		Where("credential_attempt_stats.bucket_start_ms < ?", toMS).
		Where("credential_attempt_stats.success_count > 0").
		Group("credentials.identity_fingerprint, subscription_groups.channel_id").
		Order("success_count DESC, last_success_at_ms DESC, credentials.identity_fingerprint ASC").
		Limit(homeSubscriptionAccountLimit)
}

func (s *Service) mapMySubscriptionAccount(
	memberships []homeSubscriptionMembership,
	observedAt time.Time,
) (HomeSubscriptionAccountResponse, error) {
	representative := memberships[0]
	available := 0
	for _, membership := range memberships {
		if membership.bucket == healthBucketAvailable {
			available++
		}
		if homeSubscriptionRepresentativeLess(representative, membership) {
			representative = membership
		}
	}
	group := *representative.credential.Group
	canonical, identity, err := s.decodeCredential(group, representative.credential)
	if err != nil {
		return HomeSubscriptionAccountResponse{}, err
	}
	mask, account, err := s.credentialPresentation(
		group,
		representative.credential,
		canonical,
		identity,
	)
	if err != nil {
		return HomeSubscriptionAccountResponse{}, err
	}
	credential := representative.credential
	item, err := mapCredentialRuntimeItem(
		mask,
		credential.ID,
		representative.view,
		representative.bucket,
		s.stats.Snapshot(credential.ID, observedAt),
		observedAt,
	)
	if err != nil {
		return HomeSubscriptionAccountResponse{}, err
	}
	item.ConnectionType = string(models.ConnectionTypeSubscription)
	item.SecretVersion = credential.SecretVersion
	item.AuthState = string(credential.AuthState)
	item.AuthErrorCode = safeInternalErrorCode(credential.AuthErrorCode)
	// 脱敏：只保留打码邮箱；代理字段填中性视图，且不触发上游代理查询。
	item.Account = CredentialAccountResponse{EmailMask: account.EmailMask}
	item.Observation = presentCredentialObservation(
		representative.observation,
		credential.IdentityFingerprint,
	)
	item.Proxy = outboundproxy.View{
		ConfiguredMode:  outboundproxy.ModeInherit,
		EffectiveMode:   outboundproxy.ModeDirect,
		EffectiveSource: outboundproxy.SourceDefault,
	}
	return HomeSubscriptionAccountResponse{
		GroupCount:          len(memberships),
		AvailableGroupCount: available,
		Credential:          item,
	}, nil
}
