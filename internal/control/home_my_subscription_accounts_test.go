package control

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"gpt-load/internal/outboundproxy"
	"gpt-load/internal/platform/config"
	"gpt-load/internal/storage/models"
)

func TestReadMySubscriptionAccountsScopesToPermittedGroupsAndMasksIdentity(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	now := time.Date(2026, time.August, 31, 12, 30, 0, 0, time.UTC)
	fixture.service.now = func() time.Time { return now }

	// shared 账号同时挂在 groupA 与 groupB；other 账号只在 groupB。
	groupAID, sharedInA := createHomeSubscriptionCredential(
		t, fixture, "scoped-shared-a", "scoped-shared", "shared@example.com",
	)
	groupBID, sharedInB := createHomeSubscriptionCredential(
		t, fixture, "scoped-shared-b", "scoped-shared", "shared@example.com",
	)
	_, otherInB := createHomeSubscriptionCredential(
		t, fixture, "scoped-other", "scoped-other", "other@example.com",
	)
	if groupAID == groupBID {
		t.Fatal("shared fixture unexpectedly reused one group")
	}

	createHomeCredentialObservation(t, fixture, sharedInA, now.Add(-time.Minute), "Shared plan")
	createHomeCredentialObservation(t, fixture, sharedInB, now.Add(-2*time.Minute), "Shared plan")
	createHomeCredentialObservation(t, fixture, otherInB, now.Add(-3*time.Minute), "Other plan")

	bucket := now.Truncate(time.Hour).UnixMilli()
	if err := fixture.db.Create(&[]models.CredentialAttemptStat{
		{CredentialID: sharedInA.ID, BucketStartMS: bucket, SuccessCount: 5},
		{CredentialID: sharedInB.ID, BucketStartMS: bucket, SuccessCount: 3},
		{CredentialID: otherInB.ID, BucketStartMS: bucket, SuccessCount: 9},
	}).Error; err != nil {
		t.Fatalf("create credential activity: %v", err)
	}

	scopedKey, err := fixture.service.CreateAccessKey(t.Context(), AccessKeyCreateRequest{
		Name:    "scoped key",
		Filters: &AccessKeyFilters{Groups: []uint{groupAID}},
	})
	if err != nil {
		t.Fatalf("CreateAccessKey(scoped) error = %v", err)
	}
	result, err := fixture.service.ReadMySubscriptionAccounts(t.Context(), scopedKey.ID)
	if err != nil {
		t.Fatalf("ReadMySubscriptionAccounts() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("items = %#v, want only the permitted shared account", result.Items)
	}
	item := result.Items[0]
	if item.GroupCount != 1 || item.AvailableGroupCount != 1 {
		t.Fatalf("shared account group counts = %d/%d, want only the permitted group",
			item.AvailableGroupCount, item.GroupCount)
	}
	if item.Credential.Account.Email != "" || item.Credential.Account.EmailMask == "" {
		t.Fatalf("account identity not masked = %#v", item.Credential.Account)
	}
	if item.Credential.Proxy.DisplayURL != "" ||
		item.Credential.Proxy.ConfiguredMode != outboundproxy.ModeInherit ||
		item.Credential.Proxy.EffectiveMode != outboundproxy.ModeDirect {
		t.Fatalf("proxy view not sanitized = %#v", item.Credential.Proxy)
	}
	if item.Credential.Observation == nil || item.Credential.Observation.Snapshot == nil ||
		item.Credential.Observation.Snapshot.Plan.Name != "Shared plan" {
		t.Fatalf("quota observation missing = %#v", item.Credential.Observation)
	}

	unfilteredKey, err := fixture.service.CreateAccessKey(t.Context(), AccessKeyCreateRequest{
		Name: "unfiltered key",
	})
	if err != nil {
		t.Fatalf("CreateAccessKey(unfiltered) error = %v", err)
	}
	unfiltered, err := fixture.service.ReadMySubscriptionAccounts(t.Context(), unfilteredKey.ID)
	if err != nil {
		t.Fatalf("ReadMySubscriptionAccounts(unfiltered) error = %v", err)
	}
	if len(unfiltered.Items) != 2 {
		t.Fatalf("unfiltered read = %#v, want both accounts", unfiltered.Items)
	}
	// other 账号成功计数更高，排行第一；shared 账号跨两个分组聚合出 group_count=2。
	if unfiltered.Items[0].Credential.Observation.Snapshot.Plan.Name != "Other plan" ||
		unfiltered.Items[0].GroupCount != 1 ||
		unfiltered.Items[0].Credential.Account.Email != "" {
		t.Fatalf("unfiltered first item = %#v", unfiltered.Items[0])
	}
	if unfiltered.Items[1].GroupCount != 2 {
		t.Fatalf("shared account group_count = %d, want 2", unfiltered.Items[1].GroupCount)
	}

	emptyKey, err := fixture.service.CreateAccessKey(t.Context(), AccessKeyCreateRequest{
		Name:    "empty key",
		Filters: &AccessKeyFilters{Groups: []uint{groupAID}, Models: []string{"no-such-model"}},
	})
	if err != nil {
		t.Fatalf("CreateAccessKey(empty) error = %v", err)
	}
	empty, err := fixture.service.ReadMySubscriptionAccounts(t.Context(), emptyKey.ID)
	if err != nil {
		t.Fatalf("ReadMySubscriptionAccounts(empty) error = %v", err)
	}
	if len(empty.Items) != 0 {
		t.Fatalf("empty-permission read = %#v, want no items", empty.Items)
	}
}

func TestMySubscriptionAccountsRouteServesAccessKeysAndAdmin(t *testing.T) {
	t.Parallel()
	initControlI18n(t)
	fixture := newServiceFixture(t)
	accessKey, err := fixture.service.CreateAccessKey(t.Context(), AccessKeyCreateRequest{
		Name: "home scoped readonly",
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	NewServer(&config.Config{AuthKey: authTestKey}, fixture.service).RegisterRoutes(engine)

	access := performHomeRequest(engine, "/api/home/my-subscription-accounts", accessKey.Key)
	if access.Code != http.StatusOK {
		t.Fatalf("access key response = %d %s", access.Code, access.Body.String())
	}
	unknownQuery := performHomeRequest(
		engine,
		"/api/home/my-subscription-accounts?unknown=1",
		accessKey.Key,
	)
	if unknownQuery.Code != http.StatusBadRequest {
		t.Fatalf("unknown query response = %d %s", unknownQuery.Code, unknownQuery.Body.String())
	}
	admin := performHomeRequest(engine, "/api/home/my-subscription-accounts", authTestKey)
	if admin.Code != http.StatusOK {
		t.Fatalf("admin response = %d %s", admin.Code, admin.Body.String())
	}
}
