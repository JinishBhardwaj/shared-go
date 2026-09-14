package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
)

// fakeRows is a hand-rolled implementation of the pgx.Rows interface (an
// interface in pgx v5, so no live database or mocking library is needed to
// satisfy it) used to drive GetPermissions in tests without a real
// PostgreSQL connection.
type fakeRows struct {
	data []([]any)
	idx  int
	err  error
}

func (f *fakeRows) Close()                                       {}
func (f *fakeRows) Err() error                                   { return f.err }
func (f *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (f *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (f *fakeRows) Next() bool {
	if f.idx >= len(f.data) {
		return false
	}
	f.idx++
	return true
}

func (f *fakeRows) Scan(dest ...any) error {
	row := f.data[f.idx-1]
	for i, d := range dest {
		switch v := d.(type) {
		case *string:
			*v = row[i].(string)
		case *authz.Effect:
			*v = row[i].(authz.Effect)
		default:
			return errors.New("fakeRows: unsupported scan destination type")
		}
	}
	return nil
}

func (f *fakeRows) Values() ([]any, error) { return nil, nil }
func (f *fakeRows) RawValues() [][]byte    { return nil }
func (f *fakeRows) Conn() *pgx.Conn        { return nil }

// fakeQuerier is a hand-rolled implementation of pgxQuerier used to
// substitute for *pgxpool.Pool/*pgx.Conn in tests, recording the SQL and
// args it was called with so tests can assert parameterization.
type fakeQuerier struct {
	queryFn func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	execFn  func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)

	lastSQL  string
	lastArgs []any
}

func (f *fakeQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.lastSQL = sql
	f.lastArgs = args
	return f.queryFn(ctx, sql, args...)
}

func (f *fakeQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	panic("QueryRow not used by PermissionRepository")
}

func (f *fakeQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.lastSQL = sql
	f.lastArgs = args
	return f.execFn(ctx, sql, args...)
}

func TestGetPermissions_ScansAllFields(t *testing.T) {
	q := &fakeQuerier{
		queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &fakeRows{
				data: []([]any){
					{"read", "report", "rep_*", "tenant-1", authz.Effect("permit")},
					{"write", "order", "*", "", authz.Effect("deny")},
				},
			}, nil
		},
	}
	repo := NewPermissionRepository(q)

	got, err := repo.GetPermissions(context.Background(), "principal-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PrincipalID != "principal-1" {
		t.Fatalf("PrincipalID = %q, want %q", got.PrincipalID, "principal-1")
	}
	if len(got.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(got.Rules))
	}

	want0 := authz.PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "rep_*",
		TenantID:          "tenant-1",
		Effect:            authz.EffectPermit,
	}
	if got.Rules[0] != want0 {
		t.Fatalf("Rules[0] = %+v, want %+v", got.Rules[0], want0)
	}

	want1 := authz.PermissionRule{
		ActionPattern:     "write",
		ResourceType:      "order",
		ResourceIDPattern: "*",
		TenantID:          "",
		Effect:            authz.EffectDeny,
	}
	if got.Rules[1] != want1 {
		t.Fatalf("Rules[1] = %+v, want %+v", got.Rules[1], want1)
	}

	if q.lastSQL != `SELECT action_pattern, resource_type, resource_id_pattern, tenant_id, effect FROM auth_permission_rules WHERE principal_id = $1` {
		t.Fatalf("unexpected SQL: %q", q.lastSQL)
	}
	if len(q.lastArgs) != 1 || q.lastArgs[0] != "principal-1" {
		t.Fatalf("unexpected args: %+v", q.lastArgs)
	}
}

func TestGetPermissions_ZeroRowsIsNotAnError(t *testing.T) {
	q := &fakeQuerier{
		queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &fakeRows{data: nil}, nil
		},
	}
	repo := NewPermissionRepository(q)

	got, err := repo.GetPermissions(context.Background(), "principal-none")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := &authz.PrincipalPermissions{PrincipalID: "principal-none", Rules: nil}
	if got.PrincipalID != want.PrincipalID {
		t.Fatalf("PrincipalID = %q, want %q", got.PrincipalID, want.PrincipalID)
	}
	if len(got.Rules) != 0 {
		t.Fatalf("Rules = %+v, want empty", got.Rules)
	}
}

func TestGetPermissions_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("connection refused")
	q := &fakeQuerier{
		queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return nil, wantErr
		},
	}
	repo := NewPermissionRepository(q)

	got, err := repo.GetPermissions(context.Background(), "principal-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Fatalf("got = %+v, want nil on error", got)
	}
}

func TestGetPermissions_RowsErrPropagates(t *testing.T) {
	wantErr := errors.New("read failed mid-stream")
	q := &fakeQuerier{
		queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			return &fakeRows{
				data: []([]any){
					{"read", "report", "rep_*", "tenant-1", authz.Effect("permit")},
				},
				err: wantErr,
			}, nil
		},
	}
	repo := NewPermissionRepository(q)

	got, err := repo.GetPermissions(context.Background(), "principal-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Fatalf("got = %+v, want nil on error", got)
	}
}

func TestGrantPermission_ParameterizesArgs(t *testing.T) {
	var gotSQL string
	var gotArgs []any
	q := &fakeQuerier{
		execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			gotSQL = sql
			gotArgs = args
			return pgconn.CommandTag{}, nil
		},
	}
	repo := NewPermissionRepository(q)

	rule := authz.PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "rep_*",
		TenantID:          "tenant-1",
		Effect:            authz.EffectPermit,
	}
	if err := repo.GrantPermission(context.Background(), "principal-1", rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantSQL := `INSERT INTO auth_permission_rules (principal_id, action_pattern, resource_type, resource_id_pattern, tenant_id, effect) VALUES ($1,$2,$3,$4,$5,$6)`
	if gotSQL != wantSQL {
		t.Fatalf("SQL = %q, want %q", gotSQL, wantSQL)
	}
	wantArgs := []any{"principal-1", "read", "report", "rep_*", "tenant-1", authz.EffectPermit}
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("args = %+v, want %+v", gotArgs, wantArgs)
	}
	for i := range wantArgs {
		if gotArgs[i] != wantArgs[i] {
			t.Fatalf("args[%d] = %v, want %v", i, gotArgs[i], wantArgs[i])
		}
	}
}

func TestGrantPermission_ExecErrorPropagates(t *testing.T) {
	wantErr := errors.New("constraint violation")
	q := &fakeQuerier{
		execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, wantErr
		},
	}
	repo := NewPermissionRepository(q)

	err := repo.GrantPermission(context.Background(), "principal-1", authz.PermissionRule{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestRevokeAll_ParameterizesArgs(t *testing.T) {
	var gotSQL string
	var gotArgs []any
	q := &fakeQuerier{
		execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			gotSQL = sql
			gotArgs = args
			return pgconn.CommandTag{}, nil
		},
	}
	repo := NewPermissionRepository(q)

	if err := repo.RevokeAll(context.Background(), "principal-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantSQL := `DELETE FROM auth_permission_rules WHERE principal_id = $1`
	if gotSQL != wantSQL {
		t.Fatalf("SQL = %q, want %q", gotSQL, wantSQL)
	}
	if len(gotArgs) != 1 || gotArgs[0] != "principal-1" {
		t.Fatalf("args = %+v, want [principal-1]", gotArgs)
	}
}

func TestRevokeAll_ExecErrorPropagates(t *testing.T) {
	wantErr := errors.New("connection lost")
	q := &fakeQuerier{
		execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, wantErr
		},
	}
	repo := NewPermissionRepository(q)

	err := repo.RevokeAll(context.Background(), "principal-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

// Compile-time assertion (mirrors the one in repository.go): a
// *PermissionRepository satisfies authz.PermissionRepository.
var _ authz.PermissionRepository = (*PermissionRepository)(nil)
