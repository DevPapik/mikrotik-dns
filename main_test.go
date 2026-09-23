package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "queries.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := prepareDB(db); err != nil {
		t.Fatalf("prepareDB: %v", err)
	}
	return db
}

func insertQuery(t *testing.T, db *sql.DB, ts int64, client, domain, qtype string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`, ts, client, domain, qtype); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func countRows(t *testing.T, db *sql.DB, where string, args ...any) int {
	t.Helper()
	q := `SELECT COUNT(*) FROM queries`
	if where != "" {
		q += " WHERE " + where
	}
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func doRequest(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// --- DNS type normalisation -------------------------------------------------

func TestNormalizeQueryType(t *testing.T) {
	cases := map[string]string{
		"A":               "A",
		"AAAA":            "AAAA",
		"CNAME":           "CNAME",
		"TXT":             "TXT",
		"MX":              "MX",
		"PTR":             "PTR",
		"UNKNOWN (64)":    "SVCB",
		"UNKNOWN (65)":    "HTTPS",
		"UNKNOWN (257)":   "CAA",
		"UNKNOWN (44)":    "SSHFP",
		"UNKNOWN (65400)": "UNKNOWN (65400)",
		"UNKNOWN":         "UNKNOWN",
		"":                "UNKNOWN",
	}
	for in, want := range cases {
		if got := normalizeQueryType(in); got != want {
			t.Errorf("normalizeQueryType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHandleLineParsing(t *testing.T) {
	db := newTestDB(t)
	lines := []string{
		"2025-01-15 14:23:45 dns query from 192.168.1.100: #12345 google.com. A",
		"dns query from 192.168.1.100: #12346 facebook.com. AAAA",
		"query from 172.16.0.14: #2052 www.bing.com. UNKNOWN (65)", // no "dns " prefix: must be ignored
		"2025-01-15 14:23:47 dns query from 172.16.0.14: #2052 www.bing.com. UNKNOWN (65)",
		"2025-01-15 14:23:48 dns query from 172.16.0.14: #2053 apple.com. UNKNOWN (64)",
		"2025-01-15 14:23:49 dns query from 172.16.0.14: #2054 example.org. UNKNOWN (257)",
		"2025-01-15 14:23:50 dns query from 172.16.0.14: #2055 weird.test. UNKNOWN (65400)",
		"2025-01-15 14:23:51 dns query from fe80::1: #2056 mail.example.com. MX",
		"2025-01-15 14:23:52 dns query from 10.0.0.1: #2057 _dmarc.example.com. TXT",
		"2025-01-15 14:23:53 dns query from 10.0.0.1: #2058 alias.example.com. CNAME",
		"garbage that does not parse",
	}
	for _, l := range lines {
		handleLine(db, l)
	}

	rows, err := db.Query(`SELECT timestamp, client, domain, type FROM queries ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type rec struct {
		ts                   int64
		client, domain, kind string
	}
	var got []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.ts, &r.client, &r.domain, &r.kind); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	want := []rec{
		{1736951025, "192.168.1.100", "google.com", "A"},
		{0, "192.168.1.100", "facebook.com", "AAAA"},
		{1736951027, "172.16.0.14", "www.bing.com", "HTTPS"},
		{1736951028, "172.16.0.14", "apple.com", "SVCB"},
		{1736951029, "172.16.0.14", "example.org", "CAA"},
		{1736951030, "172.16.0.14", "weird.test", "UNKNOWN (65400)"},
		{1736951031, "fe80::1", "mail.example.com", "MX"},
		{1736951032, "10.0.0.1", "_dmarc.example.com", "TXT"},
		{1736951033, "10.0.0.1", "alias.example.com", "CNAME"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].client != want[i].client || got[i].domain != want[i].domain || got[i].kind != want[i].kind {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
		if want[i].ts != 0 && got[i].ts != want[i].ts {
			t.Errorf("row %d timestamp = %d, want %d", i, got[i].ts, want[i].ts)
		}
		if want[i].ts == 0 && time.Since(time.Unix(got[i].ts, 0)) > time.Minute {
			t.Errorf("row %d without log timestamp should use now, got %d", i, got[i].ts)
		}
	}
}

// --- Retention ---------------------------------------------------------------

func TestParseRetentionHours(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 24, false},
		{"24", 24, false},
		{"168", 168, false},
		{"720", 720, false},
		{" 48 ", 48, false},
		{"0", 0, false},
		{"abc", 24, true},
		{"1.5", 24, true},
		{"-5", 24, true},
	}
	for _, c := range cases {
		got, err := parseRetentionHours(c.in)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("parseRetentionHours(%q) = (%d, %v), want (%d, err=%v)", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestRetentionLabel(t *testing.T) {
	cases := map[int]string{0: "Unlimited", 1: "1 hour", 6: "6 hours", 24: "1 day", 168: "7 days", 720: "30 days"}
	for in, want := range cases {
		if got := retentionLabel(in); got != want {
			t.Errorf("retentionLabel(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestPurgeOld(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	// More rows than one delete batch, all older than 24h.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < deleteBatchSize*2+10; i++ {
		if _, err := tx.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`, now-25*3600-int64(i), "10.0.0.1", "old.example", "A"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	insertQuery(t, db, now-23*3600, "10.0.0.1", "recent.example", "A")
	insertQuery(t, db, now-150*3600, "10.0.0.2", "week-old.example", "A")
	total := countRows(t, db, "")

	// Unlimited retention: nothing is deleted.
	purgeOld(db, 0)
	if n := countRows(t, db, ""); n != total {
		t.Fatalf("retention 0 deleted rows: %d -> %d", total, n)
	}

	// 168h keeps the week-old row, 24h removes it.
	purgeOld(db, 168)
	if n := countRows(t, db, ""); n != total {
		t.Fatalf("retention 168 deleted rows that are younger than 7 days: %d -> %d", total, n)
	}
	purgeOld(db, 24)
	if n := countRows(t, db, ""); n != 1 {
		t.Fatalf("retention 24: want 1 row left, got %d", n)
	}
	if n := countRows(t, db, "domain = ?", "recent.example"); n != 1 {
		t.Fatalf("recent row was purged")
	}
}

func TestRetentionEndpoint(t *testing.T) {
	db := newTestDB(t)
	for _, c := range []struct {
		hours     int
		unlimited bool
		label     string
	}{{24, false, "1 day"}, {168, false, "7 days"}, {0, true, "Unlimited"}} {
		rec := doRequest(t, newAPIHandler(db, c.hours), http.MethodGet, "/api/retention")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var out struct {
			RetentionHours int    `json:"retention_hours"`
			Unlimited      bool   `json:"unlimited"`
			Label          string `json:"label"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.RetentionHours != c.hours || out.Unlimited != c.unlimited || out.Label != c.label {
			t.Errorf("retention %d: got %+v", c.hours, out)
		}
	}
}

func TestQueriesPerMinuteWindow(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	for i := 0; i < 120; i++ {
		insertQuery(t, db, now-int64(i)*60, "10.0.0.1", "a.example", "A")
	}
	get := func(h int) (float64, int) {
		rec := doRequest(t, newAPIHandler(db, h), http.MethodGet, "/api/queries-per-minute")
		var out struct {
			QPM    float64 `json:"queries_per_minute"`
			Window int     `json:"time_window_minutes"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.QPM, out.Window
	}
	if qpm, w := get(24); w != 1440 || qpm != 120.0/1440.0 {
		t.Errorf("24h: qpm=%v window=%d", qpm, w)
	}
	if _, w := get(168); w != 168*60 {
		t.Errorf("168h: window=%d", w)
	}
	if qpm, w := get(0); w != 119 || qpm != 120.0/119.0 {
		t.Errorf("unlimited: qpm=%v window=%d (want actual span 119)", qpm, w)
	}
}

// --- Old records are visible when retention allows it ------------------------

func TestOldRecordsVisibleWithLongRetention(t *testing.T) {
	db := newTestDB(t)
	old := time.Now().Add(-15 * 24 * time.Hour).Unix()
	insertQuery(t, db, old, "10.0.0.9", "fifteen-days.example", "A")
	h := newAPIHandler(db, 720)

	for _, target := range []string{
		"/api/client-queries?client=10.0.0.9",
		"/api/all-queries",
		"/api/domain-queries?domain=fifteen-days.example",
		"/api/domain-clients?domain=fifteen-days.example",
		"/api/top-domains",
		"/api/clients",
		"/api/client-queries/export?client=10.0.0.9",
		"/api/queries/export",
	} {
		rec := doRequest(t, h, http.MethodGet, target)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "fifteen-days.example") && !strings.Contains(rec.Body.String(), "10.0.0.9") {
			t.Errorf("%s: 15 day old record missing (status %d, body %q)", target, rec.Code, rec.Body.String())
		}
	}
	for _, target := range []string{"/api/unique-domains-count", "/api/unique-clients-count"} {
		rec := doRequest(t, h, http.MethodGet, target)
		if !strings.Contains(rec.Body.String(), `"count":1`) {
			t.Errorf("%s = %s", target, rec.Body.String())
		}
	}
	rec := doRequest(t, h, http.MethodGet, "/api/query-types")
	if !strings.Contains(rec.Body.String(), `"type":"A","count":1`) {
		t.Errorf("query-types = %s", rec.Body.String())
	}
}

// --- CSV export --------------------------------------------------------------

func parseCSV(t *testing.T, body string) [][]string {
	t.Helper()
	recs, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, body)
	}
	return recs
}

func TestExportClientCSV(t *testing.T) {
	db := newTestDB(t)
	base := time.Date(2026, 9, 24, 0, 11, 11, 0, time.Local).Unix()
	insertQuery(t, db, base+1, "172.16.0.14", "www.adobe.com", "A")
	insertQuery(t, db, base, "172.16.0.14", "apple.com", "A")
	insertQuery(t, db, base+2, "172.16.0.14", `we"ird,domain.test`, "UNKNOWN (65400)")
	insertQuery(t, db, base, "172.16.0.15", "other.example", "AAAA")
	h := newAPIHandler(db, 24)

	rec := doRequest(t, h, http.MethodGet, "/api/client-queries/export?client=172.16.0.14")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type %q", ct)
	}
	wantName := fmt.Sprintf(`attachment; filename="dns-queries-172.16.0.14-%s.csv"`, time.Now().Format("2006-01-02"))
	if cd := rec.Header().Get("Content-Disposition"); cd != wantName {
		t.Errorf("content-disposition %q, want %q", cd, wantName)
	}
	recs := parseCSV(t, rec.Body.String())
	want := [][]string{
		{"timestamp", "client", "domain", "type"},
		{"2026-09-24 00:11:11", "172.16.0.14", "apple.com", "A"},
		{"2026-09-24 00:11:12", "172.16.0.14", "www.adobe.com", "A"},
		{"2026-09-24 00:11:13", "172.16.0.14", `we"ird,domain.test`, "UNKNOWN (65400)"},
	}
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d:\n%s", len(recs), len(want), rec.Body.String())
	}
	for i := range want {
		if strings.Join(recs[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("record %d = %v, want %v", i, recs[i], want[i])
		}
	}
	// Raw escaping check: the quote must be doubled and the field quoted.
	if !strings.Contains(rec.Body.String(), `"we""ird,domain.test"`) {
		t.Errorf("csv escaping missing:\n%s", rec.Body.String())
	}

	// Client without queries: header only.
	rec = doRequest(t, h, http.MethodGet, "/api/client-queries/export?client=10.99.99.99")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "timestamp,client,domain,type" {
		t.Errorf("empty export: status %d body %q", rec.Code, rec.Body.String())
	}

	// Missing parameter.
	if rec = doRequest(t, h, http.MethodGet, "/api/client-queries/export"); rec.Code != http.StatusBadRequest {
		t.Errorf("missing client: status %d", rec.Code)
	}

	// IPv6 client: filename must be sanitised, the client column must not.
	insertQuery(t, db, base, "fe80::1", "v6.example", "AAAA")
	rec = doRequest(t, h, http.MethodGet, "/api/client-queries/export?client=fe80%3A%3A1")
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "dns-queries-fe80__1-") {
		t.Errorf("ipv6 filename %q", cd)
	}
	if !strings.Contains(rec.Body.String(), "fe80::1,v6.example,AAAA") {
		t.Errorf("ipv6 export body:\n%s", rec.Body.String())
	}
}

func TestExportAllCSVLarge(t *testing.T) {
	db := newTestDB(t)
	const n = 3500 // crosses several flush boundaries
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-48 * time.Hour).Unix()
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`,
			base+int64(i), fmt.Sprintf("10.0.%d.%d", i/256, i%256), fmt.Sprintf("d%d.example", i), "A"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, newAPIHandler(db, 24), http.MethodGet, "/api/queries/export")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "dns-queries-all-") {
		t.Errorf("content-disposition %q", cd)
	}
	recs := parseCSV(t, rec.Body.String())
	if len(recs) != n+1 {
		t.Fatalf("got %d records, want %d", len(recs), n+1)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i][2] != fmt.Sprintf("d%d.example", i-1) {
			t.Fatalf("record %d out of order: %v", i, recs[i])
		}
	}
}

// --- Delete ------------------------------------------------------------------

func TestDeleteClientQueries(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < deleteBatchSize+123; i++ {
		if _, err := tx.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`, now-int64(i), "172.16.0.14", "a.example", "A"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	insertQuery(t, db, now, "172.16.0.15", "b.example", "A")
	insertQuery(t, db, now, "172.16.0.140", "c.example", "A") // prefix of the target: must survive
	h := newAPIHandler(db, 24)

	rec := doRequest(t, h, http.MethodGet, "/api/client-queries/count?client=172.16.0.14")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), fmt.Sprintf(`"count":%d`, deleteBatchSize+123)) {
		t.Fatalf("count: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, h, http.MethodDelete, "/api/client-queries?client=172.16.0.14")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Client  string `json:"client"`
		Deleted int64  `json:"deleted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deleted != int64(deleteBatchSize+123) || out.Client != "172.16.0.14" {
		t.Errorf("delete response %+v", out)
	}
	if n := countRows(t, db, "client = ?", "172.16.0.14"); n != 0 {
		t.Errorf("client rows left: %d", n)
	}
	if n := countRows(t, db, ""); n != 2 {
		t.Errorf("other clients affected, %d rows left", n)
	}

	// Existing GET list endpoint still works on the same path.
	rec = doRequest(t, h, http.MethodGet, "/api/client-queries?client=172.16.0.15")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "b.example") {
		t.Errorf("GET /api/client-queries broken: %d %s", rec.Code, rec.Body.String())
	}
	// Missing parameter.
	if rec = doRequest(t, h, http.MethodDelete, "/api/client-queries"); rec.Code != http.StatusBadRequest {
		t.Errorf("delete without client: status %d", rec.Code)
	}
	// Deleting a client with no rows is a no-op.
	rec = doRequest(t, h, http.MethodDelete, "/api/client-queries?client=10.9.9.9")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":0`) {
		t.Errorf("delete of unknown client: %d %s", rec.Code, rec.Body.String())
	}
}

func TestClearAllQueries(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	for i := 0; i < 50; i++ {
		insertQuery(t, db, now-int64(i), fmt.Sprintf("10.0.0.%d", i%5), "x.example", "A")
	}
	h := newAPIHandler(db, 24)

	// GET/POST must never delete.
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		if rec := doRequest(t, h, m, "/api/queries"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/queries: status %d, want 405", m, rec.Code)
		}
	}
	if n := countRows(t, db, ""); n != 50 {
		t.Fatalf("non-DELETE methods removed rows: %d left", n)
	}

	rec := doRequest(t, h, http.MethodDelete, "/api/queries")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":50`) {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if n := countRows(t, db, ""); n != 0 {
		t.Errorf("rows left after clear: %d", n)
	}

	// Schema and indexes survive.
	var idx int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='queries' AND name LIKE 'idx_queries_%'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if idx != 3 {
		t.Errorf("indexes after clear: %d, want 3", idx)
	}
	// Writes keep working and stats reflect the empty state.
	handleLine(db, "dns query from 10.0.0.1: #1 after.example. A")
	if n := countRows(t, db, ""); n != 1 {
		t.Errorf("insert after clear failed: %d rows", n)
	}
	rec = doRequest(t, h, http.MethodGet, "/api/unique-clients-count")
	if !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Errorf("stats after clear: %s", rec.Body.String())
	}
}

// --- Existing behaviour ------------------------------------------------------

func TestPaginationStillWorks(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	for i := 0; i < 45; i++ {
		insertQuery(t, db, now-int64(i), "10.0.0.1", fmt.Sprintf("d%02d.example", i), "A")
	}
	h := newAPIHandler(db, 24)
	page := func(target string) []map[string]any {
		rec := doRequest(t, h, http.MethodGet, target)
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v (%s)", target, err, rec.Body.String())
		}
		return out
	}
	p1 := page("/api/client-queries?client=10.0.0.1&page=1&page_size=20")
	p3 := page("/api/client-queries?client=10.0.0.1&page=3&page_size=20")
	if len(p1) != 20 || len(p3) != 5 {
		t.Errorf("client pagination: page1=%d page3=%d", len(p1), len(p3))
	}
	if p1[0]["domain"] != "d00.example" {
		t.Errorf("newest first expected, got %v", p1[0])
	}
	a1 := page("/api/all-queries?page=1&page_size=50")
	a2 := page("/api/all-queries?page=2&page_size=50")
	if len(a1) != 45 || len(a2) != 0 {
		t.Errorf("all-queries pagination: page1=%d page2=%d", len(a1), len(a2))
	}
}

func TestExistingDatabaseIsUpgraded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.db")
	old, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	// Schema exactly as created by previous versions (no indexes).
	if _, err := old.Exec(`CREATE TABLE queries(id INTEGER PRIMARY KEY, timestamp INTEGER, client TEXT, domain TEXT, type TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(1, '10.0.0.1', 'legacy.example', 'A')`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := prepareDB(db); err != nil {
		t.Fatalf("prepareDB on legacy db: %v", err)
	}
	if err := prepareDB(db); err != nil {
		t.Fatalf("prepareDB must be idempotent: %v", err)
	}
	if n := countRows(t, db, "domain = ?", "legacy.example"); n != 1 {
		t.Errorf("legacy data lost")
	}
	var idx int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_queries_%'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if idx != 3 {
		t.Errorf("indexes: %d, want 3", idx)
	}
}

// --- Concurrency -------------------------------------------------------------

func TestConcurrentWritesDuringExportAndDelete(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		if _, err := tx.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`, now-int64(i), "172.16.0.14", "a.example", "A"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newAPIHandler(db, 24))
	defer srv.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var writerErr error
	var writes int
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := db.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`, time.Now().Unix(), "10.0.0.2", "live.example", "A"); err != nil {
				writerErr = err
				return
			}
			writes++
		}
	}()

	resp, err := http.Get(srv.URL + "/api/queries/export")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(parseCSV(t, string(body))) < 20001 {
		t.Errorf("export during writes: status %d, %d bytes", resp.StatusCode, len(body))
	}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/client-queries?client=172.16.0.14", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"deleted":20000`) {
		t.Errorf("delete during writes: %d %s", resp.StatusCode, body)
	}

	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/api/queries", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	close(stop)
	wg.Wait()
	if writerErr != nil {
		t.Errorf("concurrent writer failed: %v", writerErr)
	}
	if writes == 0 {
		t.Errorf("writer made no progress")
	}
	if n := countRows(t, db, "client = ?", "172.16.0.14"); n != 0 {
		t.Errorf("deleted client rows remain: %d", n)
	}
}

func TestExportStopsWhenClientDisconnects(t *testing.T) {
	db := newTestDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50000; i++ {
		if _, err := tx.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`, int64(i), "10.0.0.1", "a.example", "A"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		newAPIHandler(db, 24).ServeHTTP(w, r)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/queries/export")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() // disconnect mid-stream

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after client disconnect")
	}
}
