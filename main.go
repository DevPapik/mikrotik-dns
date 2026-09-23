package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var lineRE = regexp.MustCompile(`^(?:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) )?dns query from (.+?): #[0-9]+ ([^ ]+)\. (\w+(?: \(\d+\))?)$`)

const (
	defaultRetentionHours = 24
	// deleteBatchSize limits how many rows a single DELETE transaction touches so
	// that the SQLite write lock is never held for long while UDP inserts continue.
	deleteBatchSize = 5000
)

func prepareDB(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS queries(
        id INTEGER PRIMARY KEY,
        timestamp INTEGER,
        client TEXT,
        domain TEXT,
        type TEXT
    )`,
		// Indexes are created lazily so an existing queries.db is upgraded in place on startup.
		`CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_queries_client_timestamp ON queries(client, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_queries_domain_timestamp ON queries(domain, timestamp)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// parseRetentionHours interprets the RETENTION_HOURS environment variable.
// An empty value means the default (24h). Zero disables automatic purging.
// Invalid or negative values return an error together with the safe default.
func parseRetentionHours(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultRetentionHours, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultRetentionHours, fmt.Errorf("invalid RETENTION_HOURS %q: not an integer", raw)
	}
	if n < 0 {
		return defaultRetentionHours, fmt.Errorf("invalid RETENTION_HOURS %q: must be >= 0", raw)
	}
	return n, nil
}

func retentionLabel(retentionHours int) string {
	switch {
	case retentionHours <= 0:
		return "Unlimited"
	case retentionHours%24 == 0:
		days := retentionHours / 24
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	case retentionHours == 1:
		return "1 hour"
	default:
		return fmt.Sprintf("%d hours", retentionHours)
	}
}

// deleteQueriesBatched deletes rows matching the WHERE clause in small batches so
// concurrent inserts are only briefly blocked. It returns the total rows deleted.
func deleteQueriesBatched(db *sql.DB, where string, args ...any) (int64, error) {
	stmt := `DELETE FROM queries WHERE rowid IN (SELECT rowid FROM queries WHERE ` + where + ` LIMIT ?)`
	batchArgs := append(append([]any{}, args...), deleteBatchSize)
	var total int64
	for {
		res, err := db.Exec(stmt, batchArgs...)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < deleteBatchSize {
			return total, nil
		}
	}
}

func purgeOld(db *sql.DB, retentionHours int) {
	if retentionHours <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour).Unix()
	n, err := deleteQueriesBatched(db, `timestamp < ?`, cutoff)
	if err != nil {
		log.Printf("Error purging old records: %v", err)
		return
	}
	if n > 0 {
		log.Printf("Purged %d records older than %d hours", n, retentionHours)
	}
}

func handleLine(db *sql.DB, line string) {
	m := lineRE.FindStringSubmatch(line)
	if m == nil {
		log.Printf("Unparsed line: %s", line)
		return
	}
	tsStr := m[1]
	var ts time.Time
	if tsStr != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", tsStr); err == nil {
			ts = t
		} else {
			ts = time.Now()
		}
	} else {
		ts = time.Now()
	}
	client := m[2]
	domain := m[3]
	qtypeRaw := m[4]

	qtypeRaw = normalizeQueryType(qtypeRaw)

	if strings.HasPrefix(qtypeRaw, "UNKNOWN") {
		log.Printf("Unknown type: [%s]", line)
	}
	if _, err := db.Exec(`INSERT INTO queries(timestamp, client, domain, type) VALUES(?,?,?,?)`,
		ts.Unix(), client, domain, qtypeRaw); err != nil {
		log.Printf("DB insert error: %v", err)
	} else {
		log.Printf("Logged query: %s %s %s", client, domain, qtypeRaw)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func serveAPI(db *sql.DB, retentionHours int) {
	handler := newAPIHandler(db, retentionHours)
	log.Println("Starting HTTP server on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func newAPIHandler(db *sql.DB, retentionHours int) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/top-domains", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT domain, COUNT(*) as cnt
            FROM queries
            GROUP BY domain
            ORDER BY cnt DESC
            LIMIT 20`)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var out []struct {
			Domain string `json:"domain"`
			Count  int    `json:"count"`
		}
		for rows.Next() {
			var d string
			var c int
			rows.Scan(&d, &c)
			out = append(out, struct {
				Domain string `json:"domain"`
				Count  int    `json:"count"`
			}{d, c})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/query-types", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT type, COUNT(*) AS cnt
            FROM queries
            GROUP BY type
            ORDER BY cnt DESC`)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var out []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		}
		for rows.Next() {
			var t string
			var c int
			rows.Scan(&t, &c)
			out = append(out, struct {
				Type  string `json:"type"`
				Count int    `json:"count"`
			}{t, c})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
            SELECT client, COUNT(*) as cnt
            FROM queries
            GROUP BY client
            ORDER BY cnt DESC
            LIMIT 20`)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var out []struct {
			Client string `json:"client"`
			Count  int    `json:"count"`
		}
		for rows.Next() {
			var cip string
			var cnt int
			rows.Scan(&cip, &cnt)
			out = append(out, struct {
				Client string `json:"client"`
				Count  int    `json:"count"`
			}{cip, cnt})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/unique-clients-count", func(w http.ResponseWriter, r *http.Request) {
		var count int
		err := db.QueryRow(`
        SELECT COUNT(DISTINCT client)
        FROM queries`).Scan(&count)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(struct {
			Count int `json:"count"`
		}{count})
	})

	mux.HandleFunc("/api/unique-domains-count", func(w http.ResponseWriter, r *http.Request) {
		var count int
		err := db.QueryRow(`
        SELECT COUNT(DISTINCT domain)
        FROM queries`).Scan(&count)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(struct {
			Count int `json:"count"`
		}{count})
	})

	mux.HandleFunc("/api/all-queries", func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 0 {
				page = n
			}
		}
		pageSize := 20
		if ps := r.URL.Query().Get("page_size"); ps != "" {
			if n, err := strconv.Atoi(ps); err == nil && n > 0 {
				pageSize = n
			}
		}
		offset := (page - 1) * pageSize

		rows, err := db.Query(`
        SELECT timestamp, client, domain, type
        FROM queries
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?`, pageSize, offset)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var out []struct {
			Timestamp int64  `json:"timestamp"`
			Client    string `json:"client"`
			Domain    string `json:"domain"`
			Type      string `json:"type"`
		}
		for rows.Next() {
			var ts int64
			var c, d, t string
			rows.Scan(&ts, &c, &d, &t)
			out = append(out, struct {
				Timestamp int64  `json:"timestamp"`
				Client    string `json:"client"`
				Domain    string `json:"domain"`
				Type      string `json:"type"`
			}{ts, c, d, t})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/domain-queries", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "domain query param required", http.StatusBadRequest)
			return
		}
		partial := r.URL.Query().Get("partial") == "true"
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 0 {
				page = n
			}
		}
		pageSize := 20
		if ps := r.URL.Query().Get("page_size"); ps != "" {
			if n, err := strconv.Atoi(ps); err == nil && n > 0 {
				pageSize = n
			}
		}
		offset := (page - 1) * pageSize

		var rows *sql.Rows
		var err error
		if partial {
			likePattern := "%" + domain + "%"
			rows, err = db.Query(`
        SELECT DISTINCT domain, type
        FROM queries
        WHERE domain LIKE ?
        ORDER BY domain
        LIMIT ? OFFSET ?`, likePattern, pageSize, offset)
		} else {
			rows, err = db.Query(`
        SELECT timestamp, client, domain, type
        FROM queries
        WHERE domain = ?
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?`, domain, pageSize, offset)
		}
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		if partial {
			var domains []struct {
				Domain     string        `json:"domain"`
				Type       string        `json:"type"`
				Resolution DNSResolution `json:"resolution"`
			}

			for rows.Next() {
				var d, t string
				rows.Scan(&d, &t)

				resolution := resolveDNS(d, t)

				domains = append(domains, struct {
					Domain     string        `json:"domain"`
					Type       string        `json:"type"`
					Resolution DNSResolution `json:"resolution"`
				}{d, t, resolution})
			}
			json.NewEncoder(w).Encode(domains)
		} else {
			var out []struct {
				Timestamp int64  `json:"timestamp"`
				Client    string `json:"client"`
				Domain    string `json:"domain"`
				Type      string `json:"type"`
			}
			for rows.Next() {
				var ts int64
				var c, d, t string
				rows.Scan(&ts, &c, &d, &t)
				out = append(out, struct {
					Timestamp int64  `json:"timestamp"`
					Client    string `json:"client"`
					Domain    string `json:"domain"`
					Type      string `json:"type"`
				}{ts, c, d, t})
			}
			json.NewEncoder(w).Encode(out)
		}
	})

	mux.HandleFunc("/api/queries-per-minute", func(w http.ResponseWriter, r *http.Request) {
		var totalQueries int
		var minTS, maxTS sql.NullInt64
		err := db.QueryRow(`
			SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
			FROM queries
		`).Scan(&totalQueries, &minTS, &maxTS)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}

		// With a finite retention the window is the retention period itself
		// (24h = 1440 minutes by default). With unlimited retention use the
		// actual span of stored data instead of an artificial window.
		windowMinutes := retentionHours * 60
		if retentionHours <= 0 {
			windowMinutes = 1
			if minTS.Valid && maxTS.Valid {
				if span := int((maxTS.Int64 - minTS.Int64) / 60); span > windowMinutes {
					windowMinutes = span
				}
			}
		}
		queriesPerMinute := float64(totalQueries) / float64(windowMinutes)

		json.NewEncoder(w).Encode(struct {
			QueriesPerMinute float64 `json:"queries_per_minute"`
			TotalQueries     int     `json:"total_queries"`
			TimeWindow       int     `json:"time_window_minutes"`
		}{
			QueriesPerMinute: queriesPerMinute,
			TotalQueries:     totalQueries,
			TimeWindow:       windowMinutes,
		})
	})

	mux.HandleFunc("/api/ipv4-vs-ipv6", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
			SELECT
				CASE
					WHEN INSTR(client, ':') > 0 THEN 'IPv6'
					ELSE 'IPv4'
				END as ip_type,
				COUNT(*) as count
			FROM queries
			GROUP BY ip_type
		`)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var out []struct {
			IPType string `json:"ip_type"`
			Count  int    `json:"count"`
		}
		for rows.Next() {
			var ipType string
			var count int
			rows.Scan(&ipType, &count)
			out = append(out, struct {
				IPType string `json:"ip_type"`
				Count  int    `json:"count"`
			}{ipType, count})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/domain-clients", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "domain query param required", http.StatusBadRequest)
			return
		}
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 0 {
				page = n
			}
		}
		pageSize := 20
		if ps := r.URL.Query().Get("page_size"); ps != "" {
			if n, err := strconv.Atoi(ps); err == nil && n > 0 {
				pageSize = n
			}
		}
		offset := (page - 1) * pageSize

		rows, err := db.Query(`
			SELECT client, COUNT(*) as query_count, MAX(timestamp) as last_query
			FROM queries
			WHERE domain = ?
			GROUP BY client
			ORDER BY query_count DESC, last_query DESC
			LIMIT ? OFFSET ?`, domain, pageSize, offset)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var out []struct {
			Client     string `json:"client"`
			QueryCount int    `json:"query_count"`
			LastQuery  int64  `json:"last_query"`
		}
		for rows.Next() {
			var client string
			var queryCount int
			var lastQuery int64
			rows.Scan(&client, &queryCount, &lastQuery)
			out = append(out, struct {
				Client     string `json:"client"`
				QueryCount int    `json:"query_count"`
				LastQuery  int64  `json:"last_query"`
			}{client, queryCount, lastQuery})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/client-queries", func(w http.ResponseWriter, r *http.Request) {
		client := r.URL.Query().Get("client")
		if client == "" {
			http.Error(w, "client query param required", http.StatusBadRequest)
			return
		}
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 0 {
				page = n
			}
		}
		pageSize := 20
		if ps := r.URL.Query().Get("page_size"); ps != "" {
			if n, err := strconv.Atoi(ps); err == nil && n > 0 {
				pageSize = n
			}
		}
		offset := (page - 1) * pageSize

		rows, err := db.Query(`
            SELECT timestamp, domain, type
            FROM queries
            WHERE client = ?
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?`, client, pageSize, offset)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var out []struct {
			Timestamp int64  `json:"timestamp"`
			Domain    string `json:"domain"`
			Type      string `json:"type"`
		}
		for rows.Next() {
			var ts int64
			var d, t string
			rows.Scan(&ts, &d, &t)
			out = append(out, struct {
				Timestamp int64  `json:"timestamp"`
				Domain    string `json:"domain"`
				Type      string `json:"type"`
			}{ts, d, t})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("GET /api/retention", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			RetentionHours int    `json:"retention_hours"`
			Unlimited      bool   `json:"unlimited"`
			Label          string `json:"label"`
		}{retentionHours, retentionHours <= 0, retentionLabel(retentionHours)})
	})

	mux.HandleFunc("GET /api/client-queries/count", func(w http.ResponseWriter, r *http.Request) {
		client := r.URL.Query().Get("client")
		if client == "" {
			http.Error(w, "client query param required", http.StatusBadRequest)
			return
		}
		var count int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM queries WHERE client = ?`, client).Scan(&count); err != nil {
			log.Printf("Error counting queries for client: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(struct {
			Client string `json:"client"`
			Count  int64  `json:"count"`
		}{client, count})
	})

	mux.HandleFunc("GET /api/client-queries/export", func(w http.ResponseWriter, r *http.Request) {
		client := r.URL.Query().Get("client")
		if client == "" {
			http.Error(w, "client query param required", http.StatusBadRequest)
			return
		}
		rows, err := db.QueryContext(r.Context(), `
            SELECT timestamp, client, domain, type
            FROM queries
            WHERE client = ?
            ORDER BY timestamp ASC, id ASC`, client)
		if err != nil {
			log.Printf("Error exporting client queries: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		streamCSV(w, r, rows, csvFilename(client))
	})

	mux.HandleFunc("GET /api/queries/export", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.QueryContext(r.Context(), `
            SELECT timestamp, client, domain, type
            FROM queries
            ORDER BY timestamp ASC, id ASC`)
		if err != nil {
			log.Printf("Error exporting queries: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		streamCSV(w, r, rows, csvFilename("all"))
	})

	mux.HandleFunc("DELETE /api/client-queries", func(w http.ResponseWriter, r *http.Request) {
		client := r.URL.Query().Get("client")
		if client == "" {
			http.Error(w, "client query param required", http.StatusBadRequest)
			return
		}
		deleted, err := deleteQueriesBatched(db, `client = ?`, client)
		if err != nil {
			log.Printf("Error deleting queries for client: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		log.Printf("Deleted %d queries for client %s", deleted, client)
		json.NewEncoder(w).Encode(struct {
			Client  string `json:"client"`
			Deleted int64  `json:"deleted"`
		}{client, deleted})
	})

	mux.HandleFunc("DELETE /api/queries", func(w http.ResponseWriter, r *http.Request) {
		// A DELETE without WHERE uses SQLite's truncate optimisation: the table,
		// its indexes and the schema stay intact, only the rows are removed.
		res, err := db.Exec(`DELETE FROM queries`)
		if err != nil {
			log.Printf("Error clearing queries: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		deleted, err := res.RowsAffected()
		if err != nil {
			log.Printf("Error clearing queries: %v", err)
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		log.Printf("Cleared all DNS query history (%d rows)", deleted)
		json.NewEncoder(w).Encode(struct {
			Deleted int64 `json:"deleted"`
		}{deleted})
	})

	return corsMiddleware(loggingMiddleware(mux))
}

// csvFilename builds "dns-queries-<name>-<YYYY-MM-DD>.csv", keeping only
// characters that are safe inside a Content-Disposition filename.
func csvFilename(name string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, name)
	if safe == "" {
		safe = "export"
	}
	return fmt.Sprintf("dns-queries-%s-%s.csv", safe, time.Now().Format("2006-01-02"))
}

// streamCSV writes rows of (timestamp, client, domain, type) straight from the
// database cursor into the HTTP response, so exports of any size run in
// constant memory. rows is closed by the caller.
func streamCSV(w http.ResponseWriter, r *http.Request, rows *sql.Rows, filename string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"timestamp", "client", "domain", "type"}); err != nil {
		return
	}
	flusher, _ := w.(http.Flusher)
	ctx := r.Context()

	const flushEvery = 1000
	n := 0
	for rows.Next() {
		var ts int64
		var client, domain, qtype string
		if err := rows.Scan(&ts, &client, &domain, &qtype); err != nil {
			log.Printf("CSV export scan error: %v", err)
			return
		}
		record := []string{
			time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
			client,
			domain,
			qtype,
		}
		if err := cw.Write(record); err != nil {
			return
		}
		n++
		if n%flushEvery == 0 {
			cw.Flush()
			if err := cw.Error(); err != nil {
				// The HTTP client went away; stop reading rows.
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}
	if err := rows.Err(); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Printf("CSV export rows error: %v", err)
		}
		return
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return
	}
	if flusher != nil {
		flusher.Flush()
	}
}

func main() {
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./data/dnslogs.db"
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := prepareDB(db); err != nil {
		log.Fatalf("Failed to prepare database: %v", err)
	}

	retentionHours, err := parseRetentionHours(os.Getenv("RETENTION_HOURS"))
	if err != nil {
		log.Printf("Warning: %v, falling back to %d hours", err, defaultRetentionHours)
	}
	if retentionHours > 0 {
		log.Printf("Retention: %d hours (%s)", retentionHours, retentionLabel(retentionHours))
		go func() {
			for {
				purgeOld(db, retentionHours)
				time.Sleep(time.Hour)
			}
		}()
	} else {
		log.Println("Retention: unlimited, automatic purge disabled")
	}

	go func() {
		addr, _ := net.ResolveUDPAddr("udp", ":5354")
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Fatalf("Failed to listen UDP: %v", err)
		}
		defer conn.Close()
		log.Println("Listening for UDP on :5354")

		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("Error reading UDP: %v", err)
				continue
			}
			data := string(buf[:n])
			for line := range strings.SplitSeq(strings.TrimRight(data, "\n"), "\n") {
				handleLine(db, line)
			}
		}
	}()

	serveAPI(db, retentionHours)
}

// dnsTypeNames maps DNS RR TYPE codes (IANA DNS parameters registry) to their
// names. RouterOS logs record types it does not know as "UNKNOWN (n)".
var dnsTypeNames = map[int]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
	17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV",
	35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS",
	44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
	50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP", 59: "CDS",
	60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
	99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR",
	252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA", 32768: "TA", 32769: "DLV",
}

// normalizeQueryType converts the query type captured from a RouterOS log line
// into the value stored in the database. Regular names (A, AAAA, ...) pass
// through unchanged. "UNKNOWN (n)" is mapped to the standard RR type name when
// n is known; otherwise the original "UNKNOWN (n)" text is kept so the numeric
// code is not lost.
func normalizeQueryType(qtypeRaw string) string {
	qtypeRaw = strings.TrimSpace(qtypeRaw)
	if qtypeRaw == "" {
		return "UNKNOWN"
	}
	if !strings.HasPrefix(qtypeRaw, "UNKNOWN") {
		return qtypeRaw
	}
	num, err := extractDNSTypeNumber(qtypeRaw)
	if err != nil {
		return "UNKNOWN"
	}
	if name, ok := dnsTypeNames[num]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN (%d)", num)
}

func extractDNSTypeNumber(qtypeRaw string) (int, error) {
	start := strings.Index(qtypeRaw, "(")
	end := strings.Index(qtypeRaw, ")")

	if start == -1 || end == -1 || start >= end-1 {
		return 0, errors.New("invalid DNS type format")
	}

	numStr := strings.TrimSpace(qtypeRaw[start+1 : end])
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, errors.New("invalid DNS type number")
	}

	return num, nil
}

type DNSResolution struct {
	Status   string   `json:"status"`  // "success", "blocked", "error"
	Records  []string `json:"records"` // IP addresses, CNAME, etc
	Error    string   `json:"error,omitempty"`
	Duration int64    `json:"duration"` // Resolution time in milliseconds
}

func resolveDNS(domain string, queryType string) DNSResolution {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dnsServer := os.Getenv("DNS_SERVER")
	var resolver *net.Resolver

	if dnsServer != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * 2}
				return d.DialContext(ctx, network, dnsServer+":53")
			},
		}
	} else {
		resolver = &net.Resolver{}
	}

	var result DNSResolution
	var records []string
	var err error

	switch strings.ToUpper(queryType) {
	case "A":
		ips, lookupErr := resolver.LookupIPAddr(ctx, domain)
		err = lookupErr
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				ipStr := ip.IP.String()
				if ipStr == "0.0.0.0" {
					result.Status = "blocked"
					result.Error = "Domain blocked (0.0.0.0 response)"
					result.Duration = time.Since(start).Milliseconds()
					return result
				}
				records = append(records, ipStr)
			}
		}
	case "AAAA":
		ips, lookupErr := resolver.LookupIPAddr(ctx, domain)
		err = lookupErr
		for _, ip := range ips {
			if ip.IP.To16() != nil && ip.IP.To4() == nil {
				ipStr := ip.IP.String()
				if ipStr == "::" {
					result.Status = "blocked"
					result.Error = "Domain blocked (:: response)"
					result.Duration = time.Since(start).Milliseconds()
					return result
				}
				records = append(records, ipStr)
			}
		}
	case "CNAME":
		cname, lookupErr := resolver.LookupCNAME(ctx, domain)
		err = lookupErr
		if cname != domain && cname != domain+"." {
			records = append(records, cname)
		}
	case "TXT":
		txts, lookupErr := resolver.LookupTXT(ctx, domain)
		err = lookupErr
		for _, txt := range txts {
			if len(txt) > 200 {
				txt = txt[:200] + "..."
			}
			records = append(records, txt)
		}
	case "MX":
		mxs, lookupErr := resolver.LookupMX(ctx, domain)
		err = lookupErr
		for _, mx := range mxs {
			records = append(records, strconv.Itoa(int(mx.Pref))+" "+mx.Host)
		}
	case "NS":
		nss, lookupErr := resolver.LookupNS(ctx, domain)
		err = lookupErr
		for _, ns := range nss {
			records = append(records, ns.Host)
		}
	case "PTR":
		ptrs, lookupErr := resolver.LookupAddr(ctx, domain)
		err = lookupErr
		records = ptrs
	default:
		ips, lookupErr := resolver.LookupIPAddr(ctx, domain)
		err = lookupErr
		for _, ip := range ips {
			ipStr := ip.IP.String()
			if ipStr == "0.0.0.0" || ipStr == "::" {
				result.Status = "blocked"
				result.Error = "Domain blocked (" + ipStr + " response)"
				result.Duration = time.Since(start).Milliseconds()
				return result
			}
			records = append(records, ipStr)
		}
	}

	if err != nil {
		if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server misbehaving") ||
			strings.Contains(err.Error(), "connection refused") {
			result.Status = "blocked"
			result.Error = err.Error()
		} else {
			result.Status = "error"
			result.Error = err.Error()
		}
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	if len(records) == 0 {
		result.Status = "blocked"
		result.Error = "No records returned"
	} else {
		result.Status = "success"
		result.Records = records
	}

	result.Duration = time.Since(start).Milliseconds()
	return result
}
