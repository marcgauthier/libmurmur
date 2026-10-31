// Schema adoption: manifests, additive diffs, and DDL application.
//
// Go port of schema.rs. Manifests carry monotonic sequences per digest
// under the schema manifest key; adoption applies additive deltas
// (new tables, new columns) after validating every statement.
// Destructive diffs are recorded, never adopted.
package replication

import (
	"sort"
	"strings"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/tx"
)

// SchemaParams are the adoption knobs.
type SchemaParams struct {
	AcceptRemoteSchema bool
	SchemaMaster       *NodeID
	Master             bool
	MaxSchemaBytes     int
}

// SchemaParamsFrom loads adoption knobs from settings.
func SchemaParamsFrom(db *sqlite.Conn) (*SchemaParams, error) {
	flag := func(name string) (bool, error) {
		raw, err := Setting(db, name)
		if err != nil {
			return false, err
		}
		switch raw {
		case "1":
			return true, nil
		case "0":
			return false, nil
		default:
			return false, errInvalidf("invalid %s", name)
		}
	}
	raw, err := Setting(db, "schema_master")
	if err != nil {
		return nil, err
	}
	var master *NodeID
	if raw != "" {
		id, err := ParseID(raw)
		if err != nil {
			return nil, err
		}
		master = &id
	}
	maxRaw, err := Setting(db, "max_batch_bytes")
	if err != nil {
		return nil, err
	}
	maxBytes, err := atoi(maxRaw)
	if err != nil {
		return nil, errInvalid("invalid max_batch_bytes")
	}
	accept, err := flag("accept_remote_schema")
	if err != nil {
		return nil, err
	}
	isMaster, err := flag("schema_master_enabled")
	if err != nil {
		return nil, err
	}
	return &SchemaParams{AcceptRemoteSchema: accept, SchemaMaster: master, Master: isMaster, MaxSchemaBytes: int(maxBytes)}, nil
}

// BuildSchemaManifest returns the monotonic manifest for schema bytes.
// Unsigned; the master designation is checked against the live node id.
func BuildSchemaManifest(backend tx.Backend, params *SchemaParams, own, database NodeID, schema []byte) (tx.SignedSchema, error) {
	var zero tx.SignedSchema
	if params.Master && (params.SchemaMaster == nil || *params.SchemaMaster != own) {
		return zero, errInvalid("schema master must designate its own node id")
	}
	if len(schema) > params.MaxSchemaBytes {
		return zero, errOverloaded("schema too large")
	}
	digest := tx.SchemaDigest(schema)
	key := tx.SchemaManifestKey()
	stored, sequence, ok, err := readManifestCursor(backend, key)
	if err != nil {
		return zero, err
	}
	switch {
	case ok && stored == digest:
		// keep sequence
	case ok:
		if sequence == ^uint64(0) {
			return zero, errProtocol("schema sequence exhausted")
		}
		sequence++
	default:
		sequence = 1
	}
	if !ok || stored != digest {
		if err := snapshotTxErr(backend.Commit([]tx.Record{tx.Put(key, encodeManifestCursor(digest, sequence))})); err != nil {
			return zero, err
		}
	}
	return tx.SignedSchema{Database: database, Signer: own, Sequence: sequence, Schema: schema}, nil
}

func encodeManifestCursor(digest [32]byte, sequence uint64) []byte {
	out := append([]byte(nil), digest[:]...)
	return appendVarint(out, sequence)
}

func readManifestCursor(backend tx.Backend, key []byte) ([32]byte, uint64, bool, error) {
	var digest [32]byte
	raw, ok, err := backend.Get(key)
	if err != nil {
		return digest, 0, false, snapshotTxErr(err)
	}
	if !ok {
		return digest, 0, false, nil
	}
	if len(raw) < 32 {
		return digest, 0, false, errProtocol("schema cursor")
	}
	copy(digest[:], raw[:32])
	v, rest, err := readVarint(raw[32:])
	if err != nil || len(rest) != 0 {
		if err == nil {
			err = errProtocol("trailing schema cursor bytes")
		}
		return digest, 0, false, err
	}
	return digest, v, true, nil
}

// VerifySchemaTransport is SignedSchema::verify with transport auth:
// the signer must be the authenticated source.
func VerifySchemaTransport(signed *tx.SignedSchema, database, source NodeID, params *SchemaParams) error {
	if signed.Database != database || signed.Signer != source ||
		signed.Sequence == 0 || len(signed.Schema) > params.MaxSchemaBytes {
		return errAuth("schema envelope identity or size")
	}
	return nil
}

// SchemaDecision is the vet verdict for one manifest.
type SchemaDecision int

const (
	// SchemaCurrent means the manifest matches local bytes.
	SchemaCurrent SchemaDecision = iota
	// SchemaAdopt means an additive delta should apply.
	SchemaAdopt
	// SchemaStale means an older-or-equal sequence.
	SchemaStale
	// SchemaRecord means vetted but neither adopted nor current.
	SchemaRecord
)

// RecordSchemaAccepted stores the highest accepted sequence per signer.
func RecordSchemaAccepted(backend tx.Backend, signed *tx.SignedSchema) error {
	out := appendVarint(nil, signed.Sequence)
	out = appendBytes(out, signed.Schema)
	return snapshotTxErr(backend.Commit([]tx.Record{tx.Put(tx.SchemaAcceptedKey(signed.Signer), out)}))
}

// CheckSchemaManifest vets one manifest. localSchema is the
// manifest-filtered bytes (opt-outs excluded, like the sender's).
func CheckSchemaManifest(backend tx.Backend, params *SchemaParams, own NodeID, localSchema []byte, signed *tx.SignedSchema, source NodeID) (SchemaDecision, error) {
	database, _ := backend.Identity()
	if err := VerifySchemaTransport(signed, database, source, params); err != nil {
		return SchemaRecord, err
	}
	adoptable := false
	if params.SchemaMaster != nil {
		masterSelf := params.Master && *params.SchemaMaster == own
		adoptable = signed.Signer == *params.SchemaMaster && !masterSelf
	} else {
		adoptable = true
	}
	raw, ok, err := backend.Get(tx.SchemaAcceptedKey(signed.Signer))
	if err != nil {
		return SchemaRecord, snapshotTxErr(err)
	}
	var acceptedSeq uint64
	if ok {
		acceptedSeq, _, err = readAccepted(raw)
		if err != nil {
			return SchemaRecord, err
		}
	}
	if signed.Sequence <= acceptedSeq {
		return SchemaStale, nil
	}
	if bytesEqual(signed.Schema, localSchema) {
		if err := RecordSchemaAccepted(backend, signed); err != nil {
			return SchemaRecord, err
		}
		return SchemaCurrent, nil
	}
	if !adoptable || !params.AcceptRemoteSchema {
		if err := RecordSchemaAccepted(backend, signed); err != nil {
			return SchemaRecord, err
		}
		return SchemaRecord, nil
	}
	diff, err := SchemaDiff(localSchema, signed.Schema)
	if err != nil {
		return SchemaRecord, err
	}
	if !diff.Additive {
		if err := RecordSchemaAccepted(backend, signed); err != nil {
			return SchemaRecord, err
		}
		return SchemaRecord, nil
	}
	return SchemaAdopt, nil
}

func readAccepted(b []byte) (uint64, []byte, error) {
	seq, rest, err := readVarint(b)
	if err != nil {
		return 0, nil, err
	}
	schema, rest, err := readBytes(rest)
	if err != nil {
		return 0, nil, err
	}
	if len(rest) != 0 {
		return 0, nil, errProtocol("trailing accepted bytes")
	}
	return seq, schema, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SchemaAdditive is an additive delta: new tables as (table, DDL)
// pairs, new columns as (table, original column definition) pairs.
// Definitions keep their original text for execution (normalization
// is compare-only); all DDL stays untrusted until the applier
// validates each statement.
type SchemaAdditive struct {
	NewTables  [][2]string
	AddColumns [][2]string
}

// SchemaDiffResult is the outcome of SchemaDiff.
type SchemaDiffResult struct {
	Additive     bool
	Delta        SchemaAdditive
	Incompatible string
}

// SchemaDiff diffs canonical pair bytes. Column comparison is
// whitespace-normalized and keyword case-insensitive, so formatting
// drift alone is a no-op. Unparseable DDL fails closed.
func SchemaDiff(local, remote []byte) (SchemaDiffResult, error) {
	localPairs, err := DecodeSchemaPairs(local)
	if err != nil {
		return SchemaDiffResult{}, err
	}
	remotePairs, err := DecodeSchemaPairs(remote)
	if err != nil {
		return SchemaDiffResult{}, err
	}
	localMap := map[string]string{}
	for _, p := range localPairs {
		localMap[p.Table] = p.DDL
	}
	var delta SchemaAdditive
	for _, rp := range remotePairs {
		previous, ok := localMap[rp.Table]
		if !ok {
			delta.NewTables = append(delta.NewTables, [2]string{rp.Table, rp.DDL})
			continue
		}
		if previous == rp.DDL {
			continue
		}
		before, beforeConstraints, ok := ddlColumns(previous)
		if !ok {
			return SchemaDiffResult{Incompatible: "unparseable local DDL: " + rp.Table}, nil
		}
		after, afterConstraints, ok := ddlColumns(rp.DDL)
		if !ok {
			return SchemaDiffResult{Incompatible: "unparseable remote DDL: " + rp.Table}, nil
		}
		if !equalStrings(beforeConstraints, afterConstraints) {
			return SchemaDiffResult{Incompatible: "table constraint change: " + rp.Table}, nil
		}
		for _, bc := range before {
			found := false
			for _, ac := range after {
				if ac.name == bc.name {
					found = true
					if ac.def != bc.def {
						return SchemaDiffResult{Incompatible: "column redefined: " + rp.Table + "." + bc.name}, nil
					}
					break
				}
			}
			if !found {
				return SchemaDiffResult{Incompatible: "column dropped: " + rp.Table + "." + bc.name}, nil
			}
		}
		for _, ac := range after {
			known := false
			for _, bc := range before {
				if bc.name == ac.name {
					known = true
					break
				}
			}
			if !known {
				delta.AddColumns = append(delta.AddColumns, [2]string{rp.Table, ac.original})
			}
		}
	}
	for _, lp := range localPairs {
		kept := false
		for _, rp := range remotePairs {
			if rp.Table == lp.Table {
				kept = true
				break
			}
		}
		if !kept {
			return SchemaDiffResult{Incompatible: "table retired: " + lp.Table}, nil
		}
	}
	return SchemaDiffResult{Additive: true, Delta: delta}, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PullerCompatible is the donor-side one-sided check. The puller may
// carry local-extra tables (drop-never legacy); every donor table
// must exist on the puller with byte-identical DDL.
func PullerCompatible(local, puller []byte) (bool, error) {
	localPairs, err := DecodeSchemaPairs(local)
	if err != nil {
		return false, err
	}
	pullerPairs, err := DecodeSchemaPairs(puller)
	if err != nil {
		return false, err
	}
	pullerMap := map[string]string{}
	for _, p := range pullerPairs {
		pullerMap[p.Table] = p.DDL
	}
	for _, lp := range localPairs {
		if ddl, ok := pullerMap[lp.Table]; !ok || ddl != lp.DDL {
			return false, nil
		}
	}
	return true, nil
}

type ddlColumn struct {
	name     string
	def      string
	original string
}

// ddlColumns splits a CREATE TABLE body into columns plus normalized
// table-level constraints. Constraints cannot be added later, so any
// constraint change is incompatible, not additive.
func ddlColumns(ddl string) ([]ddlColumn, []string, bool) {
	start := strings.IndexByte(ddl, '(')
	if start < 0 {
		return nil, nil, false
	}
	rest := ddl[start+1:]
	end := strings.LastIndexByte(rest, ')')
	if end < 0 {
		return nil, nil, false
	}
	body := rest[:end]
	elements, ok := splitTopLevel(body)
	if !ok {
		return nil, nil, false
	}
	var cols []ddlColumn
	var constraints []string
	for _, element := range elements {
		element = strings.TrimSpace(element)
		// Alphanumeric prefix (UNIQUE(v) has no space after the keyword).
		i := 0
		for i < len(element) && (isWordByte(element[i])) {
			i++
		}
		switch strings.ToUpper(element[:i]) {
		case "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT":
			constraints = append(constraints, normalizeDDL(element))
			continue
		}
		fields := strings.Fields(element)
		if len(fields) == 0 {
			return nil, nil, false
		}
		name := strings.Trim(fields[0], `"`)
		if name == "" || !validIdent(name) {
			return nil, nil, false
		}
		cols = append(cols, ddlColumn{name: strings.ToLower(name), def: normalizeDDL(element), original: element})
	}
	sort.Strings(constraints)
	return cols, constraints, true
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// splitTopLevel splits on top-level commas, respecting nested parens
// and quotes.
func splitTopLevel(body string) ([]string, bool) {
	var parts []string
	depth := 0
	var quote byte
	quoted := false
	var current strings.Builder
	runes := []rune(body)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quoted {
			current.WriteRune(c)
			if byte(c) == quote {
				if i+1 < len(runes) && byte(runes[i+1]) == quote {
					i++
					current.WriteRune(runes[i])
				} else {
					quoted = false
				}
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quoted = true
			quote = byte(c)
			current.WriteRune(c)
		case '(':
			depth++
			current.WriteRune(c)
		case ')':
			depth--
			if depth < 0 {
				return nil, false
			}
			current.WriteRune(c)
		case ',':
			if depth == 0 {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteRune(c)
			}
		default:
			current.WriteRune(c)
		}
	}
	if quoted || depth != 0 {
		return nil, false
	}
	parts = append(parts, current.String())
	return parts, true
}

// normalizeDDL collapses whitespace and uppercases unquoted keywords,
// keeping quoted identifiers and string literals case-sensitive.
func normalizeDDL(element string) string {
	var tokens []string
	var current strings.Builder
	var quote byte
	quoted := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, strings.ToUpper(current.String()))
			current.Reset()
		}
	}
	runes := []rune(element)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quoted {
			current.WriteRune(c)
			if byte(c) == quote {
				if i+1 < len(runes) && byte(runes[i+1]) == quote {
					i++
					current.WriteRune(runes[i])
				} else {
					quoted = false
					tokens = append(tokens, current.String())
					current.Reset()
				}
			}
			continue
		}
		switch {
		case c == '\'' || c == '"' || c == '`':
			flush()
			quoted = true
			quote = byte(c)
			current.WriteRune(c)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			flush()
		default:
			current.WriteRune(c)
		}
	}
	if quoted {
		tokens = append(tokens, current.String())
	} else {
		flush()
	}
	return strings.Join(tokens, " ")
}

// validIdent reports a plain identifier (128 chars max).
func validIdent(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$') {
			return false
		}
	}
	return true
}

// singleStatement holds for at most one statement: no semicolon
// outside quotes except a single trailing one.
func singleStatement(text string) bool {
	var quote byte
	quoted := false
	semis := 0
	trailingOK := true
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quoted {
			if byte(c) == quote {
				if i+1 < len(runes) && byte(runes[i+1]) == quote {
					i++
				} else {
					quoted = false
				}
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quoted = true
			quote = byte(c)
		case ';':
			semis++
			trailingOK = true
			for _, d := range runes[i+1:] {
				if d != ' ' && d != '\t' && d != '\n' && d != '\r' && d != '\v' && d != '\f' {
					trailingOK = false
					break
				}
			}
		}
	}
	return !quoted && (semis == 0 || (semis == 1 && trailingOK))
}

func hasUnquotedSemicolon(text string) bool {
	var quote byte
	quoted := false
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quoted {
			if byte(c) == quote {
				if i+1 < len(runes) && byte(runes[i+1]) == quote {
					i++
				} else {
					quoted = false
				}
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quoted = true
			quote = byte(c)
		case ';':
			return true
		}
	}
	return false
}

// lexShape lexes words and quoted idents for shape checks. Quotes keep
// their marks so callers can distinguish "name" from keywords.
func lexShape(text string) ([]string, bool) {
	var words []string
	var current strings.Builder
	var quote byte
	quoted := false
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quoted {
			current.WriteRune(c)
			if byte(c) == quote {
				if i+1 < len(runes) && byte(runes[i+1]) == quote {
					i++
					current.WriteRune(runes[i])
				} else {
					quoted = false
				}
			}
			continue
		}
		switch {
		case c == '\'' || c == '"' || c == '`':
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			quoted = true
			quote = byte(c)
			current.WriteRune(c)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == '(' || c == ')' || c == ',' || c == '.' || c == ';':
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			if !(c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
				words = append(words, string(c))
			}
		default:
			current.WriteRune(c)
		}
	}
	if quoted {
		return nil, false
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words, true
}

func unquoteIdent(word string) (string, bool) {
	if len(word) >= 2 {
		first, last := word[0], word[len(word)-1]
		if first == last && (first == '"' || first == '`') {
			doubled := string([]byte{first, first})
			return strings.ReplaceAll(word[1:len(word)-1], doubled, string(first)), true
		}
		if first == '[' && last == ']' {
			return word[1 : len(word)-1], true
		}
	}
	if strings.HasPrefix(word, "'") {
		return "", false
	}
	return word, true
}

// CheckCreateTable validates remote CREATE TABLE text before
// execution: single statement, plain main-schema table, name matches.
func CheckCreateTable(table, ddl string) error {
	if !validIdent(table) || !singleStatement(ddl) {
		return errInvalid("rejected schema DDL")
	}
	words, ok := lexShape(ddl)
	if !ok {
		return errInvalid("rejected schema DDL")
	}
	i := 0
	eat := func(keyword string) bool {
		if i < len(words) && strings.EqualFold(words[i], keyword) {
			i++
			return true
		}
		return false
	}
	if !eat("CREATE") || !eat("TABLE") {
		return errInvalid("rejected schema DDL")
	}
	if eat("IF") && (!eat("NOT") || !eat("EXISTS")) {
		return errInvalid("rejected schema DDL")
	}
	if i >= len(words) {
		return errInvalid("rejected schema DDL")
	}
	name, ok := unquoteIdent(words[i])
	if !ok {
		return errInvalid("rejected schema DDL")
	}
	i++
	if i < len(words) && words[i] == "." {
		if !strings.EqualFold(name, "main") {
			return errInvalid("rejected schema DDL")
		}
		if i+1 >= len(words) {
			return errInvalid("rejected schema DDL")
		}
		name, ok = unquoteIdent(words[i+1])
		if !ok {
			return errInvalid("rejected schema DDL")
		}
		i += 2
	}
	if !validIdent(name) || !strings.EqualFold(name, table) {
		return errInvalid("rejected schema DDL")
	}
	if i < len(words) && words[i] == "(" {
		return nil
	}
	return errInvalid("rejected schema DDL")
}

// CheckAddColumn validates a remote column definition before ADD
// COLUMN and returns the column name.
func CheckAddColumn(coldef string) (string, error) {
	if hasUnquotedSemicolon(coldef) || strings.TrimSpace(coldef) == "" {
		return "", errInvalid("rejected schema column")
	}
	elements, ok := splitTopLevel(coldef)
	if !ok || len(elements) != 1 {
		return "", errInvalid("rejected schema column")
	}
	trimmed := strings.TrimSpace(coldef)
	i := 0
	for i < len(trimmed) && isWordByte(trimmed[i]) {
		i++
	}
	switch strings.ToUpper(trimmed[:i]) {
	case "", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT":
		return "", errInvalid("rejected schema column")
	}
	fields := strings.Fields(coldef)
	if len(fields) == 0 {
		return "", errInvalid("rejected schema column")
	}
	name := strings.Trim(fields[0], `"`)
	if !validIdent(name) {
		return "", errInvalid("rejected schema column")
	}
	return name, nil
}

// ApplySchemaAdditive creates adopted tables (CRR-ified) and appends
// adopted columns after validating every statement.
func ApplySchemaAdditive(db *sqlite.Conn, delta *SchemaAdditive) error {
	if err := sqlite.CrsqliteInit(db); err != nil {
		return err
	}
	for _, nt := range delta.NewTables {
		table, ddl := nt[0], nt[1]
		if err := CheckCreateTable(table, ddl); err != nil {
			return err
		}
		st, err := db.Prepare("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1")
		if err != nil {
			return err
		}
		if err := st.BindText(1, table); err != nil {
			st.Close()
			return err
		}
		done, err := st.Step()
		if err != nil {
			st.Close()
			return err
		}
		if !done {
			existing := st.ColumnText(0)
			st.Close()
			if stripTight(existing) != stripTight(ddl) {
				return errProtocol("adopted table diverges")
			}
		} else {
			st.Close()
			if err := db.Exec(ddl); err != nil {
				return err
			}
		}
		clock := table + "__crsql_clock"
		n, err := countWhere(db, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1", clock)
		if err != nil {
			return err
		}
		if n != 1 {
			if err := MakeCRR(db, table); err != nil {
				return err
			}
			n, err = countWhere(db, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1", clock)
			if err != nil {
				return err
			}
			if n != 1 {
				return errProtocol("adopted table is not a CRR")
			}
		}
	}
	for _, ac := range delta.AddColumns {
		table, coldef := ac[0], ac[1]
		if !validIdent(table) {
			return errInvalid("rejected schema table")
		}
		column, err := CheckAddColumn(coldef)
		if err != nil {
			return err
		}
		st, err := db.Prepare(`SELECT type FROM pragma_table_info("` + table + `") WHERE name=?1`)
		if err != nil {
			return err
		}
		if err := st.BindText(1, column); err != nil {
			st.Close()
			return err
		}
		done, err := st.Step()
		if err != nil {
			st.Close()
			return err
		}
		if !done {
			affinity := st.ColumnText(0)
			st.Close()
			declared := ""
			if fields := strings.Fields(coldef); len(fields) > 1 {
				declared = strings.Trim(fields[1], `"`)
			}
			if !strings.EqualFold(affinity, declared) {
				return errProtocol("adopted column diverges")
			}
			continue
		}
		st.Close()
		if err := db.Exec(`ALTER TABLE "` + table + `" ADD COLUMN ` + coldef); err != nil {
			return err
		}
		n, err := countWhereBind(db, `SELECT count(*) FROM pragma_table_info("`+table+`") WHERE name=?1`, column)
		if err != nil {
			return err
		}
		if n != 1 {
			return errProtocol("adopted column missing")
		}
	}
	return nil
}

func stripTight(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasSuffix(s, ";") {
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	}
	return s
}

func countWhere(db *sqlite.Conn, query, arg string) (int64, error) {
	return countWhereBind(db, query, arg)
}

func countWhereBind(db *sqlite.Conn, query, arg string) (int64, error) {
	st, err := db.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if err := st.BindText(1, arg); err != nil {
		return 0, err
	}
	done, err := st.Step()
	if err != nil {
		return 0, err
	}
	if done {
		return 0, errProtocol("count query")
	}
	return st.ColumnInt64(0), nil
}
