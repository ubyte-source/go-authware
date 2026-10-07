package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/ubyte-source/go-authware/v2/internal/jsonobj"
)

const (
	keyDB      = "db"
	valDB      = "p4ss"
	valAlpha   = "alpha"
	valDefault = "default"
)

// A tenant of the resolver test, the shift of the 1 MiB file limit, the key of
// a password and the mode of the files the tests write.
const (
	tenantA     = "a"
	mibShift    = 20
	keyPassword = "db_password"
	privateMode = 0o600
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(body), privateMode); err != nil {
		t.Fatalf("WriteFile = %v, want nil", err)
	}
	return path
}

func mustSecret(t *testing.T, p Provider, key string) string {
	t.Helper()
	v, err := p.Secret(t.Context(), key)
	if err != nil {
		t.Fatalf("Secret(%q) = %v, want a value", key, err)
	}
	return v.Reveal()
}

func TestStatic(t *testing.T) {
	t.Parallel()
	src := map[string]string{keyDB: valDB}
	p := Static(src)
	src[keyDB] = "mutated"
	if got := mustSecret(t, p, keyDB); got != valDB {
		t.Fatalf("Secret(db) = %q, want %q: Static copies its map", got, valDB)
	}
	if _, err := p.Secret(t.Context(), "api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Secret(api) = %v, want ErrNotFound", err)
	}
	if _, err := Static(nil).Secret(t.Context(), keyDB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Static(nil).Secret = %v, want ErrNotFound", err)
	}
	if v, err := Static(map[string]string{keyDB: ""}).Secret(t.Context(), keyDB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty value = %v, %v; want ErrNotFound", v, err)
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("MYAPP_DB_PASSWORD", valDB)
	t.Setenv("RAW_KEY", "raw")
	if got := mustSecret(t, Env("myapp_"), keyPassword); got != valDB {
		t.Fatalf("Env(myapp_).Secret(db_password) = %q, want %q", got, valDB)
	}
	if got := mustSecret(t, Env(""), "raw_key"); got != "raw" {
		t.Fatalf("Env().Secret(raw_key) = %q, want raw", got)
	}
	if _, err := Env("ABSENT_PREFIX_").Secret(t.Context(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Secret(nope) = %v, want ErrNotFound", err)
	}
	t.Setenv("MYAPP_EMPTY", "")
	const want = `secret: not found: env "MYAPP_EMPTY"`
	if v, err := Env("myapp_").Secret(t.Context(), "empty"); !errors.Is(err, ErrNotFound) || err.Error() != want {
		t.Fatalf("empty variable = %v, %v; want ErrNotFound reading %s", v, err, want)
	}
}

func TestFile(t *testing.T) {
	t.Parallel()
	body := " \n{\"db\": \"p4ss\", \"a\\\"b\": \"q\\nx\", \"api\\u005fkey\": \"k\\u00e9y\"," +
		" \" sp \": \" s \", \"empty\": \"\"}\n"
	p, err := File(writeFile(t, body))
	if err != nil {
		t.Fatalf("File = %v, want a provider", err)
	}
	for _, tc := range []struct{ key, want string }{
		{keyDB, valDB}, {`a"b`, "q\nx"}, {"api_key", "kéy"}, {" sp ", " s "},
	} {
		if got := mustSecret(t, p, tc.key); got != tc.want {
			t.Fatalf("Secret(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
	for _, key := range []string{"missing", "empty"} {
		if _, err := p.Secret(t.Context(), key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Secret(%q) err = %v, want ErrNotFound", key, err)
		}
	}
}

// TestDecodeSecretsCopies holds no view of the document: every name and
// value, escaped or not, lives outside it.
func TestDecodeSecretsCopies(t *testing.T) {
	t.Parallel()
	doc := `{"plain":"value-1","esc\u0061ped":"v\u0061lue-2"}`
	p, err := decodeSecrets(doc, ErrInvalidFile)
	if err != nil {
		t.Fatalf("decodeSecrets = %v, want a provider", err)
	}
	start := reflect.ValueOf(doc).Pointer()
	inside := func(s string) bool { return reflect.ValueOf(s).Pointer()-start < uintptr(len(doc)) }
	held, ok := p.(staticProvider)
	if !ok || len(held) != 2 {
		t.Fatalf("decodeSecrets = %T %v, want two secrets", p, p)
	}
	for name, v := range held {
		if inside(name) || inside(v.Reveal()) {
			t.Errorf("secret %q is a view of the document, want a copy", name)
		}
	}
}

func TestFileEmptyObject(t *testing.T) {
	t.Parallel()
	p, err := File(writeFile(t, "{}"))
	if err != nil {
		t.Fatalf("File = %v, want a provider", err)
	}
	if _, err := p.Secret(t.Context(), keyDB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Secret(db) of an empty file = %v, want ErrNotFound", err)
	}
}

func TestFileUnreadable(t *testing.T) {
	t.Parallel()
	absent := filepath.Join(t.TempDir(), "absent.json")
	p, err := File(absent)
	if want := "secret: invalid file: open " + absent + ": no such file or directory"; p != nil ||
		!errors.Is(err, fs.ErrNotExist) || !errors.Is(err, ErrInvalidFile) || err.Error() != want {
		t.Fatalf("File(absent) = %v, %v; want %s", p, err, want)
	}
}

func TestFileCleansPath(t *testing.T) {
	t.Parallel()
	file := writeFile(t, `{"db":"p4ss"}`)
	p, err := File(file + "/")
	if held, ok := p.(staticProvider); err != nil || !ok || len(held) != 1 || held[keyDB].Reveal() != valDB {
		t.Fatalf("File(%q) = %v, %v; want the secrets of the file at filepath.Clean(path)", file+"/", p, err)
	}
	absent := filepath.Dir(file) + "/./absent.json"
	p, err = File(absent)
	if want := "secret: invalid file: open " + filepath.Clean(absent) + ": no such file or directory"; p != nil ||
		!errors.Is(err, fs.ErrNotExist) || !errors.Is(err, ErrInvalidFile) || err.Error() != want {
		t.Fatalf("File(%q) = %v, %v; want %s", absent, p, err, want)
	}
}

// TestFileRefusesSpecialFiles refuses a directory, a device, a named pipe and a
// socket; the open of a pipe without a writer blocks nothing.
func TestFileRefusesSpecialFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fifo, sock := filepath.Join(dir, "secrets.fifo"), filepath.Join(dir, "secrets.sock")
	if err := syscall.Mkfifo(fifo, privateMode); err != nil {
		t.Fatalf("Mkfifo = %v, want nil", err)
	}
	if err := syscall.Mknod(sock, syscall.S_IFSOCK|privateMode, 0); err != nil {
		t.Fatalf("Mknod = %v, want nil", err)
	}
	for _, tc := range []struct {
		path  string
		cause error // the failure of the open, kept beside the refusal; nil when it opens
	}{{dir, nil}, {os.DevNull, nil}, {fifo, nil}, {sock, syscall.ENXIO}} {
		p, err := File(tc.path)
		want := `secret: invalid file "` + tc.path + `": not a regular file`
		if tc.cause != nil {
			want += ": open " + tc.path + ": " + tc.cause.Error()
		}
		if p != nil || !errors.Is(err, ErrInvalidFile) || err.Error() != want ||
			tc.cause != nil && !errors.Is(err, tc.cause) {
			t.Errorf("File(%s) = %v, %v; want %s", tc.path, p, err, want)
		}
	}
}

// notJSONObject is the reason File gives for a document that jsonobj.Iterate refuses.
const notJSONObject = `not one UTF-8 JSON object nested at most 32 deep in which no object repeats a name`

func TestFileInvalid(t *testing.T) {
	t.Parallel()
	for body, reason := range map[string]string{
		`{"db":42}`:           `db is not a string`,
		`{"db":"a","db":"b"}`: notJSONObject,
		`{"db":"a"`:           notJSONObject,
		`["db"]`:              notJSONObject,
	} {
		path := writeFile(t, body)
		_, err := File(path)
		if want := `secret: invalid file "` + path + `": ` + reason; err == nil || err.Error() != want {
			t.Fatalf("File(%q) err = %v, want %s", body, err, want)
		}
		if !errors.Is(err, ErrInvalidFile) {
			t.Fatalf("File(%q) err = %v, want ErrInvalidFile", body, err)
		}
	}
}

var (
	// errInvalid is the error decodeFile wraps in the tests.
	errInvalid = errors.New("test: invalid")
	// errClose is the failure of closing a secrets file.
	errClose = errors.New("test: close failed")
)

// closer is a secrets file that fails its close with err.
type closer struct {
	io.Reader

	err error
}

func (c closer) Close() error { return c.err }

// fileBody opens data as a secrets file.
func fileBody(data string) io.ReadCloser { return closer{Reader: strings.NewReader(data)} }

func TestDecodeFile(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		``,
		`   `,
		`null`,
		`42`,
		`"db"`,
		`["a","b"]`,
		`{"db":"p4ss","api":"k`,
		`{"db":"p4ss","api":`,
		`{"db":"p4ss",`,
		`{"db":"p4ss"`,
		`{"db":"p4ss"} {"evil":"x"}`,
		`{"db":"p4ss"}{"evil":"x"}`,
		`{"db":"p4ss"}}}`,
		`{"db":"p4ss"} trailing`,
		`{"db":"p4ss",}`,
		`{"db":"p4ss" "api":"k"}`,
		`{"db":42}`,
		`{"db":null}`,
		`{"db":{"nested":"x"}}`,
		`{"db":["x"]}`,
		`{"db":"a","db":"b"}`,
		"{\"db\":\"a\",\"d\\u0062\":\"b\"}",
		"{\"d\tb\":\"x\"}",
		"{\"db\":\"a\tb\"}",
		`{"db":"\x"}`,
	} {
		if _, err := decodeFile(fileBody(body), errInvalid); !errors.Is(err, errInvalid) {
			t.Fatalf("decodeFile(%q) err = %v, want errInvalid", body, err)
		}
		if _, err := File(writeFile(t, body)); !errors.Is(err, ErrInvalidFile) {
			t.Fatalf("File(%q) err = %v, want ErrInvalidFile", body, err)
		}
	}
}

func TestDecodeFileLimit(t *testing.T) {
	t.Parallel()
	const head, tail = `{"db":"`, `"}`
	for size, want := range map[int]error{1 << mibShift: nil, 1<<mibShift + 1: errInvalid} {
		p, err := decodeFile(fileBody(head+strings.Repeat("x", size-len(head)-len(tail))+tail), errInvalid)
		if !errors.Is(err, want) || (want == nil) != (p != nil) {
			t.Errorf("file of %d bytes: decodeFile = %v, %v; want %v", size, p, err, want)
		}
	}
}

func TestDecodeFileCloseFailure(t *testing.T) {
	t.Parallel()
	p, err := decodeFile(closer{Reader: strings.NewReader(`{"db":"x"}`), err: errClose}, errInvalid)
	if p != nil || !errors.Is(err, errClose) || !errors.Is(err, errInvalid) {
		t.Fatalf("decodeFile = %v, %v; want errClose behind errInvalid", p, err)
	}
}

// referenceFile decodes data with encoding/json when the strict walker
// accepts it; false when data must be refused.
func referenceFile(data string) (map[string]string, bool) {
	if jsonobj.Iterate(data, errInvalid, func(_, _ string) error { return nil }) != nil {
		return nil, false
	}
	var raws map[string]json.RawMessage
	if json.Unmarshal([]byte(data), &raws) != nil {
		return nil, false
	}
	want := make(map[string]string, len(raws))
	for name, raw := range raws {
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return nil, false
		}
		if v != "" {
			want[name] = v
		}
	}
	return want, true
}

func FuzzDecodeFile(f *testing.F) {
	for _, s := range []string{
		`{"db":"p4ss","api":"k\u00e9y"}`, `{"db":""}`, `{"db":42}`, `{"db":"a","db":"b"}`, `{"\ud800":"x"}`,
		`{"db":"\ud800"}`, `{"db":"\udc00\ud800"}`, `{"db":"\ud83d\ude00"}`, `{"db":"\\ud800"}`,
		`{"db":{"n":"x"}}`, `{}`, `[]`, `{"db":"x"} {}`,
	} {
		f.Add(s)
	}
	f.Fuzz(checkDecodeFile)
}

// checkDecodeFile fails unless decodeFile agrees with the reference on data.
func checkDecodeFile(t *testing.T, data string) {
	got, err := decodeFile(fileBody(data), errInvalid)
	want, accept := referenceFile(data)
	if err != nil {
		if got != nil || !errors.Is(err, errInvalid) || accept {
			t.Fatalf("decodeFile(%q) = %v, %v; want %q", data, got, err, want)
		}
		return
	}
	held, ok := got.(staticProvider)
	revealed := func(v Value, s string) bool { return v.Reveal() == s }
	if !accept || !ok || !maps.EqualFunc(held, want, revealed) {
		t.Fatalf("decodeFile(%q) = %v, want %q (%v)", data, got, want, accept)
	}
}

func TestMapResolver(t *testing.T) {
	t.Parallel()
	src := map[string]Provider{
		tenantA: Static(map[string]string{keyDB: valAlpha}),
		"b":     Static(map[string]string{keyDB: "beta"}),
		"nil":   nil,
	}
	withFallback := MapResolver(src, Static(map[string]string{keyDB: valDefault}))
	strict := MapResolver(src, nil)
	delete(src, tenantA)
	for tenant, want := range map[string]string{tenantA: valAlpha, "b": "beta", "zzz": valDefault, "nil": valDefault} {
		if got := mustSecret(t, withFallback.For(tenant), keyDB); got != want {
			t.Fatalf("For(%q) = %q, want %q", tenant, got, want)
		}
	}
	if got := mustSecret(t, strict.For(tenantA), keyDB); got != valAlpha {
		t.Fatalf("strict For(a) = %q, want %q", got, valAlpha)
	}
	for _, tenant := range []string{"zzz", "nil"} {
		if _, err := strict.For(tenant).Secret(t.Context(), keyDB); !errors.Is(err, ErrNotFound) {
			t.Fatalf("strict For(%q) err = %v, want ErrNotFound", tenant, err)
		}
	}
}

func ExampleStatic() {
	ctx := context.Background()
	p := Static(map[string]string{"db_password": "p4ss"})
	v, err := p.Secret(ctx, "db_password")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(v, v.Reveal())
	// Output: *** p4ss
}

func ExampleMapResolver() {
	ctx, name := context.Background(), keyPassword
	alphaSecrets, defaults := map[string]string{name: valAlpha}, map[string]string{name: "default"}
	r := MapResolver(map[string]Provider{
		"alpha": Static(alphaSecrets),
		"beta":  Env("BETA_"),
	}, Static(defaults))
	tenantID := "alpha"
	v, err := r.For(tenantID).Secret(ctx, name)
	if err != nil {
		fmt.Println(err)
		return
	}
	other, err := r.For("unknown").Secret(ctx, name)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(v.Reveal(), other.Reveal())
	// Output: alpha default
}

// ExampleEnv reads the key db_password from EXAMPLE_DB_PASSWORD at each call.
func ExampleEnv() {
	const name = "EXAMPLE_DB_PASSWORD"
	if err := os.Setenv(name, "p4ss"); err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		if err := os.Unsetenv(name); err != nil {
			fmt.Println(err)
		}
	}()
	p := Env("example_")
	v, err := p.Secret(context.Background(), keyPassword)
	fmt.Println(v, v.Reveal(), err)
	_, err = p.Secret(context.Background(), "api_key")
	fmt.Println(err)
	// Output:
	// *** p4ss <nil>
	// secret: not found: env "EXAMPLE_API_KEY"
}

// ExampleFile reads a secrets file once; an empty member counts as absent.
func ExampleFile() {
	dir, err := os.MkdirTemp("", "secret-example")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			fmt.Println(rmErr)
		}
	}()
	path := filepath.Join(dir, "secrets.json")
	if err = os.WriteFile(path, []byte(`{"db_password":"p4ss","api_key":""}`), privateMode); err != nil {
		fmt.Println(err)
		return
	}
	p, err := File(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	v, err := p.Secret(context.Background(), keyPassword)
	fmt.Println(v.Reveal(), err)
	_, err = p.Secret(context.Background(), "api_key")
	fmt.Println(errors.Is(err, ErrNotFound))
	_, err = File(filepath.Join(dir, "absent.json"))
	fmt.Println(errors.Is(err, ErrInvalidFile), errors.Is(err, fs.ErrNotExist))
	// Output: p4ss <nil>
	// true
	// true true
}
