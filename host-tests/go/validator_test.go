// Package hosttests runs the API's commit validator, the duvet-e2e-validator module, as the API
// runs it: under wazero, on the vectors the validator's Rust test writes to testdata/
// (cargo test -p duvet-e2e-validator write_vectors -- --ignored).
package hosttests

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// modulePath is the module cargo builds with
// `cargo build --release --target wasm32-wasip1 -p duvet-e2e-validator`, or the one
// DUVET_VALIDATOR_WASM names when the build's target directory isn't the workspace's.
func modulePath() string {
	if path := os.Getenv("DUVET_VALIDATOR_WASM"); path != "" {
		return path
	}
	return filepath.Join("..", "..", "target", "wasm32-wasip1", "release", "duvet_e2e_validator.wasm")
}

// vector is a request, and the answer the validator gave it natively.
type vector struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Epoch uint64 `json:"epoch"`
	Code  string `json:"code"`
	input []byte
}

func readVectors(t *testing.T) []vector {
	t.Helper()
	const write = "cargo test -p duvet-e2e-validator write_vectors -- --ignored"
	manifest, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("the vectors (%s writes them): %v", write, err)
	}
	var vectors struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(manifest, &vectors); err != nil {
		t.Fatalf("testdata/vectors.json: %v", err)
	}
	if len(vectors.Vectors) == 0 {
		t.Fatalf("testdata/vectors.json lists no vector (%s writes them)", write)
	}
	for i := range vectors.Vectors {
		name := vectors.Vectors[i].Name + ".cbor"
		if vectors.Vectors[i].input, err = os.ReadFile(filepath.Join("testdata", name)); err != nil {
			t.Fatalf("testdata/%s: %v", name, err)
		}
	}
	return vectors.Vectors
}

func named(t *testing.T, vectors []vector, name string) vector {
	t.Helper()
	for _, v := range vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no %q vector", name)
	return vector{}
}

// validator is one instance of the module.
type validator struct {
	module                   api.Module
	alloc, dealloc, validate api.Function
}

func instantiate(t *testing.T, ctx context.Context, runtime wazero.Runtime, compiled wazero.CompiledModule, config wazero.ModuleConfig) *validator {
	t.Helper()
	// Anonymous, so the runtime holds as many instances as the test makes; and no start
	// function, as the module is a library.
	module, err := runtime.InstantiateModule(ctx, compiled, config.WithName("").WithStartFunctions())
	if err != nil {
		t.Fatalf("instantiating the module: %v", err)
	}
	t.Cleanup(func() {
		if err := module.Close(ctx); err != nil {
			t.Errorf("closing the module: %v", err)
		}
	})
	v := &validator{
		module:   module,
		alloc:    module.ExportedFunction("alloc"),
		dealloc:  module.ExportedFunction("dealloc"),
		validate: module.ExportedFunction("validate"),
	}
	if v.alloc == nil || v.dealloc == nil || v.validate == nil {
		t.Fatal("the module doesn't export alloc, dealloc and validate")
	}
	return v
}

// answer is what the validator answered: whether it took the request, the epoch after it, and
// the code of a refusal.
type answer struct {
	ok    bool
	epoch uint64
	code  string
}

// run hands the module a request as the API does: into a buffer `alloc` gives, freeing that
// buffer and the response's with `dealloc` once the response is read.
func (v *validator) run(ctx context.Context, request []byte) (answer, error) {
	results, err := v.alloc.Call(ctx, uint64(len(request)))
	if err != nil {
		return answer{}, fmt.Errorf("alloc: %w", err)
	}
	in := uint32(results[0])
	if in == 0 {
		return answer{}, errors.New("alloc found no room")
	}
	if !v.module.Memory().Write(in, request) {
		return answer{}, errors.New("the request is outside the module's memory")
	}
	results, err = v.validate.Call(ctx, uint64(in), uint64(len(request)))
	if err != nil {
		return answer{}, fmt.Errorf("validate: %w", err)
	}
	if _, err := v.dealloc.Call(ctx, uint64(in), uint64(len(request))); err != nil {
		return answer{}, fmt.Errorf("dealloc: %w", err)
	}
	return v.read(ctx, results[0])
}

// read reads the response `validate` answered with, at (ptr << 32) | len, and frees it.
func (v *validator) read(ctx context.Context, result uint64) (answer, error) {
	out, outLen := uint32(result>>32), uint32(result)
	view, ok := v.module.Memory().Read(out, outLen)
	if !ok {
		return answer{}, errors.New("the response is outside the module's memory")
	}
	// A view of the module's memory, which the next call may reuse.
	response := append([]byte(nil), view...)
	if _, err := v.dealloc.Call(ctx, uint64(out), uint64(outLen)); err != nil {
		return answer{}, fmt.Errorf("dealloc: %w", err)
	}

	value, rest, err := decodeCBOR(response)
	if err != nil {
		return answer{}, fmt.Errorf("the response: %w", err)
	}
	if len(rest) != 0 {
		return answer{}, errors.New("the response has bytes after its value")
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return answer{}, fmt.Errorf("the response isn't a map: %v", value)
	}
	var got answer
	if got.ok, ok = fields["ok"].(bool); !ok {
		return answer{}, fmt.Errorf("the response has no ok: %v", fields)
	}
	if got.ok {
		if got.epoch, ok = fields["epoch"].(uint64); !ok {
			return answer{}, fmt.Errorf("a success without an epoch: %v", fields)
		}
		if _, ok := fields["state"].([]byte); !ok {
			return answer{}, fmt.Errorf("a success without a state: %v", fields)
		}
		return got, nil
	}
	refusal, _ := fields["error"].(map[string]any)
	if got.code, ok = refusal["code"].(string); !ok {
		return answer{}, fmt.Errorf("a refusal without a code: %v", fields)
	}
	return got, nil
}

func (v *validator) answer(t *testing.T, ctx context.Context, request vector) answer {
	t.Helper()
	got, err := v.run(ctx, request.input)
	if err != nil {
		t.Fatalf("%s: %v", request.Name, err)
	}
	return got
}

func TestValidatorUnderWazero(t *testing.T) {
	ctx := t.Context()
	wasm, err := os.ReadFile(modulePath())
	if err != nil {
		t.Fatalf("the validator module (build it with cargo build --release --target wasm32-wasip1 -p duvet-e2e-validator, or name it in DUVET_VALIDATOR_WASM): %v", err)
	}
	vectors := readVectors(t)

	runtime := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("closing the runtime: %v", err)
		}
	})
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compiling the module: %v", err)
	}

	// How the API runs the module: with randomness, and with the real clock, by which OpenMLS
	// holds leaves to their lifetimes. wazero's defaults are fixed bytes and a clock from 2022.
	apis := wazero.NewModuleConfig().WithRandSource(rand.Reader).WithSysWalltime().WithSysNanotime()

	t.Run("every vector gets its native answer", func(t *testing.T) {
		v := instantiate(t, ctx, runtime, compiled, apis)
		for _, request := range vectors {
			want := answer{ok: request.OK, epoch: request.Epoch, code: request.Code}
			if got := v.answer(t, ctx, request); got != want {
				t.Errorf("%s: got %+v, want %+v", request.Name, got, want)
			}
		}
	})

	t.Run("a request at address 0, or past the cap, is a refusal", func(t *testing.T) {
		v := instantiate(t, ctx, runtime, compiled, apis)
		// The validator's MAX_REQUEST (crates/duvet-e2e-validator/src/lib.rs): alloc makes no room
		// past it, and validate refuses it unread.
		const maxRequest = 8 << 20
		if results, err := v.alloc.Call(ctx, maxRequest+1); err != nil || results[0] != 0 {
			t.Errorf("alloc past the cap: %v, %v", results, err)
		}
		for _, call := range []struct {
			name     string
			ptr, len uint64
			code     string
		}{
			{"a request at address 0", 0, 16, "bad_request"},
			{"a request past the cap", 1, maxRequest + 1, "too_large"},
		} {
			results, err := v.validate.Call(ctx, call.ptr, call.len)
			if err != nil {
				t.Errorf("%s: %v", call.name, err)
				continue
			}
			got, err := v.read(ctx, results[0])
			if err != nil || got != (answer{code: call.code}) {
				t.Errorf("%s: got %+v, %v, want %s", call.name, got, err, call.code)
			}
		}
	})

	t.Run("epoch 0 needs the real clock", func(t *testing.T) {
		// On wazero's clock, still at 2022, epoch 0's leaves aren't valid yet: a host that leaves
		// the clock out can't take any group's start.
		v := instantiate(t, ctx, runtime, compiled, wazero.NewModuleConfig().WithRandSource(rand.Reader))
		got := v.answer(t, ctx, named(t, vectors, "create"))
		if want := (answer{code: "invalid_group_info"}); got != want {
			t.Errorf("create without the real clock: got %+v, want %+v", got, want)
		}
	})

	t.Run("a hundred days on, a later epoch still validates", func(t *testing.T) {
		later := func() (int64, int32) {
			now := time.Now().Add(100 * 24 * time.Hour)
			return now.Unix(), int32(now.Nanosecond())
		}
		resolution := sys.ClockResolution(time.Microsecond.Nanoseconds())
		v := instantiate(t, ctx, runtime, compiled, apis.WithWalltime(later, resolution))
		// The leaves that never renewed are past their key packages' 84 days: a group built from
		// scratch, as epoch 0 is, refuses them...
		create := v.answer(t, ctx, named(t, vectors, "create"))
		if want := (answer{code: "invalid_group_info"}); create != want {
			t.Errorf("create: got %+v, want %+v", create, want)
		}
		// ...and one loaded from its state, as every later epoch is, takes the next commit.
		renew := named(t, vectors, "renew")
		if got, want := v.answer(t, ctx, renew), (answer{ok: true, epoch: renew.Epoch}); got != want {
			t.Errorf("renew: got %+v, want %+v", got, want)
		}
	})
}

// decodeCBOR reads one CBOR value of the kinds the validator writes: unsigned integers, byte and
// text strings, arrays, maps with text keys, booleans and null, all of definite length. It
// returns the value and the bytes after it.
func decodeCBOR(data []byte) (any, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("cbor: no value")
	}
	major, info := data[0]>>5, data[0]&0x1f
	data = data[1:]
	if major == 7 {
		switch info {
		case 20:
			return false, data, nil
		case 21:
			return true, data, nil
		case 22:
			return nil, data, nil
		}
		return nil, nil, fmt.Errorf("cbor: simple value %d", info)
	}
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info <= 27:
		size := 1 << (info - 24)
		if len(data) < size {
			return nil, nil, errors.New("cbor: a length past the end")
		}
		for _, b := range data[:size] {
			n = n<<8 | uint64(b)
		}
		data = data[size:]
	default:
		return nil, nil, fmt.Errorf("cbor: additional information %d", info)
	}
	switch major {
	case 0:
		return n, data, nil
	case 2, 3:
		if uint64(len(data)) < n {
			return nil, nil, errors.New("cbor: a string past the end")
		}
		if major == 2 {
			return append([]byte(nil), data[:n]...), data[n:], nil
		}
		return string(data[:n]), data[n:], nil
	case 4:
		var items []any
		for range n {
			item, rest, err := decodeCBOR(data)
			if err != nil {
				return nil, nil, err
			}
			items, data = append(items, item), rest
		}
		return items, data, nil
	case 5:
		fields := make(map[string]any)
		for range n {
			key, rest, err := decodeCBOR(data)
			if err != nil {
				return nil, nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, nil, fmt.Errorf("cbor: a map key that isn't text: %v", key)
			}
			value, rest, err := decodeCBOR(rest)
			if err != nil {
				return nil, nil, err
			}
			fields[name], data = value, rest
		}
		return fields, data, nil
	}
	return nil, nil, fmt.Errorf("cbor: major type %d", major)
}
