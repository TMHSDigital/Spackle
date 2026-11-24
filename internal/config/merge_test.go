package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// fillLeaves sets every field a config file can set (every exported field
// whose toml tag is not "-") to a value no default has, so that merge has
// something to copy for each of them.
func fillLeaves(t *testing.T, v reflect.Value, path string, n *int) {
	t.Helper()
	*n++
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() || f.Tag.Get("toml") == "-" {
				continue
			}
			fillLeaves(t, v.Field(i), path+"."+f.Name, n)
		}
	case reflect.String:
		v.SetString(fmt.Sprintf("file-value-%d", *n))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(int64(1000 + *n))
	case reflect.Float64:
		v.SetFloat(float64(*n) + 0.5)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fillLeaves(t, p.Elem(), path, n)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillLeaves(t, s.Index(0), path+"[0]", n)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fillLeaves(t, key, path+"{key}", n)
		val := reflect.New(v.Type().Elem()).Elem()
		fillLeaves(t, val, path+"{value}", n)
		m.SetMapIndex(key, val)
		v.Set(m)
	default:
		t.Fatalf("%s: fillLeaves does not handle %s; extend it", path, v.Kind())
	}
}

// checkLeaves reports every field of want that did not reach got. A map in
// got may hold more entries (defaults that the file does not replace).
func checkLeaves(t *testing.T, got, want reflect.Value, path string) {
	t.Helper()
	switch want.Kind() {
	case reflect.Struct:
		for i := 0; i < want.NumField(); i++ {
			f := want.Type().Field(i)
			if !f.IsExported() || f.Tag.Get("toml") == "-" {
				continue
			}
			checkLeaves(t, got.Field(i), want.Field(i), path+"."+f.Name)
		}
	case reflect.Map:
		for _, k := range want.MapKeys() {
			g := got.MapIndex(k)
			if !g.IsValid() || !reflect.DeepEqual(g.Interface(), want.MapIndex(k).Interface()) {
				t.Errorf("%s[%v] from the file was not merged", path, k)
			}
		}
	default:
		if !reflect.DeepEqual(got.Interface(), want.Interface()) {
			t.Errorf("%s from the file was not merged: got %v, want %v", path, got.Interface(), want.Interface())
		}
	}
}

// Every setting a config file can hold must be copied by merge. A field
// added to Config without a merge line would be accepted and ignored.
func TestMergeCopiesEveryFileField(t *testing.T) {
	var file Config
	n := 0
	fillLeaves(t, reflect.ValueOf(&file).Elem(), "Config", &n)
	cfg := Default()
	cfg.merge(file)
	checkLeaves(t, reflect.ValueOf(cfg), reflect.ValueOf(file), "Config")
}

// The keys that no other test loads from a file.
func TestLoadReadsCapsAndOutputKeys(t *testing.T) {
	p := writeConfig(t, `
[budget]
sandbox_runs = 7
max_findings = 9
max_turns = 11

[sandbox]
cpus = 1.5
pids = 64

[output]
formats = ["json", "sarif"]
dir = "out"
`)
	cfg, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Budget
	if b.SandboxRuns != 7 || b.MaxFindings != 9 || b.MaxTurns != 11 {
		t.Errorf("budget = %+v", b)
	}
	if cfg.Sandbox.CPUs != 1.5 || cfg.Sandbox.PIDs != 64 {
		t.Errorf("sandbox cpus=%v pids=%v", cfg.Sandbox.CPUs, cfg.Sandbox.PIDs)
	}
	if strings.Join(cfg.Output.Formats, ",") != "json,sarif" || cfg.Output.Dir != "out" {
		t.Errorf("output = %+v", cfg.Output)
	}
}
