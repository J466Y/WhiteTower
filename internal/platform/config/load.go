package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// EnvPrefix starts the name of every environment variable that overrides a
// setting: listeners.console.address is WT_LISTENERS_CONSOLE_ADDRESS.
const EnvPrefix = "WT_"

// Load returns the configuration: the defaults, then the YAML file at path
// (none when path is empty), then the WT_ variables of environ, which take
// precedence. It fails on an unknown key, a malformed value or an invalid
// setting, naming it.
func Load(path string, environ []string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // G304: the operator chooses the configuration file
		if err != nil {
			return cfg, fmt.Errorf("reading the configuration: %w", err)
		}
		if err := decodeYAML(data, &cfg); err != nil {
			return cfg, fmt.Errorf("configuration file %s: %w", path, err)
		}
	}
	if err := applyEnv(&cfg, environ); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid configuration:\n%w", err)
	}
	return cfg, nil
}

// decodeYAML decodes a YAML document onto cfg, refusing unknown keys, so
// that a misspelled setting fails instead of being ignored.
func decodeYAML(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// applyEnv overrides settings with the WT_ variables of environ.
func applyEnv(cfg *Config, environ []string) error {
	env := map[string]string{}
	for _, kv := range environ {
		if name, value, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(name, EnvPrefix) {
			env[name] = value
		}
	}
	var errs []error
	for _, f := range settings(reflect.ValueOf(cfg).Elem(), nil) {
		value, ok := env[f.Env]
		if !ok {
			continue
		}
		if err := setFromString(f.Value, value); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Env, err))
		}
	}
	return errors.Join(errs...)
}

// setting is one leaf of the configuration.
type setting struct {
	// Keys from the root, as in the YAML file.
	Path []string
	// The environment variable that overrides it.
	Env string
	// The value; settable when reached through a pointer.
	Value reflect.Value
	// The field, and the struct type that declares it.
	Field  reflect.StructField
	Parent reflect.Type
}

// Key returns the setting's dotted key, for example listeners.console.address.
func (s setting) Key() string { return strings.Join(s.Path, ".") }

var durationType = reflect.TypeFor[time.Duration]()

// settings lists the leaves of a configuration struct, in declaration order.
func settings(v reflect.Value, path []string) []setting {
	var out []setting
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		key := strings.Split(f.Tag.Get("yaml"), ",")[0]
		p := append(append([]string(nil), path...), key)
		if f.Type.Kind() == reflect.Struct {
			out = append(out, settings(v.Field(i), p)...)
			continue
		}
		out = append(out, setting{
			Path:   p,
			Env:    EnvPrefix + strings.ToUpper(strings.Join(p, "_")),
			Value:  v.Field(i),
			Field:  f,
			Parent: t,
		})
	}
	return out
}

// setFromString parses an environment variable's text into a setting.
func setFromString(v reflect.Value, s string) error {
	if v.Type() == durationType {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("%q: want a duration such as 8s", s)
		}
		v.SetInt(int64(d))
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return fmt.Errorf("%q: want true or false", s)
		}
		v.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q: want an integer", s)
		}
		v.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("%q: want a number", s)
		}
		v.SetFloat(f)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.String {
			if s == "" {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
				return nil
			}
			parts := strings.Split(s, ",")
			slice := reflect.MakeSlice(v.Type(), len(parts), len(parts))
			for i, p := range parts {
				slice.Index(i).SetString(strings.TrimSpace(p))
			}
			v.Set(slice)
			return nil
		}
		return fmt.Errorf("settings of type %s cannot be set from the environment", v.Type())
	case reflect.Map:
		if v.Type().Key().Kind() == reflect.String && v.Type().Elem().Kind() == reflect.String {
			m := reflect.MakeMap(v.Type())
			if s != "" {
				for _, pair := range strings.Split(s, ",") {
					k, val, ok := strings.Cut(pair, "=")
					if !ok {
						k, val, ok = strings.Cut(pair, ":")
					}
					if ok {
						m.SetMapIndex(reflect.ValueOf(strings.TrimSpace(k)), reflect.ValueOf(strings.TrimSpace(val)))
					} else if trimmed := strings.TrimSpace(pair); trimmed != "" {
						m.SetMapIndex(reflect.ValueOf(trimmed), reflect.ValueOf(trimmed))
					}
				}
			}
			v.Set(m)
			return nil
		}
		return fmt.Errorf("settings of type %s cannot be set from the environment", v.Type())
	default:
		return fmt.Errorf("settings of type %s cannot be set from the environment", v.Type())
	}
	return nil
}

// YAML returns the configuration as a YAML document, with durations written
// as text (8s). The configuration holds no secret, only the paths of the
// files that hold them, so the document is safe to show.
func (c Config) YAML() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(node(reflect.ValueOf(c))); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// node converts a configuration value to a YAML node.
func node(v reflect.Value) *yaml.Node {
	if v.Kind() == reflect.Struct && v.Type() != durationType {
		n := &yaml.Node{Kind: yaml.MappingNode}
		for i := range v.NumField() {
			key := strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0]
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, node(v.Field(i)))
		}
		return n
	}
	if v.Kind() == reflect.Slice {
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for i := range v.Len() {
			n.Content = append(n.Content, node(v.Index(i)))
		}
		return n
	}
	if v.Kind() == reflect.Map {
		n := &yaml.Node{Kind: yaml.MappingNode}
		keys := v.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
		for _, k := range keys {
			n.Content = append(n.Content, node(k), node(v.MapIndex(k)))
		}
		return n
	}
	scalar := &yaml.Node{Kind: yaml.ScalarNode}
	switch {
	case v.Type() == durationType:
		scalar.Tag, scalar.Value = "!!str", time.Duration(v.Int()).String()
	case v.Kind() == reflect.Bool:
		scalar.Tag, scalar.Value = "!!bool", strconv.FormatBool(v.Bool())
	case v.Kind() == reflect.Int || v.Kind() == reflect.Int64:
		scalar.Tag, scalar.Value = "!!int", strconv.FormatInt(v.Int(), 10)
	case v.Kind() == reflect.Float64:
		// Untagged, so that 1 prints as 1 rather than !!float 1.
		scalar.Value = strconv.FormatFloat(v.Float(), 'g', -1, 64)
	default:
		scalar.Tag, scalar.Value = "!!str", v.String()
	}
	return scalar
}
