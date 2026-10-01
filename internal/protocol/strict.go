package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// CheckStrict rejects JSON that would only decode into a value of type t
// because encoding/json is lenient. That decoder matches keys without regard
// to case and keeps the last of duplicate keys, so two parsers could read the
// same bytes differently: a relay that looks for "guest_verified" would miss
// "Guest_Verified", which the host would accept. Here every object key must
// equal a field's JSON name exactly and appear once; keys of objects with no
// known shape (json.RawMessage, maps) must also be unique.
func CheckStrict(data []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := checkValue(dec, t, ""); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data")
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

func checkValue(dec *json.Decoder, t reflect.Type, path string) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	if t == rawMessageType {
		t = nil // any shape, but still no duplicate keys
	}
	switch d {
	case '{':
		var fields map[string]reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			fields = jsonFields(t)
		}
		var elem reflect.Type
		if t != nil && t.Kind() == reflect.Map {
			elem = t.Elem()
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key := kt.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q%s", key, at(path))
			}
			seen[key] = true
			ft := elem
			if fields != nil {
				f, ok := fields[key]
				if !ok {
					return fmt.Errorf("unknown key %q%s (keys are case-sensitive)", key, at(path))
				}
				ft = f
			}
			if err := checkValue(dec, ft, path+"."+key); err != nil {
				return err
			}
		}
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.More() {
			if err := checkValue(dec, elem, path+"[]"); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

func at(path string) string {
	if path == "" {
		return ""
	}
	return " in " + strings.TrimPrefix(path, ".")
}

// jsonFields maps each JSON name of a struct, including promoted fields of
// embedded structs, to its type.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range jsonFields(ft) {
					out[k] = v
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}
