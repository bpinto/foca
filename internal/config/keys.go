package config

import (
	"encoding"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
)

// miscasedKeys returns the keys in md that name a field of raw's type in
// other than its exact spelling. The decoder matches field names
// case-insensitively and doesn't count a key it matched that way as
// undecoded, so [Plugins] or Approval = would otherwise be taken, and a
// table repeated in another case could override the first.
func miscasedKeys(md toml.MetaData, raw any) []string {
	var out []string
	for _, k := range md.Keys() {
		if !exactKey(reflect.TypeOf(raw), k) {
			out = append(out, k.String())
		}
	}
	return out
}

// exactKey reports whether every struct field on key's path is spelled
// exactly as its toml tag. Map keys (instance, vault, secret and action
// names, env variables) are the user's own, and the decoder keeps them as
// written.
func exactKey(t reflect.Type, key toml.Key) bool {
	for _, part := range key {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		// A type that decodes itself takes whatever is below it.
		if p := reflect.PointerTo(t); p.Implements(reflect.TypeFor[toml.Unmarshaler]()) ||
			p.Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) {
			return true
		}
		switch t.Kind() {
		case reflect.Map:
			t = t.Elem()
		case reflect.Struct:
			f, ok := fieldByTag(t, part)
			if !ok {
				return false
			}
			t = f.Type
		default:
			return true
		}
	}
	return true
}

func fieldByTag(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if tag, _, _ := strings.Cut(f.Tag.Get("toml"), ","); tag == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}
