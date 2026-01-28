package xmlrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type decoder struct {
	*xml.Decoder
}

func Unmarshal(body []byte, v interface{}) error {
	var resp struct {
		Fault *struct{} `xml:"fault,omitempty"`
	}
	if err := xml.Unmarshal(body, &resp); err != nil {
		return errors.Wrap(err, "unmarshal xml")
	}
	if resp.Fault != nil {
		var faultErr struct {
			Code   int    `xmlrpc:"faultCode"`
			String string `xmlrpc:"faultString"`
		}
		if err := unmarshal(body, &faultErr); err != nil {
			return errors.Wrap(err, "unmarshal")
		}
		return errors.Errorf("xmlrpc return error response. %d: %s", faultErr.Code, faultErr.String)
	}

	if err := unmarshal(body, v); err != nil {
		return errors.Wrap(err, "unmarshal")
	}

	return nil
}

func unmarshal(body []byte, v interface{}) error {
	d := decoder{xml.NewDecoder(bytes.NewReader(body))}
	for {
		t, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.Wrap(err, "return next XML token")
		}
		switch tv := t.(type) {
		case xml.StartElement:
			if tv.Name.Local == "value" {
				valueOf := reflect.ValueOf(v)
				if valueOf.Kind() != reflect.Pointer {
					return errors.New("non-pointer passed to Unmarshal")
				}
				if valueOf.IsNil() {
					return errors.New("nil pointer passed to Unmarshal")
				}
				if err := d.decodeValue(valueOf.Elem()); err != nil {
					return errors.Wrap(err, "decode value")
				}
			}
		default:
		}
	}

	return nil
}

func (d *decoder) decodeValue(value reflect.Value) error {
	var elementType string
LOOP:
	for {
		t, err := d.Token()
		if err != nil {
			return errors.Wrap(err, "return next XML token")
		}

		switch tv := t.(type) {
		case xml.StartElement:
			elementType = tv.Name.Local
			break LOOP
		case xml.EndElement:
			if tv.Name.Local == "value" {
				return nil
			}
			return errors.New("invalid xml")
		case xml.CharData:
			if v := strings.TrimSpace(string(tv)); v != "" {
				if err := checkType(value, reflect.String); err != nil {
					return errors.Wrap(err, "check type")
				}
				value.SetString(v)
				return nil
			}
		default:
		}
	}

	switch elementType {
	case "struct":
		value = indirect(value)

		ismap := false
		pmap := value
		valType := value.Type()

		var fields map[string]reflect.Value
		switch {
		case checkType(value, reflect.Struct) == nil:
			fields = make(map[string]reflect.Value)
			for i := 0; i < valType.NumField(); i++ {
				field := valType.Field(i)
				fieldVal := value.FieldByName(field.Name)

				if fieldVal.CanSet() {
					name := field.Tag.Get("xmlrpc")
					name = strings.TrimSuffix(name, ",omitempty")
					if name == "-" {
						continue
					}
					if name == "" {
						name = field.Name
					}
					fields[name] = fieldVal
				}
			}
		case checkType(value, reflect.Map) == nil:
			if valType.Key().Kind() != reflect.String {
				return errors.New("only maps with string key type can be unmarshalled")
			}
			pmap.Set(reflect.MakeMap(valType))
			ismap = true
		case checkType(value, reflect.Interface) == nil && value.IsNil():
			var dummy map[string]interface{}
			valType = reflect.TypeOf(dummy)
			pmap = reflect.New(valType).Elem()
			value.Set(pmap)
			pmap.Set(reflect.MakeMap(valType))
			ismap = true
		default:
			return errors.Errorf("no match in %v", []reflect.Kind{reflect.Struct, reflect.Map, reflect.Interface})
		}

	Struct:
		for {
			t, err := d.Token()
			if err != nil {
				return errors.Wrap(err, "return next XML token")
			}

			switch tv := t.(type) {
			case xml.StartElement:
				if tv.Name.Local != "member" {
					return errors.New("invalid xml")
				}

				fieldName, err := func() (string, error) {
				FieldName:
					for {
						t, err := d.Token()
						if err != nil {
							return "", errors.Wrap(err, "return next XML token")
						}

						switch tv := t.(type) {
						case xml.StartElement:
							if tv.Name.Local != "name" {
								return "", errors.New("invalid xml")
							}
							break FieldName
						default:
						}
					}

					t, err := d.Token()
					if err != nil {
						return "", errors.Wrap(err, "return next XML token")
					}
					switch tv := t.(type) {
					case xml.CharData:
						name := string(tv.Copy())
						if err := d.Skip(); err != nil {
							return "", errors.Wrap(err, "skip token until </name>")
						}
						return name, nil
					default:
						return "", errors.New("invalid xml")
					}
				}()
				if err != nil {
					return errors.Wrap(err, "find field name")
				}

				fv, ok := fields[fieldName]
				if ismap {
					fv = reflect.New(valType.Elem())
					ok = true
				}

				if ok {
				FieldData:
					for {
						t, err := d.Token()
						if err != nil {
							return errors.Wrap(err, "return next XML token")
						}

						switch tv := t.(type) {
						case xml.StartElement:
							if tv.Name.Local != "value" {
								break
							}

							if err := d.decodeValue(fv); err != nil {
								return errors.Wrap(err, "decode value")
							}

							if err := d.Skip(); err != nil {
								return errors.Wrap(err, "skip token until </value>")
							}

							break FieldData
						default:
						}
					}
				}

				if err := d.Skip(); err != nil {
					return errors.Wrap(err, "skip token until </member>")
				}

				if ismap {
					pmap.SetMapIndex(reflect.ValueOf(string(fieldName)), reflect.Indirect(fv))
					value.Set(pmap)
				}
			case xml.EndElement:
				break Struct
			}
		}
	case "array":
		value = indirect(value)

		slice := value
		if checkType(value, reflect.Interface) == nil && value.IsNil() {
			slice = reflect.ValueOf([]interface{}{})
		}
		if err := checkType(slice, reflect.Slice); err != nil {
			return errors.Wrap(err, "check type")
		}

	Array:
		for {
			t, err := d.Token()
			if err != nil {
				return errors.Wrap(err, "return next XML token")
			}

			switch tv := t.(type) {
			case xml.StartElement:
				var index int
				if tv.Name.Local != "data" {
					return errors.New("invalid xml")
				}

			ArrayData:
				for {
					t, err := d.Token()
					if err != nil {
						return errors.Wrap(err, "return next XML token")
					}

					switch tv := t.(type) {
					case xml.StartElement:
						if tv.Name.Local != "value" {
							return errors.New("invalid xml")
						}

						if index < slice.Len() {
							v := slice.Index(index)
							if v.Kind() == reflect.Interface {
								v = v.Elem()
							}
							if v.Kind() != reflect.Ptr {
								return errors.New("cannot write to non-pointer array element")
							}
							if err := d.decodeValue(v); err != nil {
								return errors.Wrap(err, "decode value")
							}
						} else {
							v := reflect.New(slice.Type().Elem())
							if err := d.decodeValue(v); err != nil {
								return errors.Wrap(err, "decode value")
							}
							slice = reflect.Append(slice, v.Elem())
						}

						if err := d.Skip(); err != nil {
							return errors.Wrap(err, "skip token until </value>")
						}
						index++
					case xml.EndElement:
						value.Set(slice)
						break ArrayData
					}
				}
			case xml.EndElement:
				break Array
			}
		}
	default:
		t, err := d.Token()
		if err != nil {
			return errors.Wrap(err, "return next XML token")
		}

		switch tv := t.(type) {
		case xml.EndElement:
			return nil
		case xml.CharData:
			value = indirect(value)

			data := []byte(tv.Copy())
			switch elementType {
			case "boolean":
				switch {
				case checkType(value, reflect.Interface) == nil && value.IsNil():
					v, err := strconv.ParseBool(string(data))
					if err != nil {
						return errors.Wrap(err, "parse bool")
					}
					pv := reflect.New(reflect.TypeOf(v)).Elem()
					pv.SetBool(v)
					value.Set(pv)
				case checkType(value, reflect.Bool) == nil:
					v, err := strconv.ParseBool(string(data))
					if err != nil {
						return errors.Wrap(err, "parse bool")
					}
					value.SetBool(v)
				default:
					return errors.Errorf("no match in %v", []reflect.Kind{reflect.Bool, reflect.Interface})
				}
			case "int", "i4":
				switch {
				case checkType(value, reflect.Interface) == nil && value.IsNil():
					v, err := strconv.ParseInt(string(data), 10, 64)
					if err != nil {
						return errors.Wrap(err, "parse int")
					}
					pv := reflect.New(reflect.TypeOf(v)).Elem()
					pv.SetInt(v)
					value.Set(pv)
				case checkType(value, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64) == nil:
					v, err := strconv.ParseInt(string(data), 10, value.Type().Bits())
					if err != nil {
						return errors.Wrap(err, "parse int")
					}
					value.SetInt(v)
				default:
					return errors.Errorf("no match in %v", []reflect.Kind{reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Interface})
				}
			case "double":
				switch {
				case checkType(value, reflect.Interface) == nil && value.IsNil():
					v, err := strconv.ParseFloat(string(data), 64)
					if err != nil {
						return errors.Wrap(err, "parse float")
					}
					pv := reflect.New(reflect.TypeOf(v)).Elem()
					pv.SetFloat(v)
					value.Set(pv)
				case checkType(value, reflect.Float32, reflect.Float64) == nil:
					v, err := strconv.ParseFloat(string(data), value.Type().Bits())
					if err != nil {
						return errors.Wrap(err, "parse float")
					}
					value.SetFloat(v)
				default:
					return errors.Errorf("no match in %v", []reflect.Kind{reflect.Float32, reflect.Float64, reflect.Interface})
				}
			case "string":
				switch {
				case checkType(value, reflect.Interface) == nil && value.IsNil():
					v := string(data)
					pv := reflect.New(reflect.TypeOf(v)).Elem()
					pv.SetString(v)
					value.Set(pv)
				case checkType(value, reflect.String) == nil:
					v := string(data)
					value.SetString(v)
				default:
					return errors.Errorf("no match in %v", []reflect.Kind{reflect.String, reflect.Interface})
				}
			case "base64":
				switch {
				case checkType(value, reflect.Interface) == nil && value.IsNil():
					v, err := base64.StdEncoding.DecodeString(string(data))
					if err != nil {
						return errors.Wrap(err, "decode base64")
					}
					pv := reflect.New(reflect.TypeOf(v)).Elem()
					pv.SetBytes(v)
					value.Set(pv)
				case checkType(value, reflect.Array) == nil:
					switch {
					case checkType(reflect.New(value.Type().Elem()), reflect.Uint8) == nil:
						v, err := base64.StdEncoding.DecodeString(string(data))
						if err != nil {
							return errors.Wrap(err, "decode base64")
						}
						for i := 0; i < value.Len(); i++ {
							value.Index(i).SetUint(uint64(v[i]))
						}
					case checkType(reflect.New(value.Type().Elem()), reflect.Interface) == nil:
						v, err := base64.StdEncoding.DecodeString(string(data))
						if err != nil {
							return errors.Wrap(err, "decode base64")
						}
						for i := 0; i < value.Len(); i++ {
							pv := reflect.New(reflect.TypeOf(v[i])).Elem()
							pv.SetUint(uint64(v[i]))
							value.Index(i).Set(pv)
						}
					default:
						return errors.Errorf("no match in %v", []reflect.Kind{reflect.Uint8, reflect.Interface})
					}
				case checkType(value, reflect.Slice) == nil:
					switch {
					case checkType(reflect.New(value.Type().Elem()), reflect.Uint8) == nil:
						v, err := base64.StdEncoding.DecodeString(string(data))
						if err != nil {
							return errors.Wrap(err, "decode base64")
						}
						value.SetBytes(v)
					case checkType(reflect.New(value.Type().Elem()), reflect.Interface) == nil:
						v, err := base64.StdEncoding.DecodeString(string(data))
						if err != nil {
							return errors.Wrap(err, "decode base64")
						}
						for _, e := range v {
							pv := reflect.New(reflect.TypeOf(e)).Elem()
							pv.SetUint(uint64(e))
							value.Set(reflect.Append(value, pv))
						}
					default:
						return errors.Errorf("no match in %v", []reflect.Kind{reflect.Uint8, reflect.Interface})
					}
				default:
					return errors.Errorf("no match in %v", []reflect.Kind{reflect.Array, reflect.Slice})

				}
			case "dateTime.iso8601":
				parse := func(value string) (*time.Time, error) {
					tls := []string{"20060102T15:04:05", "20060102T15:04:05Z07:00", "2006-01-02T15:04:05", "2006-01-02T15:04:05Z07:00"}
					for _, tl := range tls {
						v, err := time.Parse(tl, value)
						if err == nil {
							return &v, nil
						}
					}
					return nil, errors.Errorf("cannot parse %s in %q", string(data), tls)
				}

				switch {
				case checkType(value, reflect.Interface) == nil && value.IsNil():
					v, err := parse(string(data))
					if err != nil {
						return errors.Wrap(err, "parse time")
					}
					pv := reflect.New(reflect.TypeOf(*v)).Elem()
					pv.Set(reflect.ValueOf(v))
					value.Set(pv)
				default:
					if _, ok := value.Interface().(time.Time); !ok {
						return errors.Errorf("no match for %v in time.Time", value.Kind())
					}
					v, err := parse(string(data))
					if err != nil {
						return errors.Wrap(err, "parse time")
					}
					value.Set(reflect.ValueOf(*v))
				}
			default:
				return errors.Errorf("unsupported type: %s", elementType)
			}

			if err := d.Skip(); err != nil {
				return errors.Wrap(err, "skip token until </boolean>, </int>, </i4>, </double>, </string>, </base64>, </dateTime.iso8601>")
			}
		default:
			return errors.New("invalid xml")
		}
	}

	return nil
}

func checkType(val reflect.Value, kinds ...reflect.Kind) error {
	if len(kinds) == 0 {
		return nil
	}

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	match := false

	for _, kind := range kinds {
		if val.Kind() == kind {
			match = true
			break
		}
	}

	if !match {
		return errors.Errorf("no match for %v in %v", val.Kind(), kinds)
	}

	return nil
}

// indirect walks down v allocating pointers as needed,
// until it gets to a non-pointer.
//
// Adapted from encoding/json indirect() function
// https://golang.org/src/encoding/json/decode.go?#L480
func indirect(v reflect.Value) reflect.Value {
	// After the first round-trip, we set v back to the original value to
	// preserve the original RW flags contained in reflect.Value.
	v0 := v
	haveAddr := false

	// If v is a named type and is addressable,
	// start with its address, so that if the type has pointer methods,
	// we find them.
	if v.Kind() != reflect.Pointer && v.Type().Name() != "" && v.CanAddr() {
		haveAddr = true
		v = v.Addr()
	}
	for {
		// Load value from interface, but only if the result will be
		// usefully addressable.
		if v.Kind() == reflect.Interface && !v.IsNil() {
			e := v.Elem()
			if e.Kind() == reflect.Pointer && !e.IsNil() {
				haveAddr = false
				v = e
				continue
			}
		}

		if v.Kind() != reflect.Pointer {
			break
		}

		// Prevent infinite loop if v is an interface pointing to its own address:
		//     var v interface{}
		//     v = &v
		if v.Elem().Kind() == reflect.Interface && v.Elem().Elem() == v {
			v = v.Elem()
			break
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}

		if haveAddr {
			v = v0 // restore original value after round-trip Value.Addr().Elem()
			haveAddr = false
		} else {
			v = v.Elem()
		}
	}

	return v
}
