package xmlrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func Marshal(method string, args ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := fmt.Fprintf(buf, "<?xml version='1.0' encoding='UTF-8'?>"); err != nil {
		return nil, errors.Wrap(err, "write string to buffer")
	}
	if _, err := fmt.Fprintf(buf, "<methodCall><methodName>%s</methodName>", method); err != nil {
		return nil, errors.Wrap(err, "write string to buffer")
	}

	params, err := marshalArgs(args...)
	if err != nil {
		return nil, errors.Wrapf(err, "marshal args: %v", args)
	}
	if _, err := fmt.Fprintf(buf, "%s", params); err != nil {
		return nil, errors.Wrap(err, "write string to buffer")
	}

	if _, err := fmt.Fprintf(buf, "</methodCall>"); err != nil {
		return nil, errors.Wrap(err, "write string to buffer")
	}

	return buf.Bytes(), nil
}

func marshalArgs(args ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := fmt.Fprintf(buf, "<params>"); err != nil {
		return nil, errors.Wrap(err, "write string to buffer")
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(buf, "<param>"); err != nil {
			return nil, errors.Wrap(err, "write string to buffer")
		}

		value, err := marshalValue(arg)
		if err != nil {
			return nil, errors.Wrapf(err, "marshal value: %v", arg)
		}
		if _, err := fmt.Fprintf(buf, "%s", value); err != nil {
			return nil, errors.Wrap(err, "write bytes to buffer")
		}

		if _, err := fmt.Fprintf(buf, "</param>"); err != nil {
			return nil, errors.Wrap(err, "write string to buffer")
		}
	}

	if _, err := fmt.Fprintf(buf, "</params>"); err != nil {
		return nil, errors.Wrap(err, "write string to buffer")
	}

	return buf.Bytes(), nil
}

func marshalValue(value interface{}) ([]byte, error) {
	data, err := marshalData(value)
	if err != nil {
		return nil, errors.Wrapf(err, "marshal data: %v", value)
	}
	return []byte(fmt.Sprintf("<value>%s</value>", string(data))), nil
}

func marshalData(value interface{}) ([]byte, error) {
	valueOf := reflect.ValueOf(value)
	kind := valueOf.Kind()

	switch kind {
	case reflect.Bool:
		v := 0
		if value.(bool) {
			v = 1
		}
		return []byte(fmt.Sprintf("<boolean>%d</boolean>", v)), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return []byte(fmt.Sprintf("<int>%d</int>", value.(int))), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []byte(fmt.Sprintf("<i4>%d</i4>", value.(uint64))), nil
	case reflect.Float32, reflect.Float64:
		return []byte(fmt.Sprintf("<double>%f</double>", value.(float64))), nil
	case reflect.String:
		buf := new(bytes.Buffer)
		if err := xml.EscapeText(buf, []byte(value.(string))); err != nil {
			return nil, errors.Wrapf(err, "escape text: %s", value.(string))
		}
		return []byte(fmt.Sprintf("<string>%s</string>", buf.String())), nil
	case reflect.Array, reflect.Slice:
		switch value := value.(type) {
		case []byte:
			return []byte(fmt.Sprintf("<base64>%s</base64>", base64.StdEncoding.EncodeToString(value))), nil
		default:
			buf := new(bytes.Buffer)
			if _, err := fmt.Fprintf(buf, "<array><data>"); err != nil {
				return nil, errors.Wrap(err, "write string to buffer")
			}
			for i := 0; i < valueOf.Len(); i++ {
				bs, err := marshalValue(valueOf.Index(i).Interface())
				if err != nil {
					return nil, errors.Wrapf(err, "marshal value: %v", valueOf.Index(i).Interface())
				}
				if _, err := fmt.Fprintf(buf, "%s", bs); err != nil {
					return nil, errors.Wrap(err, "write bytes to buffer")
				}
			}
			if _, err := fmt.Fprintf(buf, "</data></array>"); err != nil {
				return nil, errors.Wrap(err, "write string to buffer")
			}
			return buf.Bytes(), nil
		}
	case reflect.Struct:
		switch value := value.(type) {
		case time.Time:
			return []byte(fmt.Sprintf("<dateTime.iso8601>%s</dateTime.iso8601>", value.Format(time.RFC3339))), nil
		default:
			buf := new(bytes.Buffer)
			if _, err := fmt.Fprintf(buf, "<struct>"); err != nil {
				return nil, errors.Wrap(err, "write string to buffer")
			}

		LOOP:
			for i := 0; i < reflect.TypeOf(value).NumField(); i++ {
				field := reflect.ValueOf(value).Field(i)
				if !field.CanInterface() {
					continue
				}

				fieldType := reflect.TypeOf(value).Field(i)
				name := fieldType.Name
				switch tag := fieldType.Tag.Get("xmlrpc"); tag {
				case "":
				case "-":
					continue LOOP
				default:
					if strings.HasSuffix(tag, ",omitempty") && field.IsZero() {
						continue LOOP
					}
					name = strings.TrimSuffix(tag, ",omitempty")
				}

				bs, err := marshalValue(field.Interface())
				if err != nil {
					return nil, errors.Wrapf(err, "marshal value: %v", field.Interface())
				}

				if _, err := fmt.Fprintf(buf, "<member><name>%s</name>%s</member>", name, bs); err != nil {
					return nil, errors.Wrap(err, "write string to buffer")
				}
			}
			if _, err := fmt.Fprintf(buf, "</struct>"); err != nil {
				return nil, errors.Wrap(err, "write string to buffer")
			}
			return buf.Bytes(), nil
		}
	case reflect.Interface, reflect.Pointer:
		if valueOf.IsNil() {
			return []byte("<nil/>"), nil
		}
		return marshalData(valueOf.Elem().Interface())
	default:
		if value == nil {
			return []byte("<nil/>"), nil
		}
		return nil, errors.Errorf("unsupported data type %v", kind)
	}
}
