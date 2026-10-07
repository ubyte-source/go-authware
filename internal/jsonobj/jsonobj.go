package jsonobj

import (
	"fmt"
	"strings"

	"github.com/ubyte-source/go-jsonfast"
)

// maxDepth bounds the nesting of arrays and objects, the top object included.
const maxDepth = 32

// Iterate calls fn with the decoded name and raw value of each member of data, one
// UTF-8 JSON object nested at most maxDepth deep in which no object repeats a name;
// fn's first error returns as is, and other input returns invalid, maybe after fn ran.
func Iterate(data string, invalid error, fn func(name, value string) error) error {
	var stop error
	err := jsonfast.IterateDocument(data, maxDepth, func(name, value string) error {
		stop = fn(name, value)
		return stop
	})
	switch {
	case stop != nil:
		return stop
	case err != nil:
		return invalid
	}
	return nil
}

// Refusal wraps invalid with the shape that a document Iterate refuses lacks.
func Refusal(invalid error) error {
	return fmt.Errorf("%w: not one UTF-8 JSON object nested at most %d deep in which no object repeats a name",
		invalid, maxDepth)
}

// CopyString decodes into dst a copy of value, which Iterate handed over for the member
// name: null leaves dst as it is, and any other value but a JSON string wraps invalid.
func CopyString(dst *string, name, value string, invalid error) error {
	if jsonfast.KindOf(value) == jsonfast.KindNull {
		return nil
	}
	s, err := String(name, value, invalid)
	if err != nil {
		return err
	}
	*dst = strings.Clone(s)
	return nil
}

// String decodes value, which Iterate handed over for the member name and which must be
// a JSON string; any other value wraps invalid.
func String(name, value string, invalid error) (string, error) {
	s, ok := jsonfast.DecodeString(value)
	if !ok {
		return "", NotString(invalid, name)
	}
	return s, nil
}

// NotString wraps invalid for the member name, whose value is no JSON string.
func NotString(invalid error, name string) error {
	return fmt.Errorf("%w: %s is not a string", invalid, name)
}
