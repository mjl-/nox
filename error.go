package nox

import (
	"fmt"

	"golang.org/x/xerrors"
)

func errorHandler(fn func(error)) (func(error, string), func()) {
	type localError struct {
		err error
	}

	check := func(err error, msg string) {
		if err != nil {
			err = xerrors.Errorf("%s: %w", msg, err)
			panic(&localError{err})
		}
	}
	handle := func() {
		e := recover()
		if e == nil {
			return
		}
		if le, ok := e.(*localError); ok {
			fn(le.err)
		} else {
			panic(e)
		}
	}
	return check, handle
}

// Remove when xerrors supports "%w" in arbitrary location in the formatting
// string. At the time of writing, it only allows it at the end.
type prefixErr struct {
	err    error
	errmsg string
}

func prefixError(err error, format string, args ...interface{}) *prefixErr {
	return &prefixErr{err, err.Error() + ": " + fmt.Sprintf(format, args...)}
}

func (e *prefixErr) Error() string {
	return e.errmsg
}

func (e *prefixErr) Unwrap() error {
	return e.err
}

// wrapErr implements "Is" for the first error, and unwraps into the second error.
type wrapErr struct {
	err  error
	next error
}

func (e *wrapErr) Error() string {
	return e.err.Error()
}

func (e *wrapErr) Is(err error) bool {
	return xerrors.Is(e.err, err)
}

func (e *wrapErr) Unwrap() error {
	return e.next
}
