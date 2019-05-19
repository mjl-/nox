package main

import (
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
