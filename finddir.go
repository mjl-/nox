package nox

import (
	"os"
	"path"
)

func findNearestFile(name string) (*os.File, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	for lastDir := ""; dir != lastDir; lastDir, dir = dir, path.Dir(dir) {
		filename := dir + "/" + name
		f, err := os.Open(filename)
		if err != nil && os.IsNotExist(err) {
			continue
		}
		return f, err
	}
	return nil, os.ErrNotExist
}

// NearestNoxDir locates the nearest directory named ".nox", starting at the
// current directory, walking up to the root. If no directory was found,
// ErrNoNoxDir is returned.
func NearestNoxDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for lastDir := ""; dir != lastDir; lastDir, dir = dir, path.Dir(dir) {
		filename := dir + "/.nox"
		info, err := os.Stat(filename)
		if err != nil && os.IsNotExist(err) {
			continue
		}
		if err == nil && !info.Mode().IsDir() {
			return filename, prefixError(ErrNoNoxDir, "%s not a directory", filename)
		}
		return filename, err
	}
	return "", ErrNoNoxDir
}
