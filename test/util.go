/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package test

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
)

func RegisterVendor(t *testing.T, name string, crypto crypto.Client, registry registry.RegistryClient) {
	cert, err := crypto.SelfSignVendorCACertificate(name)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.RegisterVendor(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = crypto.TrustStore().AddCertificate(cert); err != nil {
		t.Fatal(err)
	}
}

func CopyDir(src string, dst string) error {
	dir, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, os.ModePerm); err != nil {
		return err
	}
	for _, entry := range dir {
		sourceFile := filepath.Join(src, entry.Name())
		targetFile := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			err := CopyDir(sourceFile, targetFile)
			if err != nil {
				return err
			}
			continue
		}
		if err := CopyFile(sourceFile, targetFile); err != nil {
			return err
		}
	}
	return nil
}

func CopyFile(src string, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)

	return err
}
