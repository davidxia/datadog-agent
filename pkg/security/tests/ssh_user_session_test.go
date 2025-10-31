// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && functionaltests

// Package tests holds tests related files
package tests

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/avast/retry-go/v4"
	"github.com/oliveagle/jsonpath"
	"github.com/stretchr/testify/assert"
)

// checkSSHUserSessionJSON check if all the fields in the JSON are valid for a SSH Session
func checkSSHUserSessionJSON(testMod *testModule, t testing.TB, data []byte) {
	jsonPathValidation(testMod, data, func(_ *testModule, jsonData interface{}) {

		// Check all the fields
		if el, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.id`); err != nil || el == nil {
			t.Errorf("user_session.id not found: %v", err)
		} else if id, ok := el.(string); !ok || id == "" || id == "0" {
			t.Errorf("user_session.id is empty or invalid: %v", el)
		}

		if el, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.session_type`); err != nil || el == nil {
			t.Errorf("user_session.session_type not found: %v", err)
		} else if sessionType, ok := el.(string); !ok || sessionType != "ssh" {
			t.Errorf("user_session.session_type is not 'ssh': %v", el)
		}

		if el, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.ssh_port`); err != nil || el == nil {
			t.Errorf("user_session.ssh_port not found: %v", err)
		} else if port, ok := el.(float64); !ok || port <= 0 {
			t.Errorf("user_session.ssh_port is invalid: %v", el)
		}

		if el, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.ssh_client_ip`); err != nil || el == nil {
			t.Errorf("user_session.ssh_client_ip not found: %v", err)
		} else if ip, ok := el.(string); !ok || ip == "" {
			t.Errorf("user_session.ssh_client_ip is empty: %v", el)
		} else if ip != "127.0.0.1" && ip != "::1" {
			t.Errorf("user_session.ssh_client_ip should be localhost (127.0.0.1 or ::1): %v", ip)
		}

		if el, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.ssh_auth_method`); err != nil || el == nil {
			t.Errorf("user_session.ssh_auth_method not found: %v", err)
		} else if authMethod, ok := el.(string); !ok || authMethod == "" {
			t.Errorf("user_session.ssh_auth_method is empty: %v", el)
		} else if authMethod != "public_key" && authMethod != "password" {
			t.Errorf("user_session.ssh_auth_method has unexpected value: %v", authMethod)
		}

		if authMethod, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.ssh_auth_method`); err == nil {
			if authMethodStr, ok := authMethod.(string); ok && authMethodStr == "public_key" {
				if el, err := jsonpath.JsonPathLookup(jsonData, `$.process.user_session.ssh_public_key`); err != nil || el == nil {
					t.Errorf("user_session.ssh_public_key not found for publickey auth: %v", err)
				} else if pubKey, ok := el.(string); !ok || pubKey == "" {
					t.Errorf("user_session.ssh_public_key is empty for publickey auth: %v", el)
				}
			}
		}
	})
}

func ensureLocalhostSSHAuth() error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	home := u.HomeDir
	sshDir := filepath.Join(home, ".ssh")
	keyPath := filepath.Join(sshDir, "ci_localhost_ed25519")
	pubPath := keyPath + ".pub"
	authz := filepath.Join(sshDir, "authorized_keys")

	// 1) ~/.ssh with good rights
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", sshDir, err)
	}

	// 2) Generate a key if missing (readable format for OpenSSH)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-q")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ssh-keygen: %v (out: %s)", err, string(out))
		}
		_ = os.Chmod(keyPath, 0o600)
		_ = os.Chmod(pubPath, 0o644)
	}
	// 3) Add pubkey if missing
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read pub: %w", err)
	}
	// Ensure pub ends with newline
	pubTrimmed := bytes.TrimSpace(pub)

	if _, err := os.Stat(authz); os.IsNotExist(err) {
		// Create new authorized_keys with the key and a trailing newline
		if err := os.WriteFile(authz, append(pubTrimmed, '\n'), 0o600); err != nil {
			return fmt.Errorf("write authorized_keys: %w", err)
		}
	} else {
		existing, err := os.ReadFile(authz)
		if err != nil {
			return fmt.Errorf("read authorized_keys: %w", err)
		}
		// Check if key already exists
		if !bytes.Contains(existing, pubTrimmed) {
			// Instead of appending, rewrite the whole file to ensure proper formatting
			lines := bytes.Split(existing, []byte("\n"))
			var validLines [][]byte

			// Keep only non-empty lines
			for _, line := range lines {
				if len(bytes.TrimSpace(line)) > 0 {
					validLines = append(validLines, bytes.TrimSpace(line))
				}
			}

			// Add our key
			validLines = append(validLines, pubTrimmed)

			// Write all lines with proper formatting
			var content bytes.Buffer
			for _, line := range validLines {
				content.Write(line)
				content.WriteByte('\n')
			}

			if err := os.WriteFile(authz, content.Bytes(), 0o600); err != nil {
				return fmt.Errorf("write authorized_keys: %w", err)
			}
		}
	}
	// Strict rights needs for ssh
	if err := os.Chmod(authz, 0o600); err != nil {
		return fmt.Errorf("chmod authorized_keys: %w", err)
	}

	return nil
}

func sshLocalhostWithGeneratedKey(remoteCmd string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(u.HomeDir, ".ssh", "ci_localhost_ed25519")

	// Force key authentification
	args := []string{
		"-i", keyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PasswordAuthentication=no",
		"-o", "PubkeyAuthentication=yes",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		u.Username + "@localhost",
		remoteCmd,
	}

	cmd := exec.Command("ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func rotateAuthLog(logPath string) error {
	st, err := os.Stat(logPath)
	if err != nil {
		return fmt.Errorf("stat before rotate: %w", err)
	}
	mode := st.Mode().Perm()

	uid, gid := 0, 0
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		uid = int(sys.Uid)
		gid = int(sys.Gid)
	}

	if err := os.Rename(logPath, logPath+".1"); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create new log: %w", err)
	}
	_ = f.Close()

	if err := os.Chown(logPath, uid, gid); err != nil {
		return fmt.Errorf("chown new log: %w", err)
	}
	if err := os.Chmod(logPath, mode); err != nil {
		return fmt.Errorf("chmod new log: %w", err)
	}

	if _, err := exec.LookPath("restorecon"); err == nil {
		_ = exec.Command("restorecon", "-v", logPath).Run()
	}

	if err := exec.Command("systemctl", "reload", "rsyslog").Run(); err != nil {
		_ = exec.Command("bash", "-c", "pidof rsyslogd >/dev/null 2>&1 && kill -HUP $(pidof rsyslogd)").Run()
	}

	return nil
}

// backupAuthorizedKeys creates a backup of the authorized_keys file
// Returns the backup path and any error
func backupAuthorizedKeys() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	authzPath := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	backupPath := authzPath + ".test_backup"

	// Check if authorized_keys exists
	stat, err := os.Stat(authzPath)
	if os.IsNotExist(err) {
		// File doesn't exist, nothing to backup
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat authorized_keys: %w", err)
	}

	// Read original file
	content, err := os.ReadFile(authzPath)
	if err != nil {
		return "", fmt.Errorf("read authorized_keys: %w", err)
	}

	// Save permissions
	mode := stat.Mode().Perm()

	// Write backup with same permissions
	if err := os.WriteFile(backupPath, content, mode); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}

	// Copy ownership if possible
	if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(backupPath, int(sys.Uid), int(sys.Gid))
	}

	return backupPath, nil
}

// restoreAuthorizedKeys restores the authorized_keys file from backup
func restoreAuthorizedKeys(backupPath string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}

	authzPath := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")

	if backupPath == "" {
		// No backup was made, remove the file if it was created by the test
		return nil
	}

	// Check if backup exists
	stat, err := os.Stat(backupPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat backup: %w", err)
	}

	// Read backup
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}

	mode := stat.Mode().Perm()

	// Restore the original file
	if err := os.WriteFile(authzPath, content, mode); err != nil {
		return fmt.Errorf("restore authorized_keys: %w", err)
	}

	// Restore ownership if possible
	if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(authzPath, int(sys.Uid), int(sys.Gid))
	}

	// Remove backup file
	_ = os.Remove(backupPath)

	return nil
}

// cleanupSSHTestFiles removes SSH test artifacts created during tests
func cleanupSSHTestFiles() error {
	u, err := user.Current()
	if err != nil {
		return err
	}

	keyPath := filepath.Join(u.HomeDir, ".ssh", "ci_localhost_ed25519")
	pubPath := keyPath + ".pub"

	// Remove generated SSH keys
	_ = os.Remove(keyPath)
	_ = os.Remove(pubPath)

	return nil
}

// restoreRotatedLog restores the rotated log file to its original location
func restoreRotatedLog(logPath string) error {
	rotatedPath := logPath + ".1"

	// Check if rotated file exists
	if _, err := os.Stat(rotatedPath); os.IsNotExist(err) {
		return nil // Nothing to restore
	}

	// Remove the new empty log
	_ = os.Remove(logPath)

	// Rename .1 back to original
	if err := os.Rename(rotatedPath, logPath); err != nil {
		return fmt.Errorf("restore log: %w", err)
	}

	// Reload rsyslog
	if err := exec.Command("systemctl", "reload", "rsyslog").Run(); err != nil {
		_ = exec.Command("bash", "-c", "pidof rsyslogd >/dev/null 2>&1 && kill -HUP $(pidof rsyslogd)").Run()
	}

	return nil
}

func getLogFile() (bool, string, uint64) {
	possibleLogPaths := []string{
		"/var/log/auth.log", // Debian/Ubuntu
		"/var/log/secure",   // RHEL/CentOS/Fedora
		"/var/log/messages", // openSUSE/autres
	}

	var logPath string
	var inodeBeforeRotate uint64

	for _, path := range possibleLogPaths {
		stat, err := os.Stat(path)
		if err == nil {
			logPath = path
			// Get inode
			if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
				inodeBeforeRotate = sysStat.Ino
				return true, logPath, inodeBeforeRotate
			}
		}
	}
	return false, "", 0
}
func TestSSHUserSession(t *testing.T) {
	SkipIfNotAvailable(t)
	if testEnvironment == DockerEnvironment {
		t.Skip("Skip test spawning docker containers on docker")
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "test_rule_ssh_user_session",
			Expression: `process.user_session.id != 0 && process.user_session.session_type == ssh && exec.user == "` + currentUser.Username + `"`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs)
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	// Backup authorized_keys before modifying it
	backupPath, err := backupAuthorizedKeys()
	if err != nil {
		t.Fatalf("failed to backup authorized_keys: %v", err)
	}

	// Cleanup SSH test artifacts after test completion
	t.Cleanup(func() {
		_ = restoreAuthorizedKeys(backupPath)
		_ = cleanupSSHTestFiles()
	})

	t.Run("ssh_then_pwd", func(t *testing.T) {
		err := test.GetEventSent(t, func() error {
			if err := ensureLocalhostSSHAuth(); err != nil {
				fmt.Fprintf(os.Stderr, "setup ssh failed: %v\n", err)
				return err
			}
			if err := sshLocalhostWithGeneratedKey("pwd"); err != nil {
				fmt.Fprintf(os.Stderr, "ssh failed: %v\n", err)
				return err
			}
			return nil
		}, func(rule *rules.Rule, event *model.Event) bool {
			return true
		}, time.Second*3, "test_rule_ssh_user_session")

		if err != nil {
			t.Fatal(err)
		}
		err = retry.Do(func() error {
			msg := test.msgSender.getMsg("test_rule_ssh_user_session")
			if msg == nil {
				return errors.New("not found")
			}
			validateMessageSchema(t, string(msg.Data))

			// Check all the fields
			checkSSHUserSessionJSON(test, t, msg.Data)

			return nil
		}, retry.Delay(200*time.Millisecond), retry.Attempts(30), retry.DelayType(retry.FixedDelay))
		assert.NoError(t, err)

	})
}

func TestSSHUserSessionRotated(t *testing.T) {
	SkipIfNotAvailable(t)
	if testEnvironment == DockerEnvironment {
		t.Skip("Skip test spawning docker containers on docker")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}

	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "test_rule_ssh_user_session",
			Expression: `exec.user_session.id != 0 && exec.user_session.session_type == ssh && exec.user == "` + currentUser.Username + `"`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs)
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	// Backup authorized_keys before modifying it
	backupPath, err := backupAuthorizedKeys()
	if err != nil {
		t.Fatalf("failed to backup authorized_keys: %v", err)
	}

	if err := ensureLocalhostSSHAuth(); err != nil {
		fmt.Fprintf(os.Stderr, "setup ssh failed: %v\n", err)
		t.Fatal(err)
	}

	isLogFileExist, logPath, inodeBeforeRotate := getLogFile()
	// We skip test when we don't have a log file because we can't rotate it
	if !isLogFileExist {
		t.Skip("Skip test if log file does not exist")
	}

	// Cleanup: restore log and remove SSH artifacts after test completion
	t.Cleanup(func() {
		_ = restoreRotatedLog(logPath)
		_ = restoreAuthorizedKeys(backupPath)
		_ = cleanupSSHTestFiles()
	})

	if err := rotateAuthLog(logPath); err != nil {
		t.Fatalf("rotateAuthLog failed: %v", err)
	}

	stat, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat log file after rotation: %v", err)
	}

	var inodeAfterRotate uint64
	if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
		inodeAfterRotate = sysStat.Ino
	}

	// Check that the inode has changed
	assert.NotEqual(t, inodeBeforeRotate, inodeAfterRotate, "inode of %s should be different after rotate", logPath)

	t.Run("ssh_then_pwd_after_rotation", func(t *testing.T) {
		err := test.GetEventSent(t, func() error {
			if err := sshLocalhostWithGeneratedKey("pwd"); err != nil {
				fmt.Fprintf(os.Stderr, "ssh failed: %v\n", err)
				return err
			}
			return nil
		}, func(rule *rules.Rule, event *model.Event) bool {
			return true
		}, time.Second*3, "test_rule_ssh_user_session")

		if err != nil {
			t.Fatal(err)
		}
		err = retry.Do(func() error {
			msg := test.msgSender.getMsg("test_rule_ssh_user_session")
			if msg == nil {
				return errors.New("not found")
			}
			validateMessageSchema(t, string(msg.Data))

			// Check all the fields
			checkSSHUserSessionJSON(test, t, msg.Data)

			return nil
		}, retry.Delay(200*time.Millisecond), retry.Attempts(30), retry.DelayType(retry.FixedDelay))
		assert.NoError(t, err)

	})
}
