// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux

package tracermetadata

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

func loadTracerMetadata(t *testing.T, filename string) {
	t.Helper()
	curDir, err := testutil.CurDir()
	require.NoError(t, err)
	testDataPath := filepath.Join(curDir, filename)
	data, err := os.ReadFile(testDataPath)
	require.NoError(t, err)
	createTracerMemfd(t, data)
}

func TestGetTracerMetadata(t *testing.T) {
	pid := os.Getpid()
	procfs := kernel.ProcFSRoot()

	t.Run("cpp", func(t *testing.T) {
		loadTracerMetadata(t, "testdata/tracer_cpp.data")
		trm, err := GetTracerMetadata(pid, procfs)
		require.NoError(t, err)
		require.Equal(t, "my-service", trm.ServiceName)
		require.Equal(t, "f685d66a-7c12-4c47-84d0-c8ba75856374", trm.RuntimeID)
		require.Equal(t, "cpp", trm.TracerLanguage)
		require.Equal(t, "v1.0.0", trm.TracerVersion)
		require.Equal(t, "my-hostname", trm.Hostname)
		require.Equal(t, "my-env", trm.ServiceEnv)
		require.Equal(t, "my-version", trm.ServiceVersion)
		require.Equal(t, uint8(1), trm.SchemaVersion)

		tags := trm.GetTags()
		assert.Equal(t, []string{
			"tracer_service_name:my-service",
			"tracer_service_env:my-env",
			"tracer_service_version:my-version",
		}, tags)
	})

	t.Run("go_v2", func(t *testing.T) {
		// Generated from a go tracer version with https://github.com/DataDog/dd-trace-go/pull/3960
		// add DD_EXPERIMENTAL_PROPAGATE_PROCESS_TAGS_ENABLED=true
		loadTracerMetadata(t, "testdata/tracer_go_v2.data")
		trm, err := GetTracerMetadata(pid, procfs)
		require.Equal(t, "test-go", trm.ServiceName)
		require.Equal(t, "bfed5675-a8f9-4d3d-a630-64713d543d1a", trm.RuntimeID)
		require.Equal(t, "go", trm.TracerLanguage)
		require.Equal(t, "v2.3.0-dev.1", trm.TracerVersion)
		require.Equal(t, "my-hostname", trm.Hostname)
		require.Equal(t, "prod", trm.ServiceEnv)
		require.Equal(t, "abc123", trm.ServiceVersion)
		require.Equal(t, "entrypoint.basedir:exe,entrypoint.name:gotrace,entrypoint.type:executable,entrypoint.workdir:gotrace", trm.ProcessTags)
		require.Equal(t, "d7827075-010c-4e21-a663-daa3cd34e6f2", trm.ContainerID)
		require.Equal(t, uint8(2), trm.SchemaVersion)
		require.NoError(t, err)

		var tags []string
		// Use Tags() instead of GetTags() here to test that function directly too
		for key, value := range trm.Tags() {
			tags = append(tags, key+":"+value)
		}
		assert.Equal(t, []string{
			"tracer_service_name:test-go",
			"tracer_service_env:prod",
			"tracer_service_version:abc123",
			"entrypoint.basedir:exe",
			"entrypoint.name:gotrace",
			"entrypoint.type:executable",
			"entrypoint.workdir:gotrace",
		}, tags)
	})

	t.Run("invalid data", func(t *testing.T) {
		createTracerMemfd(t, []byte("invalid data"))
		trm, err := GetTracerMetadata(pid, procfs)
		require.Error(t, err)

		tags := trm.GetTags()
		assert.Empty(t, tags)
	})
}

func createTracerMemfd(t *testing.T, l []byte) {
	t.Helper()
	fd, err := unix.MemfdCreate("datadog-tracer-info-xxx", 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	err = unix.Ftruncate(fd, int64(len(l)))
	require.NoError(t, err)
	data, err := unix.Mmap(fd, 0, len(l), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	require.NoError(t, err)
	copy(data, l)
	err = unix.Munmap(data)
	require.NoError(t, err)
}

func TestParseProcessTags(t *testing.T) {
	tests := []struct {
		name         string
		processTags  string
		expectedTags []string
	}{
		{
			name:        "valid comma-separated tags",
			processTags: "entrypoint.name:com.example.App,service.type:tomcat,service.framework:spring",
			expectedTags: []string{
				"entrypoint.name:com.example.App",
				"service.framework:spring",
				"service.type:tomcat",
			},
		},
		{
			name:        "single tag",
			processTags: "entrypoint.workdir:app",
			expectedTags: []string{
				"entrypoint.workdir:app",
			},
		},
		{
			name:         "empty string",
			processTags:  "",
			expectedTags: nil,
		},
		{
			name:        "tags with spaces",
			processTags: " service.runtime : java-17 , entrypoint.name : com.app.Main ",
			expectedTags: []string{
				"entrypoint.name:com.app.Main",
				"service.runtime:java-17",
			},
		},
		{
			name:        "tag with colon in value",
			processTags: "url:http://example.com:8080",
			expectedTags: []string{
				"url:http://example.com:8080",
			},
		},
		{
			name:         "malformed tag without colon",
			processTags:  "invalid_tag,service.type:nginx",
			expectedTags: []string{"service.type:nginx"},
		},
		{
			name:         "tags with empty keys or values",
			processTags:  ":value,key:,service.runtime:python3.9",
			expectedTags: []string{"service.runtime:python3.9"},
		},
		{
			name:         "empty tag entries",
			processTags:  "service.framework:django,,entrypoint.name:manage.py,",
			expectedTags: []string{"entrypoint.name:manage.py", "service.framework:django"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trm := TracerMetadata{
				ProcessTags: tt.processTags,
			}

			tags := trm.GetTags()
			sort.Strings(tags)
			sort.Strings(tt.expectedTags)
			assert.Equal(t, tt.expectedTags, tags)
		})
	}
}
