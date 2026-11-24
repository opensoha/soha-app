package main

import (
	"context"
	"runtime"
	"testing"
)

func TestManagedOSVersionArg(t *testing.T) {
	cases := []struct {
		field   string
		wantArg string
		wantErr bool
	}{
		{field: "productVersion", wantArg: "-productVersion"},
		{field: "buildVersion", wantArg: "-buildVersion"},
		{field: "productName", wantErr: true},
		{field: "-productVersion", wantErr: true},
		{field: "--productVersion", wantErr: true},
		{field: "productVersion -productName", wantErr: true},
		{field: "", wantErr: true},
	}
	for _, test := range cases {
		arg, err := managedOSVersionArg(test.field)
		if (err != nil) != test.wantErr {
			t.Fatalf("managedOSVersionArg(%q) error = %v, wantErr %v", test.field, err, test.wantErr)
		}
		if arg != test.wantArg {
			t.Fatalf("managedOSVersionArg(%q) = %q, want %q", test.field, arg, test.wantArg)
		}
	}
}

func TestManagedOSVersionValue(t *testing.T) {
	cases := []struct {
		field   string
		value   string
		want    string
		wantErr bool
	}{
		{field: "productVersion", value: "15.3", want: "15.3"},
		{field: "productVersion", value: "15.3.1", want: "15.3.1"},
		{field: "productVersion", value: "15", want: "15"},
		{field: "productVersion", value: "15.", wantErr: true},
		{field: "productVersion", value: "15.3 beta", wantErr: true},
		{field: "productVersion", value: "15\n", wantErr: true},
		{field: "buildVersion", value: "24D70", want: "24D70"},
		{field: "buildVersion", value: "24D70a", want: "24D70a"},
		{field: "buildVersion", value: "24D-70", wantErr: true},
		{field: "buildVersion", value: "24D 70", wantErr: true},
		{field: "buildVersion", value: "", wantErr: true},
		{field: "productName", value: "macOS", wantErr: true},
	}
	for _, test := range cases {
		value, err := managedOSVersionValue(test.field, test.value)
		if (err != nil) != test.wantErr {
			t.Fatalf("managedOSVersionValue(%q, %q) error = %v, wantErr %v", test.field, test.value, err, test.wantErr)
		}
		if value != test.want {
			t.Fatalf("managedOSVersionValue(%q, %q) = %q, want %q", test.field, test.value, value, test.want)
		}
	}
}

func TestRunManagedOSVersionReadOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sw_vers readback is macOS-only")
	}
	for _, field := range []string{"productVersion", "buildVersion"} {
		value, err := runManagedOSVersion(context.Background(), field)
		if err != nil {
			t.Fatalf("runManagedOSVersion(%q) error = %v", field, err)
		}
		if value == "" {
			t.Fatalf("runManagedOSVersion(%q) returned empty value", field)
		}
	}
	if _, err := runManagedOSVersion(context.Background(), "-productName"); err == nil {
		t.Fatal("runManagedOSVersion accepted unsupported field")
	}
}
