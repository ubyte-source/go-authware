package secret_test

import (
	"context"
	"fmt"

	"github.com/ubyte-source/go-authware/secret"
)

func ExampleStatic() {
	p := secret.Static(map[string]string{"db_password": "p4ss"})
	v, err := p.Secret(context.Background(), "db_password")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(v)
	// Output: p4ss
}

func ExampleMapResolver() {
	tenantA := secret.Static(map[string]string{"db": "alpha"})
	tenantB := secret.Static(map[string]string{"db": "beta"})
	fallback := secret.Static(map[string]string{"db": "default"})
	r := secret.MapResolver(map[string]secret.Provider{
		"a": tenantA,
		"b": tenantB,
	}, fallback)

	for _, tenant := range []string{"a", "b", "unknown"} {
		v, err := r.For(tenant).Secret(context.Background(), "db")
		if err != nil {
			fmt.Println(tenant, err)
			continue
		}
		fmt.Println(tenant, v)
	}
	// Output:
	// a alpha
	// b beta
	// unknown default
}
