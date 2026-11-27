package handlers

import "testing"

// A client that asks for a secret-based token endpoint method is registered as
// a public client (RFC 7591 §3.2.1): Claude's connector asks for
// client_secret_post and must not get 400.
func TestDynamicRegistrationAuthMethod(t *testing.T) {
	for _, method := range []string{"", "none", "client_secret_post", "client_secret_basic"} {
		req := dynamicClientRegistrationRequest{
			ClientName:              "Claude",
			RedirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: method,
		}
		if err := validateDynamicRegistration(&req); err != nil {
			t.Fatalf("method %q: unexpected error %v", method, err)
		}
		if req.TokenEndpointAuthMethod != "none" {
			t.Fatalf("method %q: registered as %q, want none", method, req.TokenEndpointAuthMethod)
		}
	}
	req := dynamicClientRegistrationRequest{
		RedirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback"},
		TokenEndpointAuthMethod: "private_key_jwt",
	}
	if err := validateDynamicRegistration(&req); err == nil {
		t.Fatal("private_key_jwt must be refused")
	}
}
