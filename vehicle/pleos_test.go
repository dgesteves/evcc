package vehicle

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/vehicle/pleos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// pleosFake is a Pleos API where a new token revokes the previous one of the same
// client id. Pleos doesn't document this, it is inferred from user reports.
type pleosFake struct {
	mu        sync.Mutex
	secrets   map[string]string
	current   map[string]string
	issued    map[string]int
	expiresIn int64
}

func newPleosFake(t *testing.T) *pleosFake {
	t.Helper()

	f := &pleosFake{
		secrets: make(map[string]string),
		current: make(map[string]string),
		issued:  make(map[string]int),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/personal-token", f.token)
	mux.HandleFunc("GET /vehicles/consent", f.authorized(`{"data":{"vehicles":[{"vin":"VIN1"},{"vin":"VIN2"}]}}`))
	mux.HandleFunc("GET /vehicles/{vin}/batteries", f.authorized(`{"data":{"charge":{"stateOfCharge":55}}}`))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL := pleos.BaseURL
	pleos.BaseURL = srv.URL
	t.Cleanup(func() { pleos.BaseURL = baseURL })

	return f
}

func (f *pleosFake) token(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if r.Header.Get("Brand") != "kia" || !f.valid(req.ClientID, req.ClientSecret) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{"accessToken": f.issue(req.ClientID), "expiresIn": f.expiresIn},
	})
}

func (f *pleosFake) authorized(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		current := slices.Contains(slices.Collect(maps.Values(f.current)), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		f.mu.Unlock()

		if !current {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		_, _ = io.WriteString(w, body)
	}
}

func (f *pleosFake) valid(clientID, clientSecret string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.secrets[clientID] == clientSecret
}

func (f *pleosFake) issue(clientID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[clientID]++
	f.current[clientID] = fmt.Sprintf("%s-%d", clientID, f.issued[clientID])
	return f.current[clientID]
}

func (f *pleosFake) tokens(clientID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued[clientID]
}

// key registers an api key that is unique per test run, since token sources outlive the test
func (f *pleosFake) key() (string, string) {
	clientID, clientSecret := rand.Text(), rand.Text()
	f.setSecret(clientID, clientSecret)
	return clientID, clientSecret
}

func (f *pleosFake) setSecret(clientID, clientSecret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[clientID] = clientSecret
}

func newPleosVehicle(brand, clientID, clientSecret, vin string) (api.Vehicle, error) {
	return NewPleosFromConfig(map[string]any{
		"brand":        brand,
		"clientid":     clientID,
		"clientsecret": clientSecret,
		"vin":          vin,
		"cache":        "1ns",
	})
}

func assertPleosSoc(t *testing.T, vehicles ...api.Vehicle) {
	t.Helper()
	for _, v := range vehicles {
		soc, err := v.Soc()
		assert.NoError(t, err)
		assert.Equal(t, 55.0, soc)
	}
}

func TestPleosSameKey(t *testing.T) {
	for _, brand := range []string{"kia", ""} {
		t.Run("brand "+brand, func(t *testing.T) {
			f := newPleosFake(t)
			id, secret := f.key()

			kia1, err := newPleosVehicle(brand, id, secret, "VIN1")
			require.NoError(t, err)

			kia2, err := newPleosVehicle(brand, id, secret, "VIN2")
			require.NoError(t, err)
			assertPleosSoc(t, kia1, kia2)

			// validating a vehicle in the ui creates another instance
			check, err := newPleosVehicle(brand, id, secret, "VIN1")
			require.NoError(t, err)
			assertPleosSoc(t, check, kia1, kia2)

			assert.Equal(t, 1, f.tokens(id))
		})
	}
}

func TestPleosDifferentKeys(t *testing.T) {
	f := newPleosFake(t)
	id1, secret1 := f.key()
	id2, secret2 := f.key()

	kia1, err := newPleosVehicle("kia", id1, secret1, "VIN1")
	require.NoError(t, err)

	kia2, err := newPleosVehicle("kia", id2, secret2, "VIN2")
	require.NoError(t, err)

	check, err := newPleosVehicle("kia", id1, secret1, "VIN1")
	require.NoError(t, err)
	assertPleosSoc(t, check, kia1, kia2)

	assert.Equal(t, 1, f.tokens(id1))
	assert.Equal(t, 1, f.tokens(id2))
}

func TestPleosConcurrentCreation(t *testing.T) {
	f := newPleosFake(t)
	id, secret := f.key()

	vehicles := make([]api.Vehicle, 10)

	var eg errgroup.Group
	for i := range vehicles {
		eg.Go(func() (err error) {
			vehicles[i], err = newPleosVehicle("kia", id, secret, "VIN1")
			return err
		})
	}
	require.NoError(t, eg.Wait())

	assertPleosSoc(t, vehicles...)
	assert.Equal(t, 1, f.tokens(id))
}

func TestPleosChangedSecret(t *testing.T) {
	f := newPleosFake(t)
	id, secret := f.key()

	kia1, err := newPleosVehicle("kia", id, secret, "VIN1")
	require.NoError(t, err)

	// a wrong secret must neither pass validation nor cost the running vehicle its token
	_, err = newPleosVehicle("kia", id, "wrong", "VIN1")
	require.Error(t, err)
	assertPleosSoc(t, kia1)
	assert.Equal(t, 1, f.tokens(id))

	// a renewed secret must not be served the token of the old one
	f.setSecret(id, "renewed")

	kia2, err := newPleosVehicle("kia", id, "renewed", "VIN2")
	require.NoError(t, err)
	assertPleosSoc(t, kia2)
	assert.Equal(t, 2, f.tokens(id))
}

func TestPleosTokenExpiry(t *testing.T) {
	f := newPleosFake(t)
	id, secret := f.key()

	// oauth2 refreshes 10s ahead of the expiry, leaving 2s of validity
	f.expiresIn = 12

	kia1, err := newPleosVehicle("kia", id, secret, "VIN1")
	require.NoError(t, err)

	kia2, err := newPleosVehicle("kia", id, secret, "VIN2")
	require.NoError(t, err)

	// another client on the same key revokes the token, which is only replaced on expiry
	f.issue(id)
	_, err = kia1.Soc()
	require.ErrorContains(t, err, "403")

	time.Sleep(2100 * time.Millisecond)

	var eg errgroup.Group
	for _, v := range []api.Vehicle{kia1, kia2} {
		eg.Go(func() error {
			_, err := v.Soc()
			return err
		})
	}
	require.NoError(t, eg.Wait())

	assertPleosSoc(t, kia1, kia2)
	assert.Equal(t, 3, f.tokens(id))
}
