package internals

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	utils "github.com/globe-and-citizen/layer8-utils"
	googleUUID "github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	testCases := map[string]struct {
		protocol string
		host     string
		port     string
		expected string
	}{
		"success case local":         {"http", "localhost", "5001", "http://localhost:5001"},
		"success case remote":        {"https", "l8dp.net", "", "https://l8dp.net"},
		"protocol blank":             {"", "l8dp.net", "5001", ""},
		"protocol too long":          {"htttps", "l8dp.net", "5001", ""},
		"protocol illegal character": {"https.", "l8dp.net", "5001", ""},
		"host empty":                 {"http", "", "5001", ""},
		"port non digit string 1":    {"http", "", "5001a", ""},
		"port too long":              {"https", "l8dp.net", "655361", ""},
		"non-digit port":             {"http", "l8dp.net", ".5001", ""},
		"non-charater protocol":      {"http8", "l8dp.net", "5001", ""},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(tc.protocol, tc.host, tc.port)
			if err != nil {
				assert.Empty(t, client)
				assert.Equal(t, tc.expected, "")
				return
			}
			assert.Equal(t, tc.expected, client.GetURL())
		})
	}
}

func TestClientDo(t *testing.T) {
	// from "GenerateStandardToken" in server/utils/utils.go
	genToken := func(secretKey string) (string, error) {
		token := jwt.New(jwt.SigningMethodHS256)
		claims := &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
		}
		token.Claims = claims
		tokenString, err := token.SignedString([]byte(secretKey))
		assert.NoError(t, err)
		return tokenString, nil
	}

	var (
		RequestMethod  = "GET"
		RequestURL     = "https://test.layer8.com/test"
		RequestHeaders = map[string]string{
			"Content-Type":  "application/json",
			"X-Test-Header": "test",
		}
		RequestPayload, _ = json.Marshal(map[string]interface{}{
			"test": "test",
		})

		ResponseStatusCode = 200
		ResponseHeader     = map[string]string{
			"Content-Type":  "application/json",
			"X-Test-Header": "test-response",
		}
		ResponsePayload, _ = json.Marshal(map[string]interface{}{
			"test": "test-response",
		})
	)

	var sharedkey *utils.JWK

	// generate a key pair for the server
	sPri, sPub, err := utils.GenerateKeyPair(utils.ECDH)
	assert.NoError(t, err)
	assert.NotNil(t, sPri)
	assert.NotNil(t, sPub)

	// Create a mock server
	mockProxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/init-tunnel":
			token, err := genToken("mock_secret")
			assert.NoError(t, err)
			assert.NotNil(t, token)

			userpub, err := utils.B64ToJWK(r.Header.Get("x-ecdh-init"))
			assert.NoError(t, err)

			sharedkey, err = sPri.GetECDHSharedSecret(userpub)
			assert.NoError(t, err)

			data, err := json.Marshal(map[string]interface{}{
				"server_pubKeyECDH": sPub,
				"up_JWT":            token,
			})
			assert.NoError(t, err)

			w.Header().Add("up_JWT", token)
			w.WriteHeader(200)
			w.Write(data)
		default:
			// every request to the proxy is expected to be a POST request
			assert.Equal(t, r.Method, "POST")

			pURL, err := url.Parse(RequestURL)
			assert.NoError(t, err)

			// the "X-Forwarded-Host" header must be set to the original request's IP
			assert.Equal(t, pURL.Host, r.Header.Get("X-Forwarded-Host"))
			// the "X-Forwarded-Proto" header must be set to the original request's scheme
			assert.Equal(t, pURL.Scheme, r.Header.Get("X-Forwarded-Proto"))
			// the path of the request must match the path of the original request
			assert.Equal(t, "/", r.URL.Path) // Here

			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.NotNil(t, body)

			reqBody := make(map[string]interface{})
			err = json.Unmarshal(body, &reqBody)
			assert.NoError(t, err)

			// it is expected that the body is encrypted and encoded in base64 format
			// and set to the "data" key of the request body
			assert.NotNil(t, reqBody["data"])

			// decrypt the body
			data, err := base64.URLEncoding.DecodeString(reqBody["data"].(string))
			assert.NoError(t, err)

			decrypted, err := sharedkey.SymmetricDecrypt(data)
			assert.NoError(t, err)

			req, err := utils.FromJSONRequest(decrypted)
			assert.NoError(t, err)
			assert.NotNil(t, req)
			assert.Equal(t, req.Method, RequestMethod)
			assert.Equal(t, req.Headers, RequestHeaders)
			assert.Equal(t, req.Body, RequestPayload)

			// encrypt and return response
			res := utils.Response{
				Body:       ResponsePayload,
				Headers:    ResponseHeader,
				Status:     ResponseStatusCode,
				StatusText: http.StatusText(ResponseStatusCode),
			}
			bRes, err := res.ToJSON()
			assert.NoError(t, err)
			assert.NotNil(t, bRes)

			encRes, err := sharedkey.SymmetricEncrypt(bRes)
			assert.NoError(t, err)
			assert.NotNil(t, encRes)

			resData, err := json.Marshal(map[string]interface{}{
				"data": base64.URLEncoding.EncodeToString(encRes),
			})
			assert.NoError(t, err)

			w.WriteHeader(ResponseStatusCode)
			w.Write(resData)
		}
	}))
	defer mockProxyServer.Close()

	// init tunnel
	pri, pub, err := utils.GenerateKeyPair(utils.ECDH)
	assert.NoError(t, err)
	assert.NotNil(t, pri)
	assert.NotNil(t, pub)

	b64, err := pub.ExportAsBase64()
	assert.NoError(t, err)
	assert.NotNil(t, b64)

	uuid := googleUUID.New().String()

	iClient := &http.Client{}
	iReq, err := http.NewRequest("GET", mockProxyServer.URL+"/init-tunnel", bytes.NewBuffer([]byte(b64)))
	assert.NoError(t, err)

	iReq.Header.Add("x-ecdh-init", b64)
	iReq.Header.Add("x-client-uuid", uuid)

	iRes, err := iClient.Do(iReq)
	assert.NoError(t, err)
	assert.Equal(t, iRes.StatusCode, 200)

	up_JWT := iRes.Header.Get("up_JWT")
	iBody, err := io.ReadAll(iRes.Body)
	assert.NoError(t, err)

	iData := make(map[string]interface{})
	err = json.Unmarshal(iBody, &iData)
	assert.NoError(t, err)

	serverjwk, err := utils.JWKFromMap(iData)
	assert.NoError(t, err)
	assert.NotNil(t, serverjwk)

	symmkey, err := pri.GetECDHSharedSecret(serverjwk)
	assert.NoError(t, err)
	assert.NotNil(t, symmkey)

	// Tests of Client Functions
	client := &Client{
		proxyURL: mockProxyServer.URL,
	}

	// client.do

	// client.transfer
	t.Run("client.transfer(...)", func(t *testing.T) {
		testCasesForStrings := map[string]struct {
			backendURL     string
			UpJWT          string
			UUID           string
			ExpectedStatus int
		}{
			"Success":      {RequestURL, up_JWT, uuid, 200},
			"URL blank":    {"", up_JWT, uuid, 400},
			"up_JWT blank": {RequestURL, "", uuid, 400},
			"uuid blank":   {RequestURL, up_JWT, "", 400},
		}

		for name, tc := range testCasesForStrings {
			t.Run(name, func(t *testing.T) {
				res, err := client.transfer(symmkey, utils.NewRequest(RequestMethod, RequestHeaders, RequestPayload), tc.backendURL, false, tc.UpJWT, tc.UUID)
				assert.Nil(t, err)
				assert.Equal(t, tc.ExpectedStatus, res.Status)
			})
		}

		testCasesOfNullPointers := map[string]struct {
			SharedSecret   *utils.JWK
			Request        *utils.Request
			ExpectedStatus int
		}{
			"Success":            {symmkey, utils.NewRequest(RequestMethod, RequestHeaders, RequestPayload), 200},
			"Nil Shared Secret":  {nil, utils.NewRequest(RequestMethod, RequestHeaders, RequestPayload), 400},
			"Nil Client Request": {symmkey, nil, 400},
		}

		for name, tc := range testCasesOfNullPointers {
			t.Run(name, func(t *testing.T) {
				res, err := client.transfer(tc.SharedSecret, tc.Request, RequestURL, false, up_JWT, uuid)
				assert.Nil(t, err)
				assert.Equal(t, tc.ExpectedStatus, res.Status)
			})
		}

	})

	// client.Do
	// What behaviour do we want if a POST is used, malformed request, etc?
	t.Run("client.Do(...)", func(t *testing.T) {
		testCases := map[string]struct {
			Method   string
			Headers  map[string]string
			Payload  []byte
			Expected int
		}{
			"Success case": {"GET", RequestHeaders, RequestPayload, 200},
			// "'POST' not 'GET'": {"POST", RequestHeaders, RequestPayload, 200},
			// "Empty headers map": {"GET", make(map[string]string), RequestPayload, 200},
			// "Empty Payload":     {"GET", RequestHeaders, []byte{}},
		}

		for name, tc := range testCases {
			t.Run(name, func(t *testing.T) {
				malformedReq := utils.NewRequest(tc.Method, tc.Headers, tc.Payload)
				res := client.Do(RequestURL, malformedReq, symmkey, false, up_JWT, uuid)
				assert.NotNil(t, res)
				assert.Equal(t, tc.Expected, res.Status) // 200, 500
				for k, v := range ResponseHeader {
					assert.Equal(t, v, res.Headers[k])
				}
				assert.Equal(t, ResponsePayload, res.Body)
				assert.Equal(t, http.StatusText(ResponseStatusCode), res.StatusText)
			})
		}
	})
}
