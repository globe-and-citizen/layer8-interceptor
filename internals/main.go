package internals

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

	// "globe-and-citizen/layer8/utils" (Dep)
	"net/http"
	"net/url"

	utils "github.com/globe-and-citizen/layer8-utils"
)

type Client struct {
	proxyURL string
}

type ClientImpl interface {
	GetURL() string
	Do(
		url string, req *utils.Request, sharedSecret *utils.JWK, isStatic bool, UpJWT, UUID string,
	) *utils.Response
}

// NewClient creates a new client with the given proxy server url
func NewClient(protocol, host, port string) (ClientImpl, error) {

	r1, _ := regexp.Compile("[^a-zA-Z]")

	if protocol == "" ||
		len(protocol) > 5 ||
		r1.MatchString(protocol) {
		return nil, fmt.Errorf("invalid protocol. Cannot create new layer8 client ")
	}

	if host == "" {
		return nil, fmt.Errorf("invalid host. Cannot create New Client")
	}

	r1, _ = regexp.Compile("[^0-9]")
	if len(port) >= 6 ||
		r1.MatchString(port) {
		return nil, fmt.Errorf("invalid port. Cannot create new layer8 client ")
	}

	var ProxyURL string
	if port != "" {
		ProxyURL = fmt.Sprintf("%s://%s:%s", protocol, host, port)
	} else {
		ProxyURL = fmt.Sprintf("%s://%s", protocol, host)
	}
	return &Client{
		proxyURL: ProxyURL,
	}, nil
}

func (c *Client) GetURL() string {
	return c.proxyURL
}

// Do sends a request to through the layer8 proxy server and returns a response
func (c *Client) Do(url string, req *utils.Request, sharedSecret *utils.JWK, isStatic bool, UpJWT, UUID string) *utils.Response {
	// Send request
	res, err := c.transfer(sharedSecret, req, url, isStatic, UpJWT, UUID)
	if err != nil {
		return &utils.Response{
			Status:     500,
			StatusText: err.Error(),
		}
	}
	return res
}

// Performs Prechecks and then transforms the byte slice to a utils.Response struct.
func (c *Client) transfer(sharedSecret *utils.JWK, req *utils.Request, url string, isStatic bool, UpJWT, UUID string) (*utils.Response, error) {
	// Prechecks
	if sharedSecret == nil || req == nil {
		return &utils.Response{
			Status:     400,
			StatusText: "client.transfer(...) error. The 'sharedSecret' or req parameter was nil pointer",
		}, nil
	}

	if url == "" || UpJWT == "" || UUID == "" {
		return &utils.Response{
			Status:     400,
			StatusText: "client.transfer(...) error. The 'url', 'UpJWT', or 'UUID' was blank",
		}, nil
	}

	// send the request
	res := c.do(req, sharedSecret, url, isStatic, UpJWT, UUID)
	// decode response body
	resData, err := utils.FromJSONResponse(res)
	if err != nil {
		return &utils.Response{
			Status:     500,
			StatusText: err.Error(),
		}, nil
	}
	return resData, nil
}

// do sends the request to the remote server through the layer8 proxy server
// returns a status code and response body
func (c *Client) do(
	req *utils.Request, sharedSecret *utils.JWK, backendUrl string, isStatic bool, UpJWT, UUID string,
) []byte {
	var err error

	data, err := req.ToJSON()
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: fmt.Sprintf("Error marshalling request: %s", err.Error()),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	data, err = sharedSecret.SymmetricEncrypt(data)
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	data, err = json.Marshal(map[string]interface{}{
		"data": base64.URLEncoding.EncodeToString(data),
	})

	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	parsedURL, err := url.Parse(backendUrl)
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}
	// create request
	client := &http.Client{}
	r, err := http.NewRequest("POST", c.proxyURL+parsedURL.Path, bytes.NewBuffer(data))
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}
	// Add headers to the interceptor request.
	// Note that at this point, the user's headers are bundled into the encrypted body of the interceptor's request
	r.Header.Add("X-Forwarded-Host", parsedURL.Host)
	r.Header.Add("X-Forwarded-Proto", parsedURL.Scheme)
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("up-JWT", UpJWT)
	r.Header.Add("x-client-uuid", UUID)
	if isStatic {
		r.Header.Add("X-Static", "true")
	}

	// send request
	res, err := client.Do(r)
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	defer res.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	bufByte := buf.Bytes()
	mapB := make(map[string]interface{})
	json.Unmarshal(bufByte, &mapB)

	toDecode, ok := mapB["data"].(string)
	if !ok {
		res := &utils.Response{
			Status:     500,
			StatusText: "Proxy's response to interceptor's request failed to unmarshall: mapB[\"data\"].(string) not 'ok'",
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	decoded, err := base64.URLEncoding.DecodeString(toDecode)
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	bufByte, err = sharedSecret.SymmetricDecrypt(decoded)
	if err != nil {
		res := &utils.Response{
			Status:     500,
			StatusText: err.Error(),
			Headers:    make(map[string]string),
		}
		resByte, _ := res.ToJSON()
		return resByte
	}

	// At this point the proxy's headers have been stripped and you have the SP's response as bufByte
	return bufByte
}
