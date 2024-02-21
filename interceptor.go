package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"globe-and-citizen/layer8-interceptor/internals"
	"time"

	"net/http"
	"strings"
	"syscall/js"

	utils "github.com/globe-and-citizen/layer8-utils"

	uuid "github.com/google/uuid"
)

// Declare global constants
const INTERCEPTOR_VERSION = "0.0.14"

// Declare global variables
var (
	Layer8Scheme        string
	Layer8Host          string
	Layer8Port          string
	Layer8LightsailURL  string
	Counter             int
	EncryptedTunnelFlag bool
	privJWK_ecdh        *utils.JWK
	pubJWK_ecdh         *utils.JWK
	userSymmetricKey    *utils.JWK
	UpJWT               string
	UUID                string
	L8Client            internals.ClientImpl
)

/*
	//var L8Client = internals.NewClient(Layer8Scheme, Layer8Host, Layer8Port) // Ravi TODO this should probably be revisited
*/

func main() {
	// Create channel to keep the Go thread alive
	c := make(chan struct{})

	// Initialize global variables
	Layer8Scheme = ""
	Layer8Host = ""
	Layer8Port = ""

	EncryptedTunnelFlag = false

	// Expose layer8 functionality to the front end Javascript
	js.Global().Set("layer8", js.ValueOf(map[string]interface{}{
		"testWASM":             js.FuncOf(testWASM),
		"persistenceCheck":     js.FuncOf(persistenceCheck),
		"initEncryptedTunnel":  js.FuncOf(initializeECDHTunnel),
		"checkEncryptedTunnel": js.FuncOf(checkEncryptedTunnel),
		"fetch":                js.FuncOf(fetch),
		"static":               js.FuncOf(getStatic),
		// TODO: add a function here that returns the state of the tunnel
	}))

	// Developer Warnings:
	fmt.Println("WARNING: wasm_exec.js is versioned and has some breaking changes. Ensure you are using the correct version.")

	// Wait indefinitely
	<-c
}

// Utility function to test promise resolution / rejection from the console.
func testWASM(this js.Value, args []js.Value) interface{} {
	var promise_logic = func(this js.Value, resolve_reject []js.Value) interface{} {
		resolve := resolve_reject[0]
		reject := resolve_reject[1]
		if len(args) == 0 {
			reject.Invoke(js.ValueOf("Promise rejection occurs if not arguments are passed. Pass an argument."))
			return nil
		}
		go func() {
			resolve.Invoke(js.ValueOf(fmt.Sprintf("WASM Interceptor version %s successfully loaded. Argument passed: %v. To test promise rejection, call with no argument.", INTERCEPTOR_VERSION, args[0])))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(promise_logic))
	return promise
}

func persistenceCheck(this js.Value, args []js.Value) interface{} {
	var promise_logic = func(this js.Value, resolve_reject []js.Value) interface{} {
		resolve := resolve_reject[0]
		go func() {
			Counter++
			fmt.Println("WASM Counter: ", Counter)
			resolve.Invoke(js.ValueOf(Counter))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(promise_logic))
	return promise
}

func initializeECDHTunnel(this js.Value, args []js.Value) interface{} {
	// Convert JS values into useable Golang variables
	ServiceProviderURL := ""
	Layer8Scheme := ""
	Layer8Host := ""
	Layer8Port := ""
	ErrorDestructuringConfigObject := false

	js.Global().Get("Object").Call("entries", args[0]).Call("forEach", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// fmt.Println("Key: ", args[0].Index(0).String())   // key
		key := args[0].Index(0).String()
		// fmt.Println("Value: ", args[0].Index(1).String()) // value
		value := args[0].Index(1).String()

		switch key {
		case "ServiceProviderURL":
			ServiceProviderURL = value
		case "Layer8Scheme":
			Layer8Scheme = value
		case "Layer8Host":
			Layer8Host = value
		case "Layer8Port":
			Layer8Port = value
		default:
			ErrorDestructuringConfigObject = true
		}
		return nil
	}))

	if ErrorDestructuringConfigObject {
		return js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			// resolve := args[0]
			reject := args[1]
			reject.Invoke(js.Global().Get("Error").New("Unable to destructure the Layer8 encrypted tunnel config object. "))
			return nil
		}))
	}

	return js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			var err error
			privJWK_ecdh, pubJWK_ecdh, err = utils.GenerateKeyPair(utils.ECDH)
			if err != nil {
				fmt.Println("[Interceptor]", err.Error())
				EncryptedTunnelFlag = false
				reject.Invoke(js.Global().Get("Error").New("Unable to generate client key pair"))
				return
			}

			b64PubJWK, err := pubJWK_ecdh.ExportAsBase64()
			if err != nil {
				fmt.Println("[Interceptor]", err.Error())
				EncryptedTunnelFlag = false
				reject.Invoke(js.Global().Get("Error").New("Failed to Export publicJWK_ecdh"))
				return
			}

			var ProxyURL string
			if Layer8Port != "" {
				ProxyURL = fmt.Sprintf("%s://%s:%s/init-tunnel?backend=%s", Layer8Scheme, Layer8Host, Layer8Port, ServiceProviderURL)
			} else {
				ProxyURL = fmt.Sprintf("%s://%s/init-tunnel?backend=%s", Layer8Scheme, Layer8Host, ServiceProviderURL)
			}

			// fmt.Println("[Interceptor]", ProxyURL)
			client := &http.Client{}
			req, err := http.NewRequest("POST", ProxyURL, bytes.NewBuffer([]byte(b64PubJWK)))
			if err != nil {
				fmt.Println(err.Error())
				EncryptedTunnelFlag = false
				reject.Invoke(js.Global().Get("Error").New("Creation of initialization POST request failed. "))
				return
			}
			uuid := uuid.New()
			UUID = uuid.String()
			req.Header.Add("x-ecdh-init", b64PubJWK)
			req.Header.Add("x-client-uuid", uuid.String())

			// send request
			resp, err := client.Do(req)
			if err != nil {
				fmt.Println(err.Error())
				reject.Invoke(js.Global().Get("Error").New("Initialization POST request to Proxy failed. "))
				EncryptedTunnelFlag = false
				return
			}

			if resp.StatusCode == 401 {
				reject.Invoke(js.Global().Get("Error").New("401 response from proxy, user is not authorized. "))
				EncryptedTunnelFlag = false
				return
			}

			Respbody := utils.ReadResponseBody(resp.Body)

			data := map[string]interface{}{}

			err = json.Unmarshal(Respbody, &data)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("The data received from the proxy could not be unmarshalled: ", err.Error()))
				EncryptedTunnelFlag = false
				return
			}

			UpJWT = data["up-JWT"].(string)

			server_pubKeyECDH, err := utils.JWKFromMap(data)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				EncryptedTunnelFlag = false
				return
			}

			userSymmetricKey, err = privJWK_ecdh.GetECDHSharedSecret(server_pubKeyECDH)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				EncryptedTunnelFlag = false
				return
			}

			// fmt.Println("[Interceptor] UpJWT: ", UpJWT)

			// TODO: Send an encrypted ping / confirmation to the server using the shared secret
			// just like the 1. Syn 2. Syn/Ack 3. Ack flow in a TCP handshake
			EncryptedTunnelFlag = true
			L8Client = internals.NewClient(Layer8Scheme, Layer8Host, Layer8Port)
			//fmt.Println("[interceptor] ", L8Client)
			fmt.Println("[Interceptor] Encrypted tunnel successfully established.")
			resolve.Invoke(true)
			return
		}()

		return nil
	}))
}

func checkEncryptedTunnel(this js.Value, args []js.Value) interface{} {
	return js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, resolve_reject []js.Value) interface{} {
		resolve := resolve_reject[0]
		//reject := resolve_reject[1]
		if EncryptedTunnelFlag {
			resolve.Invoke(true)
		} else {
			resolve.Invoke(false)
		}
		return nil
	}))
}

func fetch(this js.Value, args []js.Value) interface{} {
	var promise_logic = func(this js.Value, resolve_reject []js.Value) interface{} {
		resolve := resolve_reject[0]
		reject := resolve_reject[1]

		if !EncryptedTunnelFlag {
			reject.Invoke(js.Global().Get("Error").New("The Encrypted tunnel is closed. Reload page."))
			return nil
		}

		if len(args) == 0 {
			reject.Invoke(js.Global().Get("Error").New("No URL provided to fetch call."))
			return nil
		}

		url := args[0].String()
		if len(url) <= 0 {
			reject.Invoke(js.Global().Get("Error").New("Invalid URL provided to fetch call."))
			return nil
		}

		options := js.ValueOf(map[string]interface{}{
			"method":  "GET", // Set HTTP "GET" request to be the default
			"headers": js.ValueOf(map[string]interface{}{}),
			"body":    "<undefined>",
		})

		if len(args) > 1 {
			options = args[1]
		}

		method := options.Get("method").String()
		if method == "" {
			method = "GET"
		}

		// Set headers to an empty object if it is 'undefined' or 'null'
		userAddedHeaders := options.Get("headers")
		if userAddedHeaders.String() == "<undefined>" || userAddedHeaders.String() == "null" {
			userAddedHeaders = js.ValueOf(map[string]interface{}{})
		}

		userHeaderMap := make(map[string]string)
		js.Global().Get("Object").Call("entries", userAddedHeaders).Call("forEach", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			userHeaderMap[args[0].Index(0).String()] = args[0].Index(1).String()
			return nil
		}))

		// set the content-type to application/json if it's undefined
		// TODO: If it's a GET request, is this still necessary / appropriate?
		// In the switch statement below, all GET requests are given a body of '{}'. On arrival in the sever, this should actually be `undefined`.
		if _, ok := userHeaderMap["Content-Type"]; !ok {
			if options.Get("body").Call("constructor").Get("name").String() == "FormData" {
				userHeaderMap["Content-Type"] = "multipart/form-data"
			} else {
				userHeaderMap["Content-Type"] = "application/json"
			}
		}

		go func() {
			var res *utils.Response

			switch strings.ToLower(userHeaderMap["Content-Type"]) {
			case "application/json": // Note this is the default that GET requests travel through
				// Converting the body to Golag or setting it as null/nil
				bodyMap := map[string]interface{}{}
				body := options.Get("body")
				if body.String() == "<undefined>" {
					// body = js.ValueOf(map[string]interface{}{}) <= this will err out as "Uncaught (in promise) Error: invalid character '<' looking for beginning of value"
					body = js.ValueOf("{}")
				} else {
					err := json.Unmarshal([]byte(body.String()), &bodyMap)
					if err != nil {
						reject.Invoke(js.Global().Get("Error").New(err.Error()))
						return
					}
				}
				// encode the body to json
				bodyByte, err := json.Marshal(bodyMap)
				if err != nil {
					reject.Invoke(js.Global().Get("Error").New(err.Error()))
					return
				}

				// forward request to the layer8 proxy server
				res = L8Client.Do(
					url, utils.NewRequest(method, userHeaderMap, bodyByte),
					userSymmetricKey, false, UpJWT, UUID)

			case "multipart/form-data":
				userHeaderMap["Content-Type"] = "application/layer8.buffer+json"

				body := options.Get("body")
				if body.String() == "<undefined>" || body.String() == "null" {
					reject.Invoke(js.Global().Get("Error").New("No body provided to fetch call."))
					return
				}

				// get data from formdata
				var (
					dataLength = js.Global().Get("Array").Call("from", body.Call("keys")).Get("length").Int()
					formdata   = make(map[string]interface{}, dataLength)
				)

				js.Global().Get("Array").Call("from", body.Call("keys")).Call("forEach", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
					var (
						key       = args[0].String()
						value     = body.Call("get", key)
						valueType = value.Get("constructor").Get("name").String()
					)

					switch valueType {
					case "File":
						value.Call("arrayBuffer").Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
							buff := make([]byte, value.Get("size").Int())
							js.CopyBytesToGo(buff, js.Global().Get("Uint8Array").New(args[0]))

							data := map[string]interface{}{
								"_type": "File",
								"name":  value.Get("name").String(),
								"size":  value.Get("size").Int(),
								"type":  value.Get("type").String(),
								"buff":  base64.StdEncoding.EncodeToString(buff),
							}

							// because formdata can have multiple entries for the same key
							// each key is an array of maps
							if val, ok := formdata[key]; !ok {
								formdata[key] = []map[string]interface{}{data}
							} else {
								formdata[key] = append(val.([]map[string]interface{}), data)
							}
							return nil
						}))
					case "String":
						data := map[string]interface{}{
							"_type": "String",
							"value": value.String(),
						}

						if val, ok := formdata[key]; !ok {
							formdata[key] = []map[string]interface{}{data}
						} else {
							formdata[key] = append(val.([]map[string]interface{}), data)
						}
					case "Number":
						data := map[string]interface{}{
							"_type": "Number",
							"value": value.Float(),
						}

						if val, ok := formdata[key]; !ok {
							formdata[key] = []map[string]interface{}{data}
						} else {
							formdata[key] = append(val.([]map[string]interface{}), data)
						}
					case "Boolean":
						data := map[string]interface{}{
							"_type": "Boolean",
							"value": value.Bool(),
						}

						if val, ok := formdata[key]; !ok {
							formdata[key] = []map[string]interface{}{data}
						} else {
							formdata[key] = append(val.([]map[string]interface{}), data)
						}
					default:
						reject.Invoke(js.Global().Get("Error").New(fmt.Sprintf("Unsupported type: %s", valueType)))
						return nil
					}

					return nil
				}))

				// wait for the formdata to be populated, this is a hacky way to do it, but it works for now
				// having tried using a channel, it fails with a "fatal error: all goroutines are asleep - deadlock!"
				// TODO: find a better way to do this
				time.Sleep(100 * time.Millisecond)

				// encode the body to json
				bodyByte, err := json.Marshal(formdata)
				if err != nil {
					reject.Invoke(js.Global().Get("Error").New(err.Error()))
					return
				}

				// forward request to the layer8 proxy server
				res = L8Client.Do( // RAVI TODO: Get a single client working again.
					url, utils.NewRequest(method, userHeaderMap, bodyByte),
					userSymmetricKey, false, UpJWT, UUID)
			default:
				res = &utils.Response{
					Status:     400,
					StatusText: "Content-Type not supported",
				}
			}

			if res.Status >= 100 && res.Status < 300 { // Handle Success & Default Rejection
				resHeaders := js.Global().Get("Headers").New()

				for k, v := range res.Headers {
					//fmt.Println("Encrypted Headers from the SP: ", k, v)
					resHeaders.Call("append", js.ValueOf(k), js.ValueOf(v))
				}

				resolve.Invoke(js.Global().Get("Response").New(string(res.Body), js.ValueOf(map[string]interface{}{
					"status":     res.Status,
					"statusText": res.StatusText,
					"headers":    resHeaders,
				})))
				return
			}

			reject.Invoke(js.Global().Get("Error").New(res.StatusText))
			fmt.Printf("[interceptor] fetch status %s. Error txt: %s", res.Status, res.StatusText)
			return
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(promise_logic))
	return promise
}

func getStatic(this js.Value, args []js.Value) interface{} {
	url := args[0].String()

	return js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]

		go func() {
			resp := L8Client.Do(
				url, utils.NewRequest("GET", make(map[string]string), nil),
				userSymmetricKey, true, UpJWT, UUID)

			// convert response body to js arraybuffer
			jsBody := js.Global().Get("Uint8Array").New(len(resp.Body))
			js.CopyBytesToJS(jsBody, resp.Body)

			// create a map of the response headers
			resHeaders := js.Global().Get("Headers").New()
			for k, v := range resp.Headers {
				resHeaders.Call("append", js.ValueOf(k), js.ValueOf(v))
			}

			blob := js.Global().Get("Blob").New([]interface{}{jsBody}, js.ValueOf(map[string]interface{}{
				"type": resHeaders.Call("get", js.ValueOf("content-type")),
			}))
			objURL := js.Global().Get("URL").Call("createObjectURL", blob)

			resolve.Invoke(objURL)
		}()

		return nil
	}))
}
