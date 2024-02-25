package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"globe-and-citizen/layer8-interceptor/internals"
	"os"
	"time"

	"net/http"
	"net/url"
	"strings"
	"syscall/js"

	utils "github.com/globe-and-citizen/layer8-utils"

	uuid "github.com/google/uuid"
)

// Declare global constants
const INTERCEPTOR_VERSION = "0.0.14"

// Declare global variables
var (
	Layer8LightsailURL  string
	Counter             int
	EncryptedTunnelFlag bool
	privJWK_ecdh        *utils.JWK
	pubJWK_ecdh         *utils.JWK
	userSymmetricKey    *utils.JWK
	UpJWT               string
	UUID                string
	L8Clients           map[string]internals.ClientImpl = make(map[string]internals.ClientImpl)
)

/*
	//var L8Client = internals.NewClient(Layer8Scheme, Layer8Host, Layer8Port) // Ravi TODO this should probably be revisited
*/

func main() {
	// Create channel to keep the Go thread alive
	c := make(chan struct{})

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

func getHost(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	res := p.Scheme + "://" + p.Hostname()
	if p.Port() != "" {
		res = res + ":" + p.Port()
	}
	return res, nil
}

func initializeECDHTunnel(this js.Value, args []js.Value) interface{} {
	// Convert JS values into useable Golang variables
	var (
		providers []string
		proxy     string = "https://layer8devproxy.net" // set LAYER8_PROXY in the environment to override
		mode      string = "prod"
	)
	if len(args) > 1 {
		mode = args[1].String()
	}

	ErrorDestructuringConfigObject := false

	js.Global().Get("Object").Call("entries", args[0]).Call("forEach", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		key := args[0].Index(0).String()

		switch key {
		case "providers":
			providers = make([]string, args[0].Index(1).Length())
			for i := 0; i < args[0].Index(1).Get("length").Int(); i++ {
				providers[i] = args[0].Index(1).Index(i).String()
			}
		case "proxy":
			if mode == "dev" {
				proxy = args[0].Index(1).String()
			} else {
				if os.Getenv("LAYER8_PROXY") != "" {
					proxy = os.Getenv("LAYER8_PROXY")
				}
			}
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

		initTunnel := func(provider string) {
			// parse the provider URL to maintain a pattern of scheme://host:port
			// in the L8Clients map
			provider, err := getHost(provider)
			if err != nil {
				fmt.Println("[Interceptor]", err.Error())
				EncryptedTunnelFlag = false
				reject.Invoke(js.Global().Get("Error").New("Unable to parse the provider URL. "))
				return
			}

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

			proxy = fmt.Sprintf("%s/init-tunnel?backend=%s", proxy, provider)

			client := &http.Client{}
			req, err := http.NewRequest("POST", proxy, bytes.NewBuffer([]byte(b64PubJWK)))
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
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				EncryptedTunnelFlag = false
				return
			}
			port := proxyURL.Port()
			if port == "" {
				if proxyURL.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			L8Clients[provider] = internals.NewClient(proxyURL.Scheme, proxyURL.Hostname(), port)
			fmt.Printf("[%s] Encrypted tunnel successfully established.\n", provider)
			resolve.Invoke(true)
			return
		}

		for _, provider := range providers {
			go initTunnel(provider)
		}

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

		spURL := args[0].String()
		if len(spURL) <= 0 {
			reject.Invoke(js.Global().Get("Error").New("Invalid URL provided to fetch call."))
			return nil
		}

		options := js.ValueOf(map[string]interface{}{
			"method":  "GET", // Set HTTP "GET" request to be the default
			"headers": js.ValueOf(map[string]interface{}{}),
			"body":    js.ValueOf("<undefined>"),
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
			body := options.Get("body")
			if body.String() != "<undefined>" && body.Get("constructor").Get("name").String() == "FormData" {
				userHeaderMap["Content-Type"] = "multipart/form-data"
			} else {
				userHeaderMap["Content-Type"] = "application/json"
			}
		}

		host, err := getHost(spURL)
		if err != nil {
			reject.Invoke(js.Global().Get("Error").New(err.Error()))
			return nil
		}
		client := L8Clients[host]

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
				res = client.Do(
					spURL, utils.NewRequest(method, userHeaderMap, bodyByte),
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
				res = client.Do( // RAVI TODO: Get a single client working again.
					spURL, utils.NewRequest(method, userHeaderMap, bodyByte),
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
			fmt.Printf("[interceptor] fetch status %d. Error txt: %s", res.Status, res.StatusText)
			return
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(promise_logic))
	return promise
}

func getStatic(this js.Value, args []js.Value) interface{} {
	spURL := args[0].String()

	return js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		pURL, err := url.Parse(spURL)
		if err != nil {
			reject.Invoke(js.Global().Get("Error").New(err.Error()))
			return nil
		}
		client := L8Clients[pURL.Scheme+"://"+pURL.Host]

		// using indexDB to cache the static files
		openDB := func() js.Value {
			// open the indexedDB
			db := js.Global().Get("indexedDB").Call("open", "__layer8_cache")
			db.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				reject.Invoke(js.Global().Get("Error").New(
					"Please enable IndexedDB in your browser or update your browser to the latest version."))
				return nil
			}))
			// create the object store
			db.Set("onupgradeneeded", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				db := args[0].Get("target").Get("result")
				store := db.Call("createObjectStore", "static", js.ValueOf(map[string]interface{}{
					"keyPath": "url",
				}))
				store.Call("createIndex", "url", "url", js.ValueOf(map[string]interface{}{
					"unique": true,
				}))
				return nil
			}))
			return db
		}

		// fetch the static file from the server and store it in the cache
		fetchStatic := func() {
			resp := client.Do(
				spURL, utils.NewRequest("GET", make(map[string]string), nil),
				userSymmetricKey, true, UpJWT, UUID)

			// convert response body to js arraybuffer
			jsBody := js.Global().Get("Uint8Array").New(len(resp.Body))
			js.CopyBytesToJS(jsBody, resp.Body)

			// create a map of the response headers
			resHeaders := js.Global().Get("Headers").New()
			for k, v := range resp.Headers {
				resHeaders.Call("append", js.ValueOf(k), js.ValueOf(v))
			}

			fileType := resHeaders.Call("get", js.ValueOf("content-type"))

			// store the file in the cache
			db := openDB()
			db.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				db := args[0].Get("target").Get("result")
				tx := db.Call("transaction", "static", "readwrite")
				store := tx.Call("objectStore", "static")
				store.Call("put", js.ValueOf(map[string]interface{}{
					"url":  spURL,
					"body": jsBody,
					"type": fileType,
				}))
				return nil
			}))

			// convert the response body to a blob and resolve the promise
			blob := js.Global().Get("Blob").New([]interface{}{jsBody}, js.ValueOf(map[string]interface{}{
				"type": fileType,
			}))
			objURL := js.Global().Get("URL").Call("createObjectURL", blob)
			resolve.Invoke(objURL)
		}

		// check if the file is in the cache
		db := openDB()
		db.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			db := args[0].Get("target").Get("result")
			tx := db.Call("transaction", "static", "readonly")
			store := tx.Call("objectStore", "static")
			index := store.Call("index", "url")
			req := index.Call("get", spURL)
			req.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				if req.Get("result").IsUndefined() {
					// if the file is not in the cache, fetch it from the server
					go fetchStatic()
				} else {
					data := req.Get("result")
					blob := js.Global().Get("Blob").New([]interface{}{js.ValueOf(data.Get("body"))}, js.ValueOf(map[string]interface{}{
						"type": data.Get("type"),
					}))
					objURL := js.Global().Get("URL").Call("createObjectURL", blob)
					resolve.Invoke(objURL)
				}
				return nil
			}))
			return nil
		}))

		return nil
	}))
}
