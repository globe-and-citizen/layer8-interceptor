// IMPORTS
import wasmBin from "./dist/interceptor.json";
import "./dist/wasm_exec.js";

// GLOBALS
let l8Ready = false;
let callbackObjectArray = [];

// UTILITY FUNCS
const decode = (encoded) => {
  var str = atob(encoded);
  var bytes = new Uint8Array(str.length);
  for (var i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes.buffer;
};

function illGetBackToYou(_name, _resolve, _reject, _args) {
  callbackObjectArray.push({
    name: _name,
    resolve: _resolve,
    reject: _reject,
    args: _args,
  });
}

function triggerCallbacks() {
  callbackObjectArray.forEach(async (callbackObject, _idx, _arr) => {
    const name = callbackObject.name;
    const resolve = callbackObject.resolve;
    const reject = callbackObject.reject;
    const args = callbackObject.args;

    switch (name) {
      case "testWASM":
        try {
          resolve(await layer8.testWASM(...args));
        } catch (error) {
          reject(`Call to Layer8.${name} failed: ${error}`);
        }
        break;
      case "persistenceCheck":
        try {
          resolve(await layer8.persistenceCheck());
        } catch (error) {
          initEncryptedTunnel;
          reject(`Call to Layer8.${name} failed: ${error}`);
        }
        break;
      case "initEncryptedTunnel":
        try {
          resolve(await layer8.initEncryptedTunnel(...args));
        } catch (error) {
          reject(`Call to Layer8.${name} failed: ${error}`);
        }
        break;
      case "checkEncryptedTunnel":
        try {
          resolve(await layer8.checkEncryptedTunnel())
        } catch (error){
          reject(`Call to Layer8.${name} failed: ${error}`);
        }
      case "fetch":
        try {
          resolve(await layer8.fetch(...args));
        } catch (error) {
          reject(`Call to Layer8.${name} failed: ${error}`);
        }
        break;
      case "static":
        try{
          resolve(await layer8.static(...args));
        } catch(error){
          reject(`Call to Layer8.${name} failed: ${erorr}`);
        }
      default:
      // code block
    }
  });
}

// MODULE LOAD & INITIAZLIZE
const go = new Go();
const importObject = go.importObject;
WebAssembly.instantiate(decode(wasmBin), importObject).then((result) => {
  go.run(result.instance);
  l8Ready = true;
  triggerCallbacks();
});

// EXPORTS
export default {
  testWASM: (arg) => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        resolve(await layer8.testWASM(arg));
      } else {
        illGetBackToYou("testWASM", resolve, reject, [arg]);
      }
    });
  },
  persistenceCheck: () => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        resolve(await layer8.persistenceCheck());
      } else {
        illGetBackToYou("persistenceCheck", resolve, reject, null);
      }
    });
  },
  initEncryptedTunnel: (...arg) => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        resolve(await layer8.initEncryptedTunnel(...arg));
      } else {
        illGetBackToYou("initEncryptedTunnel", resolve, reject, [...arg]);
      }
    });
  },
  checkEncryptedTunnel: () => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        resolve(await layer8.checkEncryptedTunnel());
      } else {
        illGetBackToYou("checkEncryptedTunnel", resolve, reject, null);
      }
    })
  },
  fetch: (url, config = null) => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        if (config == null) {
          resolve(await layer8.fetch(url));
        } else {
          resolve(await layer8.fetch(url, config));
        }
      } else {
        if (config == null) {
          illGetBackToYou("fetch", resolve, reject, [url]);
        } else {
          illGetBackToYou("fetch", resolve, reject, [url, config]);
        }
      }
    });
  },
  static: (url) => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready){
        resolve(await layer8.static(url))
      } else {
        illGetBackToYou("static", resolve, reject, [url])
      }
    })
  }
};
