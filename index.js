// const _ = require("./dist/wasm_exec.js");
// const wasmBin = require("./dist/interceptor.json");

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

function illGetBackToYou(_func, _resolve, _reject, _args) {
  callbackObjectArray.push({
    func: _func,
    resolve: _resolve,
    reject: _reject,
    args: _args,
  });
}

function triggerCallbacks() {
  callbackObjectArray.forEach(async (callbackObject, _idx, _arr) => {
    const name = callbackObject.func.name;
    const func = callbackObject.func;
    const resolve = callbackObject.resolve;
    const reject = callbackObject.reject;
    const args = callbackObject.args || [];

    try {
      resolve(await func(...args));
    } catch (error) {
      reject(`Call to Layer8.${name} failed: ${error}`);
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
        illGetBackToYou(layer8.testWASM, resolve, reject, [arg]);
      }
    });
  },
  persistenceCheck: () => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        resolve(await layer8.persistenceCheck());
      } else {
        illGetBackToYou(layer8.persistenceCheck, resolve, reject, null);
      }
    });
  },
  initEncryptedTunnel: (...arg) => {
    return new Promise(async (resolve, reject) => {
      if (l8Ready) {
        resolve(await layer8.initEncryptedTunnel(...arg));
      } else {
        illGetBackToYou(layer8.initEncryptedTunnel, resolve, reject, [...arg]);
      }
    });
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
          illGetBackToYou(layer8.fetch, resolve, reject, [url]);
        } else {
          illGetBackToYou(layer8.fetch, resolve, reject, [url, config]);
        }
      }
    });
  },
};
