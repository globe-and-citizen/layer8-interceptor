// IMPORTS
import wasmBin from "./dist/interceptor.json";
import "./dist/wasm_exec.js";

// GLOBALS
let l8Ready = false;
let callbackObjectArray = [];
let layer8;

// UTILITY FUNCS
const decode = (encoded) => {
  var str = atob(encoded);
  var bytes = new Uint8Array(str.length);
  for (var i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes.buffer;
};

function illGetBackToYou(_func_name, _resolve, _reject, _args) {
  callbackObjectArray.push({
    func_name: _func_name,
    resolve: _resolve,
    reject: _reject,
    args: _args,
  });
}

function triggerCallbacks() {
  callbackObjectArray.forEach(async (callbackObject) => {
    const func = callbackObject.func_name.split(".").reduce((acc, cur) => acc[cur], window);
    const resolve = callbackObject.resolve;
    const reject = callbackObject.reject;
    const args = callbackObject.args;

    try {
      resolve(await func(...args));
    } catch (error) {
      reject(`Call to Layer8.${func.name} failed: ${error}`);
    }
  });
}

// MODULE LOAD & INITIAZLIZE
const go = new window.Go();
const importObject = go.importObject;
WebAssembly.instantiate(decode(wasmBin), importObject).then((result) => {
  go.run(result.instance);
  l8Ready = true;
  layer8 = window.layer8;
  triggerCallbacks();
});

// EXPORTS
export default {
  testWASM: async (arg) => {
    if (l8Ready) {
      return await layer8.testWASM(arg);
    }
    return new Promise((resolve, reject) => {
      illGetBackToYou("layer8.testWASM", resolve, reject, [arg]);
    })
  },
  persistenceCheck: async () => {
    if (l8Ready) {
      return await layer8.persistenceCheck();
    }
    return new Promise((resolve, reject) => {
      illGetBackToYou("layer8.persistenceCheck", resolve, reject, null);
    })
  },
  initEncryptedTunnel: async (...arg) => {
    if (l8Ready) {
      return await layer8.initEncryptedTunnel(...arg);
    }
    return new Promise((resolve, reject) => {
      illGetBackToYou("layer8.initEncryptedTunnel", resolve, reject, [...arg]);
    })
  },
  checkEncryptedTunnel: async () => {
    if (l8Ready) {
      return await layer8.checkEncryptedTunnel();
    }
    return new Promise((resolve, reject) => {
      illGetBackToYou("layer8.checkEncryptedTunnel", resolve, reject, null);
    })
  },
  fetch: async (url, ...args) => {
    if (l8Ready) {
      return await layer8.fetch(url, ...args);
    }
    return new Promise((resolve, reject) => {
      illGetBackToYou("layer8.fetch", resolve, reject, [url, ...args]);
    })
  },
  static: async (url) => {
    if (l8Ready) {
      return await layer8.static(url);
    }
    return new Promise((resolve, reject) => {
      illGetBackToYou("layer8.static", resolve, reject, [url]);
    })
  }
};
