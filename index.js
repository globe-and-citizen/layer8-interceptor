import './wasm_exec.js';
import { wasm_url} from './config.json'

let l8Ready = false;
let callbackObjectArray = [];
let layer8;

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


const go = new Go();
WebAssembly.instantiateStreaming(fetch(wasm_url), go.importObject).
then((result) => {
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
