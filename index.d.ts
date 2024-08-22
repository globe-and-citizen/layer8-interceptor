declare namespace _default {
    export function testWASM(arg: any): Promise<any>;
    export function persistenceCheck(): Promise<any>;
    export function initEncryptedTunnel(...arg: any[]): Promise<any>;
    export function checkEncryptedTunnel(): Promise<any>;
    export function fetch(url: any, ...args: any[]): Promise<any>;
    export function _static(url: any): Promise<any>;
    export { _static as static };
}
export default _default;
