
export class Layer8Config {
    ServiceProviderURL: string;
    Layer8Scheme: string;
    Layer8Host: string;
    Layer8Port: string;
}

export interface Layer8 {
    testWASM(arg: any): Promise<any>,
    persistenceCheck(): Promise<any>,
    initEncryptedTunnel(config: Layer8Config): Promise<any>,
    static(url: string): Promise<string>,
    fetch(input: RequestInfo | URL, init?: RequestInit | undefined): Promise<Response>
}

