declare module 'node:fs' {
  export const createReadStream: (...args: any[]) => any;
  export const createWriteStream: (...args: any[]) => any;
}

declare module 'node:fs/promises' {
  export const mkdir: (...args: any[]) => Promise<any>;
  export const open: (...args: any[]) => Promise<any>;
  export const opendir: (...args: any[]) => Promise<AsyncIterable<any>>;
  export const readdir: (...args: any[]) => Promise<any[]>;
  export const readFile: (...args: any[]) => Promise<any>;
  export const rename: (...args: any[]) => Promise<any>;
  export const rm: (...args: any[]) => Promise<any>;
  export const stat: (...args: any[]) => Promise<any>;
  export const writeFile: (...args: any[]) => Promise<any>;
}

declare module 'node:http' {
  export const createServer: (...args: any[]) => any;
}

declare module 'node:https' {
  export const createServer: (...args: any[]) => any;
}

declare module 'node:path' {
  export const dirname: (path: string) => string;
  export const join: (...parts: string[]) => string;
}

declare module 'node:stream' {
  export class Readable {
    static fromWeb(stream: ReadableStream<Uint8Array>): any;
    static toWeb(stream: any): ReadableStream<Uint8Array>;
  }
}

declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string);
    exec(sql: string): void;
    prepare(sql: string): {
      get(...parameters: unknown[]): unknown;
      all(...parameters: unknown[]): unknown;
      run(...parameters: unknown[]): unknown;
    };
    close(): void;
  }
}

declare const process: any;
