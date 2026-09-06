/// <reference types="vite/client" />

declare module 'lzma' {
  const lzma: any
  export default lzma
  export const decompress: any
  export const compress: any
}

declare module 'lzma/src/lzma-d.js' {
  const lzma: any
  export const LZMA: any
  export const LZMA_WORKER: any
  export default lzma
}

