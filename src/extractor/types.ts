export interface HashPackage {
  format: 'file-password-recovery-hash'
  version: number
  sourceName: string
  sourceType: string
  hashMode: number
  hash: string
  status: 'ok' | 'blocked' | 'error'
  blockedCode?: string
  blockedReason?: string
  blockedMessage?: string
  blockedDetails?: string
  details?: string
  metadata?: Record<string, any>
}

export interface ExtractionOptions {
  pdfTarget?: 'open' | 'permission'
  officeTarget?: 'open' | 'permission'
  forceFullHash?: boolean
}

// 7z 全量哈希文件的体积安全阈值上限 64KB
export const HASH_7Z_BLOCK_MAX_BYTES = 64 * 1024
export const HASH_7Z_MAX_HASH_BYTES = 64 * 1024
export const MICRO_HASH_MAX_BYTES = 1024

export function bufToHex(buffer: Uint8Array | ArrayBuffer): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function hexToBuf(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '')
  const bytes = new Uint8Array(cleanHex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16)
  }
  return bytes
}

export function base64ToHex(b64: string): string {
  const binary = atob(b64.trim())
  let hex = ''
  for (let i = 0; i < binary.length; i++) {
    hex += binary.charCodeAt(i).toString(16).padStart(2, '0')
  }
  return hex
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim())
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
