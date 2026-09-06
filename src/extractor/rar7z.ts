import { bufToHex, HASH_7Z_BLOCK_MAX_BYTES } from './types'
import type { HashPackage } from './types'

export function inspectRarOr7z(buffer: ArrayBuffer, fileName: string): HashPackage {
  const bytes = new Uint8Array(buffer)

  // 1. Check 7z signature: 37 7a bc af 27 1c
  if (
    bytes.length >= 6 &&
    bytes[0] === 0x37 &&
    bytes[1] === 0x7a &&
    bytes[2] === 0xbc &&
    bytes[3] === 0xaf &&
    bytes[4] === 0x27 &&
    bytes[5] === 0x1c
  ) {
    return parse7z(bytes, fileName)
  }

  // 2. Check RAR5 signature: 52 61 72 21 1a 07 01 00
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x72 &&
    bytes[3] === 0x21 &&
    bytes[4] === 0x1a &&
    bytes[5] === 0x07 &&
    bytes[6] === 0x01 &&
    bytes[7] === 0x00
  ) {
    return parseRar5(bytes, fileName)
  }

  // 3. Check RAR4 signature: 52 61 72 21 1a 07 00
  if (
    bytes.length >= 7 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x72 &&
    bytes[3] === 0x21 &&
    bytes[4] === 0x1a &&
    bytes[5] === 0x07 &&
    bytes[6] === 0x00
  ) {
    return parseRar4(fileName)
  }

  throw new Error('未识别的压缩格式或非 RAR/7z 文件')
}

function parse7z(bytes: Uint8Array, fileName: string): HashPackage {
  if (bytes.length < 32) {
    throw new Error('7z 文件头过短损坏')
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const nextHeaderOffset = Number(view.getBigUint64(12, true))
  const nextHeaderSize = Number(view.getBigUint64(20, true))

  const nextHeaderAbsolute = 32 + nextHeaderOffset
  let isHeaderEncrypted = false

  if (nextHeaderAbsolute >= 0 && nextHeaderAbsolute < bytes.length) {
    const firstByte = bytes[nextHeaderAbsolute]
    if (firstByte === 0x17) {
      // kEncodedHeader: Header itself is encrypted (Type 0)
      isHeaderEncrypted = true
    }
  }

  if (isHeaderEncrypted) {
    return {
      format: 'file-password-recovery-hash',
      version: 1,
      sourceName: fileName,
      sourceType: '7z',
      hashMode: 11600,
      hash: '',
      status: 'blocked',
      blockedCode: '7Z_HEADER_ENCRYPTED_TRAP',
      blockedReason: '勾选了「加密文件名」的 7z 压缩包',
      blockedMessage:
        '该 7z 启用了「文件名加密」(Type 0)，整个文件树被 LZMA 压缩并整体加密，无独立校验头。若强行提交 GPU 会导致 CPU 单核 100% 满载软解压而 GPU 饥饿假死。已智能拦截保护算力。',
      details: '7z (文件名加密 Type 0, 已智能拦截保护算力)',
    }
  }

  // 安全判断阈值：7z 头部或加密块超过 64KB 严格拦截
  if (nextHeaderSize > HASH_7Z_BLOCK_MAX_BYTES) {
    return {
      format: 'file-password-recovery-hash',
      version: 1,
      sourceName: fileName,
      sourceType: '7z',
      hashMode: 11600,
      hash: '',
      status: 'blocked',
      blockedCode: '7Z_HEADER_EXCEEDS_64KB',
      blockedReason: '7z 头部数据块超过 64KB 安全上限',
      blockedMessage: `该 7z 头部数据块大小为 ${(nextHeaderSize / 1024).toFixed(1)}KB，超过了 64KB 安全阈值上限。全量流式解压会导致 GPU 严重饥饿与 CPU 假死。`,
      details: `7z (头部数据块 ${(nextHeaderSize / 1024).toFixed(1)}KB > 64KB)`,
    }
  }

  // 检查是否超过 64KB 安全阈值上限
  if (bytes.length > HASH_7Z_BLOCK_MAX_BYTES) {
    return {
      format: 'file-password-recovery-hash',
      version: 1,
      sourceName: fileName,
      sourceType: '7z',
      hashMode: 11600,
      hash: '',
      status: 'blocked',
      blockedCode: '7Z_STREAM_EXCEEDS_64KB',
      blockedReason: '7z 加密数据流超过 64KB 安全上限',
      blockedMessage: `该 7z 加密文件体积为 ${(bytes.length / 1024).toFixed(1)}KB，超过了全量哈希 64KB 安全阈值上限。crc_len / unpack_size 覆盖整条大文件数据流且无中间校验点，必须完整解密解压全部流式数据才能得出 CRC32，已智能拦截以保护 GPU 算力。`,
      details: `7z (加密数据流 ${(bytes.length / 1024).toFixed(1)}KB > 64KB)`,
    }
  }

  // Search for AES coder identifier: 06 F1 07 01
  let foundAes = false
  for (let i = 32; i < Math.min(bytes.length - 4, 1024 * 1024); i++) {
    if (bytes[i] === 0x06 && bytes[i + 1] === 0xf1 && bytes[i + 2] === 0x07 && bytes[i + 3] === 0x01) {
      foundAes = true
      break
    }
  }

  if (!foundAes) {
    throw new Error('该 7z 文件未检测到 AES 加密数据流')
  }

  return {
    format: 'file-password-recovery-hash',
    version: 1,
    sourceName: fileName,
    sourceType: '7z',
    hashMode: 11600,
    hash: '',
    status: 'blocked',
    blockedCode: '7Z_STREAM_CLIENT_EXTRACT',
    blockedReason: '7z 数据流解密需要专用解析器',
    blockedMessage:
      '7z 数据流加密 (Type 1, Mode 11600) 全量哈希体积严格控制在 64KB 以下。建议通过配套的「桌面版恢复哈希提取工具」快速提取轻量哈希。',
    details: '7z (数据流加密 Type 1, Mode 11600, 符合64KB阈值)',
  }
}

function parseRar5(bytes: Uint8Array, fileName: string): HashPackage {
  // RAR5 header block parsing
  let offset = 8 // skip RAR5 signature
  let foundEnc = false

  while (offset + 4 < bytes.length) {
    // Read header CRC (4 bytes)
    offset += 4

    // Read header size (vint)
    const [headerSize, vintLen] = readVint(bytes, offset)
    offset += vintLen
    const headerStart = offset
    const headerEnd = headerStart + headerSize

    if (headerEnd > bytes.length) break

    // Read header type (vint)
    const [headerType, typeLen] = readVint(bytes, offset)
    offset += typeLen

    // Read header flags (vint)
    const [, flagsLen] = readVint(bytes, offset)
    offset += flagsLen

    if (headerType === 4) {
      // Archive encryption header (Type 4)
      foundEnc = true
      const [, verLen] = readVint(bytes, offset)
      offset += verLen
      const [, encFlagsLen] = readVint(bytes, offset)
      offset += encFlagsLen

      const kdfCount = bytes[offset]
      offset += 1
      const salt = bytes.slice(offset, offset + 16)
      offset += 16
      const checkVal = bytes.slice(offset, offset + 12)

      const saltHex = bufToHex(salt)
      const checkHex = bufToHex(checkVal)

      const rar5Hash = `$rar5$16$${saltHex}$${kdfCount}$${checkHex}$0`

      return {
        format: 'file-password-recovery-hash',
        version: 1,
        sourceName: fileName,
        sourceType: 'rar',
        hashMode: 13000,
        hash: rar5Hash,
        status: 'ok',
        details: 'RAR5 (原生 PBKDF2-HMAC-SHA256, Mode 13000)',
        metadata: {
          rarVersion: 5,
          kdfCount,
          saltHex,
        },
      }
    }

    offset = headerEnd
  }

  if (!foundEnc) {
    throw new Error('该 RAR5 压缩包未发现主加密头，请使用桌面端提取器')
  }

  throw new Error('未能从 RAR5 中提取有效哈希')
}

function parseRar4(fileName: string): HashPackage {
  return {
    format: 'file-password-recovery-hash',
    version: 1,
    sourceName: fileName,
    sourceType: 'rar',
    hashMode: 12500,
    hash: '',
    status: 'blocked',
    blockedCode: 'RAR4_LOCAL_CLIENT_EXTRACT',
    blockedReason: '旧版 RAR3/RAR4 建议使用本地提取器',
    blockedMessage: '旧版 RAR 格式 (Mode 12500) 请直接使用桌面版恢复哈希提取工具导出。',
    details: 'RAR4 (旧版 RAR 算法, Mode 12500)',
  }
}

function readVint(bytes: Uint8Array, offset: number): [number, number] {
  let val = 0
  let shift = 0
  let len = 0
  while (offset + len < bytes.length && len < 8) {
    const b = bytes[offset + len]
    len++
    val |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) break
    shift += 7
  }
  return [val, len]
}
