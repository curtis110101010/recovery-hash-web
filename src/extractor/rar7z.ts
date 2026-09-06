import { decompressLzmaRaw } from './lzma-raw'
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
  const nextHeader = bytes.slice(nextHeaderAbsolute, nextHeaderAbsolute + nextHeaderSize)
  let isHeaderEncrypted = false

  if (nextHeader.length > 0) {
    const firstByte = nextHeader[0]
    if (firstByte === 0x01) {
      // kHeader: 普通未压缩头 -> 文件名明文可见，未加密 (Type 1)
      isHeaderEncrypted = false
    } else if (firstByte === 0x17) {
      // kEncodedHeader: 编码（压缩）头。
      // 注意：7-Zip 默认即使未勾选“加密文件名”，也会使用 LZMA 压缩目录结构头（firstByte 为 0x17）。
      // 只有当编码头内部明确包含 AES 编码器 (06 F1 07 01) 时，头部才真正被加密（Type 0）。
      let hasAesInHeader = false
      for (let i = 0; i <= nextHeader.length - 4; i++) {
        if (
          nextHeader[i] === 0x06 &&
          nextHeader[i + 1] === 0xf1 &&
          nextHeader[i + 2] === 0x07 &&
          nextHeader[i + 3] === 0x01
        ) {
          hasAesInHeader = true
          break
        }
      }
      isHeaderEncrypted = hasAesInHeader
    } else {
      // 既不是 0x01 也不是 0x17：整头直接加密的随机字节
      isHeaderEncrypted = true
    }
  }

  // 1. 文件名真正被加密 (Type 0)
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
      blockedReason: '勾选了「加密文件名」的 7z 压缩包 (Type 0)',
      blockedMessage:
        '该 7z 启用了「文件名加密」(Type 0)，整个文件树被 LZMA 压缩并整体加密，无独立校验头。若强行提交 GPU 会导致 CPU 单核 100% 满载软解压而 GPU 饥饿假死。已智能拦截以保护算力。',
      details: '7z (文件名加密 Type 0, 已智能拦截保护算力)',
    }
  }

  // 2. 文件名未加密 (Type 1) - 安全判断阈值控制在 64KB 以下
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

  // 检查加密数据流或文件总大小是否超过 64KB 安全阈值上限
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

  // 3. 文件名未加密且体积在 64KB 安全范围内：浏览器纯前端本地秒级解析提取 Mode 11600 哈希
  return extract7zType1Hash(bytes, nextHeader, fileName)
}


function read7zNumber(bytes: Uint8Array, offset: { val: number }): number {
  if (offset.val >= bytes.length) return 0
  const first = bytes[offset.val++]
  if ((first & 0x80) === 0) return first
  let value = bytes[offset.val++]
  for (let i = 1; i < 8; i++) {
    const mask = 0x80 >> i
    if ((first & mask) === 0) {
      const high = first & (mask - 1)
      value |= high << (i * 8)
      return value
    }
    const next = bytes[offset.val++]
    value |= next << (i * 8)
  }
  return value
}

function readUInt32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  )
}

function extract7zType1Hash(bytes: Uint8Array, nextHeader: Uint8Array, fileName: string): HashPackage {
  let rawHeader = nextHeader

  // 若头部被 LZMA 压缩 (kEncodedHeader = 0x17)，先在前端本地解压出目录头结构
  if (nextHeader.length > 0 && nextHeader[0] === 0x17) {
    const offset = { val: 1 }
    let hdrPackPos = 0
    let hdrPackSize = 0
    let lzmaProps: Uint8Array | null = null
    let hdrUnpackSize = 0

    while (offset.val < nextHeader.length) {
      const id = nextHeader[offset.val++]
      if (id === 0x00) break // kEnd
      if (id === 0x06) {
        // kPackInfo
        hdrPackPos = read7zNumber(nextHeader, offset)
        read7zNumber(nextHeader, offset) // numPackStreams
        while (offset.val < nextHeader.length) {
          const subId = nextHeader[offset.val++]
          if (subId === 0x00) break
          if (subId === 0x09) {
            // kSize
            hdrPackSize = read7zNumber(nextHeader, offset)
          }
        }
      } else if (id === 0x07) {
        // kUnpackInfo
        while (offset.val < nextHeader.length) {
          const subId = nextHeader[offset.val++]
          if (subId === 0x00) break
          if (subId === 0x0b) {
            // kFolder
            read7zNumber(nextHeader, offset) // numFolders
            offset.val++ // external
            const numCoders = read7zNumber(nextHeader, offset)
            for (let i = 0; i < numCoders; i++) {
              const flags = nextHeader[offset.val++]
              const codecIdSize = flags & 0x0f
              const isComplex = (flags & 0x10) !== 0
              const hasAttributes = (flags & 0x20) !== 0
              offset.val += codecIdSize
              if (isComplex) {
                read7zNumber(nextHeader, offset)
                read7zNumber(nextHeader, offset)
              }
              if (hasAttributes) {
                const attrSize = read7zNumber(nextHeader, offset)
                lzmaProps = nextHeader.slice(offset.val, offset.val + attrSize)
                offset.val += attrSize
              }
            }
          } else if (subId === 0x0c) {
            // kCodersUnpackSize
            hdrUnpackSize = read7zNumber(nextHeader, offset)
          } else if (subId === 0x0a) {
            // kCRC
            offset.val += 5
          }
        }
      }
    }

    if (!lzmaProps || lzmaProps.length === 0) {
      throw new Error('未识别的 7z 压缩头属性')
    }

    // 构造标准 13 字节 LZMA Alone Header: [5 字节 LZMA 参数] + [8 字节 64 位解压大小] + [压缩数据]
    const lzmaStream = new Uint8Array(lzmaProps.length + 8 + hdrPackSize)
    lzmaStream.set(lzmaProps, 0)
    const view = new DataView(lzmaStream.buffer, lzmaStream.byteOffset, lzmaStream.byteLength)
    view.setBigUint64(lzmaProps.length, BigInt(hdrUnpackSize), true)
    const compressedData = bytes.slice(32 + hdrPackPos, 32 + hdrPackPos + hdrPackSize)
    lzmaStream.set(compressedData, lzmaProps.length + 8)

    rawHeader = decompressLzmaRaw(lzmaStream)
  }

  // 深度解析 rawHeader 提取 AES-256 加密流与校验信息
  const offset = { val: 1 } // 跳过 0x01 (kHeader)
  let packPos = 0
  let packSize = 0
  let aesCoder: { codecId: Uint8Array; attributes: Uint8Array } | null = null
  let secondCoder: { codecId: Uint8Array; attributes: Uint8Array | null } | null = null
  let aesUnpackSize = 0
  let secondUnpackSize = 0
  let crc = 0

  while (offset.val < rawHeader.length) {
    const id = rawHeader[offset.val++]
    if (id === 0x00) break
    if (id === 0x04) {
      // kMainStreamsInfo
      while (offset.val < rawHeader.length) {
        const subId = rawHeader[offset.val++]
        if (subId === 0x00) break
        if (subId === 0x06) {
          // kPackInfo
          packPos = read7zNumber(rawHeader, offset)
          read7zNumber(rawHeader, offset) // numPackStreams
          while (offset.val < rawHeader.length) {
            const pId = rawHeader[offset.val++]
            if (pId === 0x00) break
            if (pId === 0x09) {
              // kSize
              packSize = read7zNumber(rawHeader, offset)
            }
          }
        } else if (subId === 0x07) {
          // kUnpackInfo
          while (offset.val < rawHeader.length) {
            const uId = rawHeader[offset.val++]
            if (uId === 0x00) break
            if (uId === 0x0b) {
              // kFolder
              read7zNumber(rawHeader, offset) // numFolders
              offset.val++ // external
              const numCoders = read7zNumber(rawHeader, offset)
              for (let i = 0; i < numCoders; i++) {
                const flags = rawHeader[offset.val++]
                const codecIdSize = flags & 0x0f
                const isComplex = (flags & 0x10) !== 0
                const hasAttributes = (flags & 0x20) !== 0
                const codecId = rawHeader.slice(offset.val, offset.val + codecIdSize)
                offset.val += codecIdSize
                if (isComplex) {
                  read7zNumber(rawHeader, offset)
                  read7zNumber(rawHeader, offset)
                }
                let attributes: Uint8Array | null = null
                if (hasAttributes) {
                  const attrSize = read7zNumber(rawHeader, offset)
                  attributes = rawHeader.slice(offset.val, offset.val + attrSize)
                  offset.val += attrSize
                }
                const isAes =
                  codecId.length === 4 &&
                  codecId[0] === 0x06 &&
                  codecId[1] === 0xf1 &&
                  codecId[2] === 0x07 &&
                  codecId[3] === 0x01

                if (isAes) {
                  aesCoder = { codecId, attributes: attributes || new Uint8Array(0) }
                } else {
                  secondCoder = { codecId, attributes }
                }
              }
              const numBindPairs = numCoders - 1
              for (let i = 0; i < numBindPairs; i++) {
                read7zNumber(rawHeader, offset)
                read7zNumber(rawHeader, offset)
              }
            } else if (uId === 0x0c) {
              // kCodersUnpackSize
              aesUnpackSize = read7zNumber(rawHeader, offset)
              secondUnpackSize = read7zNumber(rawHeader, offset)
            }
          }
        } else if (subId === 0x08) {
          // kSubStreamsInfo
          while (offset.val < rawHeader.length) {
            const sId = rawHeader[offset.val++]
            if (sId === 0x00) break
            if (sId === 0x0a) {
              // kCRC
              const allDef = rawHeader[offset.val++]
              if (allDef === 0x01 || allDef === 0x00) {
                crc = readUInt32LE(rawHeader, offset.val)
                offset.val += 4
              }
            }
          }
        }
      }
    }
  }

  if (!aesCoder || !aesCoder.attributes || aesCoder.attributes.length === 0) {
    throw new Error('该 7z 压缩包未设置密码或未检测到 AES 加密流')
  }

  // 解码 AES 属性 (Cycles, Salt, IV)
  const attr = aesCoder.attributes
  const firstByte = attr[0]
  const numCyclesPower = firstByte & 0x3f
  let saltLen = (firstByte >> 7) & 1
  let ivLen = (firstByte >> 6) & 1
  let aOff = 1
  if ((firstByte & 0xc0) !== 0) {
    const secondByte = attr[1]
    aOff++
    saltLen += secondByte >> 4
    ivLen += secondByte & 0x0f
  }
  const saltBuf = attr.slice(aOff, aOff + saltLen)
  aOff += saltLen
  let ivBuf = attr.slice(aOff, aOff + ivLen)
  if (ivBuf.length < 16) {
    const padded = new Uint8Array(16)
    padded.set(ivBuf)
    ivBuf = padded
  }

  // 截取加密数据流
  const encData = bytes.slice(32 + packPos, 32 + packPos + packSize)

  // 压缩算法类型识别与 Coder Attributes
  let dataType = 0
  let coderAttrs = ''
  if (secondCoder) {
    if (
      secondCoder.codecId.length === 3 &&
      secondCoder.codecId[0] === 0x03 &&
      secondCoder.codecId[1] === 0x01 &&
      secondCoder.codecId[2] === 0x01
    ) {
      dataType = 1 // LZMA1
    } else if (secondCoder.codecId.length === 1 && secondCoder.codecId[0] === 0x21) {
      dataType = 2 // LZMA2
    } else if (
      secondCoder.codecId.length === 3 &&
      secondCoder.codecId[0] === 0x03 &&
      secondCoder.codecId[1] === 0x04 &&
      secondCoder.codecId[2] === 0x01
    ) {
      dataType = 3 // PPMD
    } else if (
      secondCoder.codecId.length === 3 &&
      secondCoder.codecId[0] === 0x04 &&
      secondCoder.codecId[1] === 0x02 &&
      secondCoder.codecId[2] === 0x02
    ) {
      dataType = 6 // BZIP2
    } else if (
      secondCoder.codecId.length === 3 &&
      secondCoder.codecId[0] === 0x04 &&
      secondCoder.codecId[1] === 0x01 &&
      secondCoder.codecId[2] === 0x08
    ) {
      dataType = 7 // DEFLATE
    }

    if (secondCoder.attributes) {
      coderAttrs = bufToHex(secondCoder.attributes)
    }
  }

  // 生成与 Hashcat Mode 11600 完全对齐的标准哈希串
  let hashString = ''
  if (dataType === 0) {
    hashString = `$7z$0$${numCyclesPower}$${saltLen}$${bufToHex(saltBuf)}$${ivBuf.length}$${bufToHex(ivBuf)}$${crc}$${packSize}$${aesUnpackSize}$${bufToHex(encData)}`
  } else {
    hashString = `$7z$${dataType}$${numCyclesPower}$${saltLen}$${bufToHex(saltBuf)}$${ivBuf.length}$${bufToHex(ivBuf)}$${crc}$${packSize}$${aesUnpackSize}$${bufToHex(encData)}$${secondUnpackSize}$${coderAttrs}`
  }

  const codecName = dataType === 2 ? 'LZMA2' : dataType === 1 ? 'LZMA1' : dataType === 0 ? 'Store' : 'Compressed'

  return {
    format: 'file-password-recovery-hash',
    version: 1,
    sourceName: fileName,
    sourceType: '7z',
    hashMode: 11600,
    hash: hashString,
    status: 'ok',
    details: `7z (AES-256 + ${codecName}, Mode 11600)`,
    metadata: {
      cycles: 1 << numCyclesPower,
      saltLen,
      ivLen: ivBuf.length,
      crc,
      packSize,
      aesUnpackSize,
      secondUnpackSize,
    },
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
