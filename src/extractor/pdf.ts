import { bufToHex } from './types'
import type { HashPackage } from './types'
import { md5, rc4, sha256 } from './crypto'

const PDF_PADDING = new Uint8Array([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
  0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
])

/**
 * 依据 ISO 32000-1 规范校验 PDF 打开密码是否为空字符串 \"\"。
 * 若校验通过，说明文档任何人无需密码即可直接打开阅读。
 */
function isPdfUserPasswordEmpty(
  revision: number,
  keyBits: number,
  permissions: number,
  encryptMetadata: number,
  documentIdBytes: Uint8Array,
  oBytes: Uint8Array | null,
  uBytes: Uint8Array | null
): boolean {
  if (!uBytes || !oBytes) return false

  if (revision <= 4) {
    const keyLen = revision <= 2 ? 5 : Math.floor(keyBits / 8)
    const pDv = new DataView(new ArrayBuffer(4))
    pDv.setInt32(0, permissions, true)
    const pBytes = new Uint8Array(pDv.buffer)

    // Algorithm 2: Compute key for empty user password
    const parts = [PDF_PADDING, oBytes, pBytes, documentIdBytes]
    if (revision >= 4 && encryptMetadata === 0) {
      parts.push(new Uint8Array([0xff, 0xff, 0xff, 0xff]))
    }
    const totalLen = parts.reduce((acc, p) => acc + p.length, 0)
    const combined = new Uint8Array(totalLen)
    let pos = 0
    for (const part of parts) {
      combined.set(part, pos)
      pos += part.length
    }

    let digest = md5(combined)
    if (revision >= 3) {
      for (let i = 0; i < 50; i++) {
        digest = md5(digest.slice(0, keyLen))
      }
    }
    const key = digest.slice(0, keyLen)

    // Algorithm 6 / 7: Authenticating user password
    if (revision <= 2) {
      if (uBytes.length < 32) return false
      const res = rc4(key, PDF_PADDING)
      for (let i = 0; i < 32; i++) {
        if (res[i] !== uBytes[i]) return false
      }
      return true
    } else {
      if (uBytes.length < 16) return false
      const parts2 = new Uint8Array(PDF_PADDING.length + documentIdBytes.length)
      parts2.set(PDF_PADDING, 0)
      parts2.set(documentIdBytes, PDF_PADDING.length)
      let out = rc4(key, md5(parts2))
      for (let i = 1; i <= 19; i++) {
        const ki = new Uint8Array(key.length)
        for (let j = 0; j < key.length; j++) ki[j] = key[j] ^ i
        out = rc4(ki, out)
      }
      for (let i = 0; i < 16; i++) {
        if (out[i] !== uBytes[i]) return false
      }
      return true
    }
  }

  // Revision 5 (AES-256): U has 48 bytes (32 hash + 8 validation salt + 8 key salt)
  if (revision === 5 && uBytes.length >= 40) {
    const validationSalt = uBytes.slice(32, 40)
    const expected = sha256(validationSalt)
    for (let i = 0; i < 32; i++) {
      if (expected[i] !== uBytes[i]) return false
    }
    return true
  }

  return false
}

function decodePdfString(raw: string): Uint8Array {
  const trimmed = raw.trim()
  // Hex string: <4E6F77>
  if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
    const hex = trimmed.slice(1, -1).replace(/\s+/g, '')
    const padded = hex.length % 2 !== 0 ? hex + '0' : hex
    const bytes = new Uint8Array(padded.length / 2)
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(padded.substr(i * 2, 2), 16)
    }
    return bytes
  }

  // Literal string: (...)
  if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
    const content = trimmed.slice(1, -1)
    const bytes: number[] = []
    let i = 0
    while (i < content.length) {
      const char = content[i]
      if (char === '\\' && i + 1 < content.length) {
        const next = content[i + 1]
        if (next >= '0' && next <= '7') {
          // Octal escape \ooo
          let octal = next
          i += 2
          while (i < content.length && content[i] >= '0' && content[i] <= '7' && octal.length < 3) {
            octal += content[i]
            i++
          }
          bytes.push(parseInt(octal, 8))
          continue
        } else {
          switch (next) {
            case 'n': bytes.push(10); break
            case 'r': bytes.push(13); break
            case 't': bytes.push(9); break
            case 'b': bytes.push(8); break
            case 'f': bytes.push(12); break
            case '(': bytes.push(40); break
            case ')': bytes.push(41); break
            case '\\': bytes.push(92); break
            default: bytes.push(next.charCodeAt(0)); break
          }
          i += 2
          continue
        }
      } else {
        bytes.push(char.charCodeAt(0) & 0xff)
        i++
      }
    }
    return new Uint8Array(bytes)
  }

  return new TextEncoder().encode(trimmed)
}

function findMatchingDict(text: string, startIndex: number): string {
  let depth = 0
  let i = startIndex
  let start = -1

  while (i < text.length) {
    if (text.substr(i, 2) === '<<') {
      if (depth === 0) start = i
      depth++
      i += 2
    } else if (text.substr(i, 2) === '>>') {
      depth--
      i += 2
      if (depth === 0) {
        return text.substring(start, i)
      }
    } else {
      i++
    }
  }
  return ''
}

function uint8ArrayToBinaryString(bytes: Uint8Array): string {
  const CHUNK = 32768
  let str = ''
  for (let i = 0; i < bytes.length; i += CHUNK) {
    str += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, bytes.length)) as unknown as number[])
  }
  return str
}

export function extractPdfHash(buffer: ArrayBuffer, fileName: string, target: 'open' | 'permission' = 'open'): HashPackage {
  const bytes = new Uint8Array(buffer)
  // 必须使用 String.fromCharCode 保持 0x00-0xFF 纯 8 位字节无损映射，
  // 严禁使用 TextDecoder('latin1')，因浏览器 WHATWG 规范会将 0x80-0x9F 重定向为 Windows-1252 从而彻底破坏原始哈希字节！
  const content = uint8ArrayToBinaryString(bytes)

  if (!content.includes('/Encrypt')) {
    throw new Error('该 PDF 文件未加密，没有设置密码保护')
  }

  // 1. Locate /Encrypt
  // Case A: /Encrypt <obj_num> <gen_num> R
  // Case B: /Encrypt << ... >>
  const encryptRefMatch = content.match(/\/Encrypt\s+(\d+)\s+(\d+)\s+R/)
  let encryptDictStr = ''

  if (encryptRefMatch) {
    const objNum = encryptRefMatch[1]
    const genNum = encryptRefMatch[2]
    // Search for obj definition: objNum genNum obj << ... >>
    const objRegex = new RegExp(`\\b${objNum}\\s+${genNum}\\s+obj\\s*(<<[\\s\\S]*?>>)`, 'm')
    const objMatch = content.match(objRegex)
    if (objMatch) {
      encryptDictStr = objMatch[1]
    } else {
      // Fallback: search for objNum genNum obj then find matching << >>
      const objIndex = content.search(new RegExp(`\\b${objNum}\\s+${genNum}\\s+obj\\b`))
      if (objIndex !== -1) {
        const dictIndex = content.indexOf('<<', objIndex)
        if (dictIndex !== -1) {
          encryptDictStr = findMatchingDict(content, dictIndex)
        }
      }
    }
  }

  if (!encryptDictStr) {
    const directDictIndex = content.indexOf('/Encrypt')
    if (directDictIndex !== -1) {
      const dictIndex = content.indexOf('<<', directDictIndex)
      if (dictIndex !== -1 && dictIndex - directDictIndex < 30) {
        encryptDictStr = findMatchingDict(content, dictIndex)
      }
    }
  }

  if (!encryptDictStr) {
    throw new Error('无法解析 PDF /Encrypt 加密字典结构')
  }

  // 2. Parse dictionary attributes
  const vMatch = encryptDictStr.match(/\/V\s+(\d+)/)
  const rMatch = encryptDictStr.match(/\/R\s+(\d+)/)
  const lengthMatch = encryptDictStr.match(/\/Length\s+(\d+)/)
  const pMatch = encryptDictStr.match(/\/P\s+(-?\d+)/)
  const encryptMetaMatch = encryptDictStr.match(/\/EncryptMetadata\s+(true|false)/i)

  const algorithm = vMatch ? parseInt(vMatch[1], 10) : 0
  const revision = rMatch ? parseInt(rMatch[1], 10) : 0
  const keyLength = lengthMatch ? parseInt(lengthMatch[1], 10) : 40
  let permissions = pMatch ? parseInt(pMatch[1], 10) : 0
  if (permissions > 0x7fffffff) {
    permissions -= 0x100000000
  }
  const encryptMetadata = encryptMetaMatch && encryptMetaMatch[1].toLowerCase() === 'false' ? 0 : 1

  // 3. Document ID (/ID [ <hex> <hex> ])
  let documentIdBytes: Uint8Array = new Uint8Array(16)
  const idMatch = content.match(/\/ID\s*\[\s*([<(\s\S]*?)\]/)
  if (idMatch) {
    const idInner = idMatch[1].trim()
    const firstIdMatch = idInner.match(/(<[0-9a-fA-F]+>|\([^)]+\))/)
    if (firstIdMatch) {
      documentIdBytes = decodePdfString(firstIdMatch[1])
    }
  }

  // 4. Extract /U, /O, /OE, /UE
  const maxFieldLength = revision <= 4 ? 32 : 48
  const passwordFields: string[] = []

  const extractEntry = (key: string): Uint8Array | null => {
    const idx = encryptDictStr.search(new RegExp(`\\/${key}[\\s<(]`))
    if (idx === -1) return null
    let p = idx + key.length + 1
    while (p < encryptDictStr.length && /\s/.test(encryptDictStr[p])) p++
    if (encryptDictStr[p] === '<') {
      const end = encryptDictStr.indexOf('>', p)
      if (end !== -1) {
        return decodePdfString(encryptDictStr.substring(p, end + 1))
      }
    } else if (encryptDictStr[p] === '(') {
      let depth = 1
      let i = p + 1
      while (i < encryptDictStr.length && depth > 0) {
        if (encryptDictStr[i] === '\\') {
          i += 2
          continue
        }
        if (encryptDictStr[i] === '(') depth++
        else if (encryptDictStr[i] === ')') depth--
        i++
      }
      return decodePdfString(encryptDictStr.substring(p, i))
    }
    return null
  }

  const uBytes = extractEntry('U')
  const oBytes = extractEntry('O')

  // 5. 智能前置校验：打开密码 vs 权限限制密码
  if (target === 'open') {
    const userPassIsEmpty = isPdfUserPasswordEmpty(
      revision,
      keyLength,
      permissions,
      encryptMetadata,
      documentIdBytes,
      oBytes,
      uBytes
    )

    if (userPassIsEmpty) {
      if ((oBytes && oBytes.length > 0) || permissions !== -4) {
        throw new Error(
          '该 PDF 文档未设置打开密码（任何人均可直接正常打开阅读），但检测到设置了权限限制密码！请将左侧「PDF 提取目标」切换为「权限/编辑密码 (25400)」进行提取。'
        )
      }
      throw new Error('该 PDF 文件未设置任何密码保护（无打开密码，亦无权限限制）。')
    }
  } else if (target === 'permission') {
    if (!oBytes || oBytes.length === 0) {
      throw new Error('该 PDF 文档未设置权限/所有者密码，请将左侧「PDF 提取目标」切换为「打开密码」进行提取。')
    }
    if (revision !== 3 && revision !== 4) {
      throw new Error(
        `Hashcat GPU 模式暂不支持 PDF R=${revision} 的权限密码恢复（仅支持 PDF 1.4-1.6 的 128 位加密），请使用客户端恢复工具的 CPU 模式。`
      )
    }
  }

  for (const key of ['U', 'O', 'OE', 'UE']) {
    const rawBytes = extractEntry(key)
    if (rawBytes && rawBytes.length > 0) {
      const sliced = rawBytes.slice(0, maxFieldLength)
      passwordFields.push(sliced.length.toString(), bufToHex(sliced))
    }
  }

  if (passwordFields.length === 0) {
    throw new Error('PDF 加密字典中未找到 /U 或 /O 验证哈希字段')
  }

  const pdfHash = [
    `$pdf$${algorithm}`,
    revision.toString(),
    keyLength.toString(),
    permissions.toString(),
    encryptMetadata.toString(),
    documentIdBytes.length.toString(),
    bufToHex(documentIdBytes),
    ...passwordFields,
  ].join('*')

  let hashMode = 0
  if (target === 'permission') {
    hashMode = 25400
  } else {
    const modeMap: Record<number, number> = {
      2: 10400,
      3: 10500,
      4: 10500,
      5: 10600,
      6: 10700,
    }
    hashMode = modeMap[revision] || 0
    if (!hashMode) {
      throw new Error(`GPU 模式暂不支持该 PDF 加密版本 R=${revision}`)
    }
  }

  return {
    format: 'file-password-recovery-hash',
    version: 1,
    sourceName: fileName,
    sourceType: 'pdf',
    hashMode,
    hash: pdfHash,
    status: 'ok',
    details: `PDF (R=${revision}, V=${algorithm}, ${keyLength}位, ${target === 'permission' ? '权限限制密码' : '打开密码'})`,
    metadata: {
      revision,
      algorithm,
      keyLength,
      permissions,
      target,
    },
  }
}
