import { bufToHex } from './types'
import type { HashPackage } from './types'

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

export function extractPdfHash(buffer: ArrayBuffer, fileName: string, target: 'open' | 'permission' = 'open'): HashPackage {
  const bytes = new Uint8Array(buffer)
  // Decode text using latin1 to keep 1-to-1 byte positions for ASCII structure
  const decoder = new TextDecoder('latin1')
  const content = decoder.decode(bytes)

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
  let documentIdBytes: Uint8Array<any> = new Uint8Array(16)
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
    // Match /Key <hex> or /Key (...)
    const regex = new RegExp(`\\/${key}\\s*(<[0-9a-fA-F\\s]+>|\\([\\s\\S]*?\\)(?=[\\s/<>]))`, 'm')
    const match = encryptDictStr.match(regex)
    if (match) {
      return decodePdfString(match[1])
    }
    return null
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
    if (revision === 3 || revision === 4) {
      hashMode = 25400
    } else {
      throw new Error(
        `Hashcat GPU 模式暂不支持 PDF R=${revision} 的权限密码恢复（仅支持 PDF 1.4-1.6），请使用打开密码模式`
      )
    }
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
    details: `PDF (R=${revision}, V=${algorithm}, ${keyLength}位, ${target === 'permission' ? '权限密码' : '打开密码'})`,
    metadata: {
      revision,
      algorithm,
      keyLength,
      permissions,
      target,
    },
  }
}
