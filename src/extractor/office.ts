import * as CFB from 'cfb'
import JSZip from 'jszip'
import { base64ToHex, bufToHex } from './types'
import type { HashPackage } from './types'

export async function extractOfficeHash(
  buffer: ArrayBuffer,
  fileName: string,
  target: 'open' | 'permission' = 'open'
): Promise<HashPackage> {
  const bytes = new Uint8Array(buffer)

  // If user requested permission/protection password or file is unencrypted ZIP
  if (target === 'permission') {
    return extractOfficePermission(bytes, fileName)
  }

  // Check for OLE container (starts with D0 CF 11 E0 A1 B1 1A E1)
  const isOle =
    bytes.length > 8 &&
    bytes[0] === 0xd0 &&
    bytes[1] === 0xcf &&
    bytes[2] === 0x11 &&
    bytes[3] === 0xe0 &&
    bytes[4] === 0xa1 &&
    bytes[5] === 0xb1 &&
    bytes[6] === 0x1a &&
    bytes[7] === 0xe1

  if (!isOle) {
    // Might be unencrypted OOXML zip or other format
    if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
      // It's a standard ZIP container - does it have protection/permission passwords?
      try {
        return await extractOfficePermission(bytes, fileName)
      } catch {
        throw new Error('该 Office 文档未设置打开密码，也没有工作表/编辑限制保护')
      }
    }
    throw new Error('该文件不是有效的 Office 加密文档 (OLE/OOXML)')
  }

  // Parse OLE with CFB
  let cfbDoc: CFB.CFB$Container
  try {
    cfbDoc = CFB.read(bytes, { type: 'array' })
  } catch (e: any) {
    throw new Error(`无法解析 Office 复合文件结构: ${e.message}`)
  }

  // Look for EncryptionInfo stream
  let encInfoEntry: CFB.CFB$Entry | null = null
  for (const name of cfbDoc.FullPaths) {
    if (name.toLowerCase().endsWith('encryptioninfo')) {
      encInfoEntry = CFB.find(cfbDoc, name)
      break
    }
  }

  if (!encInfoEntry || !encInfoEntry.content) {
    // Check if it's legacy Word/Excel RC4/XOR
    for (const name of cfbDoc.FullPaths) {
      if (name.toLowerCase().endsWith('worddocument') || name.toLowerCase().endsWith('workbook')) {
        // Legacy office
        return extractLegacyOffice(cfbDoc, fileName)
      }
    }
    throw new Error('未在 Office 复合文件中找到 EncryptionInfo 加密流')
  }

  const encBytes = new Uint8Array(encInfoEntry.content as any)
  if (encBytes.length < 8) {
    throw new Error('Office EncryptionInfo 加密流数据不完整')
  }

  const view = new DataView(encBytes.buffer, encBytes.byteOffset, encBytes.byteLength)
  const majorVersion = view.getUint16(0, true)
  const minorVersion = view.getUint16(2, true)

  // Agile / Extensible Encryption (Office 2010 / 2013 / 2016 / 2019 / 365)
  if (majorVersion >= 4) {
    // Look for XML <?xml in the stream
    const rawText = new TextDecoder('utf-8', { fatal: false }).decode(encBytes)
    const xmlStart = rawText.indexOf('<?xml')
    if (xmlStart === -1) {
      throw new Error('未在 Office 加密流中定位到 Agile XML 描述块')
    }

    const xmlEnd = rawText.indexOf('</encryption>')
    const xmlContent = xmlEnd !== -1 ? rawText.substring(xmlStart, xmlEnd + 13) : rawText.substring(xmlStart)

    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(xmlContent, 'text/xml')

    const keyData = xmlDoc.querySelector('keyData')
    let pEncryptedKey = xmlDoc.querySelector('p\\:encryptedKey, encryptedKey')
    if (!pEncryptedKey) {
      const candidates = xmlDoc.getElementsByTagName('*')
      for (let i = 0; i < candidates.length; i++) {
        if (candidates[i].localName === 'encryptedKey' || candidates[i].nodeName.endsWith('encryptedKey')) {
          pEncryptedKey = candidates[i]
          break
        }
      }
    }

    const saltValue = pEncryptedKey?.getAttribute('saltValue') || keyData?.getAttribute('saltValue')
    const encryptedVerifierHashInput = pEncryptedKey?.getAttribute('encryptedVerifierHashInput')
    const encryptedVerifierHashValue = pEncryptedKey?.getAttribute('encryptedVerifierHashValue')
    const spinCount = pEncryptedKey?.getAttribute('spinCount') || '100000'
    const keyBits = pEncryptedKey?.getAttribute('keyBits') || keyData?.getAttribute('keyBits') || '128'
    const hashAlgorithm = (pEncryptedKey?.getAttribute('hashAlgorithm') || keyData?.getAttribute('hashAlgorithm') || 'SHA512').toUpperCase()

    if (!saltValue || !encryptedVerifierHashInput || !encryptedVerifierHashValue) {
      throw new Error('Office 加密描述块中缺少关键 Salt 或 Verifier 散列参数')
    }

    let version = 2013
    let hashMode = 9600
    if (hashAlgorithm === 'SHA1' || hashAlgorithm.includes('SHA1')) {
      version = 2010
      hashMode = 9500
    } else if (hashAlgorithm === 'SHA512') {
      version = 2013
      hashMode = 9600
    }

    const saltHex = base64ToHex(saltValue)
    const saltSize = saltHex.length / 2
    const verifierInputHex = base64ToHex(encryptedVerifierHashInput)
    const verifierValueHex = base64ToHex(encryptedVerifierHashValue).substring(0, 64)

    const hashStr = `$office$*${version}*${parseInt(spinCount, 10)}*${parseInt(keyBits, 10)}*${saltSize}*${saltHex}*${verifierInputHex}*${verifierValueHex}`

    return {
      format: 'file-password-recovery-hash',
      version: 1,
      sourceName: fileName,
      sourceType: 'office',
      hashMode,
      hash: hashStr,
      status: 'ok',
      details: `Office ${version} (Agile AES-${keyBits}, ${hashAlgorithm}, Mode ${hashMode})`,
      metadata: {
        version,
        spinCount: parseInt(spinCount, 10),
        keyBits: parseInt(keyBits, 10),
        hashAlgorithm,
        target: 'open',
      },
    }
  }

  // Standard Encryption (Office 2007, Mode 9400)
  if (majorVersion === 3 || majorVersion === 2) {
    // Offset 4: flags, offset 8: headerLength
    let offset = 8
    const headerLength = view.getUint32(offset, true)
    offset += headerLength // skip encryption header

    // Verifier structure
    const saltSize = view.getUint32(offset, true)
    offset += 4
    const salt = encBytes.slice(offset, offset + saltSize)
    offset += saltSize
    const encryptedVerifier = encBytes.slice(offset, offset + 16)
    offset += 16
    const verifierHashSize = view.getUint32(offset, true)
    offset += 4
    const encryptedVerifierHash = encBytes.slice(offset, offset + verifierHashSize)

    const saltHex = bufToHex(salt)
    const verifierHex = bufToHex(encryptedVerifier)
    const verifierHashHex = bufToHex(encryptedVerifierHash).substring(0, 64)

    const hashStr = `$office$*2007*50000*128*${saltSize}*${saltHex}*${verifierHex}*${verifierHashHex}`
    return {
      format: 'file-password-recovery-hash',
      version: 1,
      sourceName: fileName,
      sourceType: 'office',
      hashMode: 9400,
      hash: hashStr,
      status: 'ok',
      details: 'Office 2007 (Standard Encryption AES-128, Mode 9400)',
      metadata: {
        version: 2007,
        hashMode: 9400,
        target: 'open',
      },
    }
  }

  throw new Error(`暂不支持的 Office 加密协议版本 (v${majorVersion}.${minorVersion})`)
}

function extractLegacyOffice(_cfbDoc: CFB.CFB$Container, _fileName: string): HashPackage {
  throw new Error('旧版 Office 97-2003 (RC4) 请使用本地哈希提取工具')
}

export async function extractOfficePermission(bytes: Uint8Array, fileName: string): Promise<HashPackage> {
  let zip: JSZip
  try {
    zip = await JSZip.loadAsync(bytes)
  } catch {
    throw new Error('该文档不是有效的 OOXML (ZIP) 文档或已设置强加密打开密码')
  }

  const names = Object.keys(zip.files)
  const targetFiles = names.filter((n) => {
    const low = n.toLowerCase()
    return (
      (low.startsWith('xl/worksheets/sheet') && low.endsWith('.xml')) ||
      low === 'xl/workbook.xml' ||
      low === 'word/settings.xml' ||
      low === 'ppt/presentation.xml'
    )
  })

  for (const filename of targetFiles) {
    const file = zip.file(filename)
    if (!file) continue
    const text = await file.async('text')

    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(text, 'text/xml')

    const tags = [
      'sheetProtection',
      'workbookProtection',
      'documentProtection',
      'writeProtection',
      'fileSharing',
      'modifyVerifier',
    ]

    const allElems = xmlDoc.getElementsByTagName('*')
    for (let i = 0; i < allElems.length; i++) {
      const elem = allElems[i]
      const localTag = elem.localName || elem.nodeName.split(':').pop() || ''
      if (tags.includes(localTag)) {
        const attrs: Record<string, string> = {}
        for (let j = 0; j < elem.attributes.length; j++) {
          const attr = elem.attributes[j]
          const attrKey = attr.localName || attr.name.split(':').pop() || attr.name
          attrs[attrKey] = attr.value
        }

        const saltB64 = attrs['saltValue'] || attrs['salt'] || attrs['workbookSaltValue']
        const hashB64 = attrs['hashValue'] || attrs['hash'] || attrs['workbookHashValue']
        const spinCount = attrs['spinCount'] || attrs['cryptSpinCount'] || attrs['workbookSpinCount'] || '100000'
        const alg = attrs['algorithmName'] || attrs['workbookAlgorithmName'] || 'SHA-512'

        if (saltB64 && hashB64) {
          const formattedHash = `$office$2016$0$${spinCount}$${saltB64}$${hashB64}`
          const descMap: Record<string, string> = {
            sheetProtection: '工作表保护 (SheetProtection)',
            workbookProtection: '工作簿保护 (WorkbookProtection)',
            documentProtection: '文档编辑限制 (DocumentProtection)',
            writeProtection: '写保护修改密码 (WriteProtection)',
            fileSharing: '文件共享密码 (FileSharing)',
            modifyVerifier: '演示文稿修改密码 (ModifyVerifier)',
          }

          return {
            format: 'file-password-recovery-hash',
            version: 1,
            sourceName: fileName,
            sourceType: 'office',
            hashMode: 25300,
            hash: formattedHash,
            status: 'ok',
            details: `Office ${descMap[localTag] || localTag} (SHA-512, Mode 25300)`,
            metadata: {
              target: 'permission',
              protectionType: descMap[localTag] || localTag,
              algorithm: alg,
              spinCount: parseInt(spinCount, 10),
              targetFileInZip: filename,
            },
          }
        }

        const pwdHex = attrs['password'] || attrs['workbookPassword'] || attrs['reservationPassword']
        if (pwdHex) {
          return {
            format: 'file-password-recovery-hash',
            version: 1,
            sourceName: fileName,
            sourceType: 'office',
            hashMode: 0,
            hash: `$office$xor$${pwdHex.padStart(4, '0').toUpperCase()}`,
            status: 'ok',
            details: `Office 传统工作表保护 (16-bit XOR, 瞬时求解)`,
            metadata: {
              target: 'permission',
              algorithm: '16-bit XOR',
              xorHex: pwdHex,
              targetFileInZip: filename,
            },
          }
        }
      }
    }
  }

  throw new Error('该 Office 文档中未发现工作表保护、文档限制或编辑修改密码')
}
