import { bufToHex } from './types'
import type { HashPackage } from './types'

export function extractZipHash(buffer: ArrayBuffer, fileName: string): HashPackage {
  const bytes = new Uint8Array(buffer)
  const view = new DataView(buffer)

  let offset = 0
  let foundEncrypted = false

  while (offset + 30 <= bytes.length) {
    const signature = view.getUint32(offset, true)
    if (signature !== 0x04034b50) {
      // Not a local file header, search next PK
      offset++
      while (offset + 4 <= bytes.length && view.getUint32(offset, true) !== 0x04034b50) {
        offset++
      }
      if (offset + 30 > bytes.length) break
    }

    const flags = view.getUint16(offset + 6, true)
    const compMethod = view.getUint16(offset + 8, true)
    const crc32 = view.getUint32(offset + 14, true)
    const compSize = view.getUint32(offset + 18, true)
    const uncompSize = view.getUint32(offset + 22, true)
    const nameLen = view.getUint16(offset + 26, true)
    const extraLen = view.getUint16(offset + 28, true)

    const entryName = new TextDecoder('utf-8', { fatal: false }).decode(
      bytes.slice(offset + 30, offset + 30 + nameLen)
    )

    const extraField = bytes.slice(offset + 30 + nameLen, offset + 30 + nameLen + extraLen)
    const dataOffset = offset + 30 + nameLen + extraLen

    const isEncrypted = (flags & 0x01) !== 0

    if (isEncrypted) {
      foundEncrypted = true

      // Check for WinZip AES (extra header 0x9901 or compMethod 99)
      let isAes = compMethod === 99
      let aesMode = 3 // default AES-256 (16 byte salt)

      // Search extra field for 0x9901
      let efOffset = 0
      while (efOffset + 4 <= extraField.length) {
        const headerId = extraField[efOffset] | (extraField[efOffset + 1] << 8)
        const dataSize = extraField[efOffset + 2] | (extraField[efOffset + 3] << 8)
        if (headerId === 0x9901 && dataSize >= 7) {
          isAes = true
          aesMode = extraField[efOffset + 8] // 1 = 128-bit, 2 = 192-bit, 3 = 256-bit
          break
        }
        efOffset += 4 + dataSize
      }

      if (isAes) {
        // WinZip AES: Salt (8/12/16) + PVV (2) + Encrypted Data + AuthCode (10)
        let saltLen = 16
        if (aesMode === 1) saltLen = 8
        else if (aesMode === 2) saltLen = 12
        else saltLen = 16

        if (dataOffset + saltLen + 2 + 10 > bytes.length) {
          throw new Error('ZIP WinZip AES 加密数据流截断')
        }

        const salt = bytes.slice(dataOffset, dataOffset + saltLen)
        const pvv = bytes.slice(dataOffset + saltLen, dataOffset + saltLen + 2)

        const payloadSize = compSize > 0 ? compSize : bytes.length - dataOffset
        const encDataLen = Math.max(0, payloadSize - saltLen - 2 - 10)
        const encData = bytes.slice(dataOffset + saltLen + 2, dataOffset + saltLen + 2 + encDataLen)
        const authCode = bytes.slice(
          dataOffset + saltLen + 2 + encDataLen,
          dataOffset + saltLen + 2 + encDataLen + 10
        )

        const saltHex = bufToHex(salt)
        const pvvHex = bufToHex(pvv)
        const dataLenHex = encData.length.toString(16)
        const dataHex = bufToHex(encData)
        const authHex = bufToHex(authCode)

        const zipHash = `$zip2$*0*${aesMode}*0*${saltHex}*${pvvHex}*${dataLenHex}*${dataHex}*${authHex}*$/zip2$`

        return {
          format: 'file-password-recovery-hash',
          version: 1,
          sourceName: fileName,
          sourceType: 'zip',
          hashMode: 13600,
          hash: zipHash,
          status: 'ok',
          details: `WinZip AES-${aesMode === 1 ? 128 : aesMode === 2 ? 192 : 256} (条目: ${entryName}, Mode 13600)`,
          metadata: {
            encryption: 'WinZip AES',
            aesMode,
            entryName,
            compSize,
            uncompSize,
          },
        }
      }

      // Traditional PKZIP (ZipCrypto)
      // Standard 12-byte encryption header + compressed data
      if (compSize > 320 * 1024) {
        return {
          format: 'file-password-recovery-hash',
          version: 1,
          sourceName: fileName,
          sourceType: 'zip',
          hashMode: 17200,
          hash: '',
          status: 'blocked',
          blockedCode: 'ZIP_PKZIP_TOO_LARGE',
          blockedReason: 'PKZIP 加密数据块超过 GPU 上限 (320KB)',
          blockedMessage: `该 ZIP (PKZIP) 加密数据块大小为 ${(compSize / 1024).toFixed(0)}KB，超过了 Hashcat GPU 320KB 上限。建议使用 CPU 模式或 WinZip AES。`,
          details: `ZIP (传统 ZipCrypto, 条目: ${entryName})`,
        }
      }

      const encHeader = bytes.slice(dataOffset, dataOffset + 12)
      const encHeaderHex = bufToHex(encHeader)
      const crcHex = crc32.toString(16).padStart(8, '0')
      const checkByte = (crc32 >> 24) & 0xff

      // Hashcat Mode 17200 / 17220 (PKZIP)
      const zipHash = `$pkzip2$1*1*2*0*${compSize.toString(16)}*${uncompSize.toString(16)}*${crcHex}*0*1f*63*${compSize.toString(16)}*${crcHex.substring(0, 4)}*${checkByte.toString(16).padStart(4, '0')}*${encHeaderHex}*$/pkzip2$`

      return {
        format: 'file-password-recovery-hash',
        version: 1,
        sourceName: fileName,
        sourceType: 'zip',
        hashMode: 17200,
        hash: zipHash,
        status: 'ok',
        details: `ZIP (传统 ZipCrypto, 条目: ${entryName}, Mode 17200)`,
        metadata: {
          encryption: 'ZipCrypto',
          entryName,
          compSize,
          crc32: crcHex,
        },
      }
    }

    offset = dataOffset + compSize
  }

  if (!foundEncrypted) {
    throw new Error('该 ZIP 压缩包未设置密码保护')
  }

  throw new Error('未能从 ZIP 压缩包中提取有效的加密数据头')
}
