import { extractPdfHash } from './pdf'
import { extractOfficeHash } from './office'
import { extractZipHash } from './zip'
import { inspectRarOr7z } from './rar7z'
import { HASH_7Z_MAX_HASH_BYTES } from './types'
import type { ExtractionOptions, HashPackage } from './types'

export * from './types'

function guardHashPackage(pkg: HashPackage): HashPackage {
  if (pkg.status === 'ok' && pkg.hash) {
    const hashBytes = new TextEncoder().encode(pkg.hash).length
    if (pkg.hash.startsWith('$7z$') && hashBytes > HASH_7Z_MAX_HASH_BYTES) {
      return {
        ...pkg,
        status: 'blocked',
        hash: '',
        blockedCode: '7Z_HASH_EXCEEDS_64KB',
        blockedReason: '7z 全量哈希体积超过 64KB 安全上限',
        blockedMessage: `提取出的 7z 全量哈希体积为 ${(hashBytes / 1024).toFixed(1)}KB，超过了 64KB 安全上限。提交 GPU 会导致严重的 CPU 软解压负载与算力假死，已自动拦截。`,
      }
    }
  }
  return pkg
}

export async function extractHashFromFile(
  file: File,
  options: ExtractionOptions = {}
): Promise<HashPackage> {
  const fileName = file.name
  const ext = fileName.split('.').pop()?.toLowerCase() || ''

  // Read file into ArrayBuffer
  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer)

  let res: HashPackage

  // 1. PDF detection
  if (
    ext === 'pdf' ||
    (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
  ) {
    res = extractPdfHash(buffer, fileName, options.pdfTarget || 'open')
  } else if (
    ['doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm'].includes(ext) ||
    (bytes.length >= 8 &&
      bytes[0] === 0xd0 &&
      bytes[1] === 0xcf &&
      bytes[2] === 0x11 &&
      bytes[3] === 0xe0 &&
      bytes[4] === 0xa1 &&
      bytes[5] === 0xb1 &&
      bytes[6] === 0x1a &&
      bytes[7] === 0xe1)
  ) {
    // 2. Office detection
    res = await extractOfficeHash(buffer, fileName, options.officeTarget || 'open')
  } else if (
    ext === 'rar' ||
    ext === '7z' ||
    (bytes.length >= 6 && bytes[0] === 0x37 && bytes[1] === 0x7a && bytes[2] === 0xbc) ||
    (bytes.length >= 4 && bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21)
  ) {
    // 3. RAR & 7z
    res = inspectRarOr7z(buffer, fileName)
  } else if (
    ext === 'zip' ||
    (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04)
  ) {
    // 4. ZIP
    res = extractZipHash(buffer, fileName)
  } else {
    throw new Error(`暂不支持识别或提取该类型的文件扩展名 (.${ext})`)
  }

  return guardHashPackage(res)
}
