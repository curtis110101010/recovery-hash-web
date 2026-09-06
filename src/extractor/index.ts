import { extractPdfHash } from './pdf'
import { extractOfficeHash } from './office'
import { extractZipHash } from './zip'
import { inspectRarOr7z } from './rar7z'
import type { ExtractionOptions, HashPackage } from './types'

export * from './types'

export async function extractHashFromFile(
  file: File,
  options: ExtractionOptions = {}
): Promise<HashPackage> {
  const fileName = file.name
  const ext = fileName.split('.').pop()?.toLowerCase() || ''

  // Read file into ArrayBuffer
  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer)

  // 1. PDF detection
  if (
    ext === 'pdf' ||
    (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
  ) {
    return extractPdfHash(buffer, fileName, options.pdfTarget || 'open')
  }

  // 2. Office detection (.docx, .xlsx, .pptx, .docm, .xlsm, .pptm, .doc, .xls, .ppt)
  const officeExts = ['doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm']
  const isOleHeader =
    bytes.length >= 8 &&
    bytes[0] === 0xd0 &&
    bytes[1] === 0xcf &&
    bytes[2] === 0x11 &&
    bytes[3] === 0xe0 &&
    bytes[4] === 0xa1 &&
    bytes[5] === 0xb1 &&
    bytes[6] === 0x1a &&
    bytes[7] === 0xe1

  if (officeExts.includes(ext) || isOleHeader) {
    return await extractOfficeHash(buffer, fileName, options.officeTarget || 'open')
  }

  // 3. RAR & 7z
  if (
    ext === 'rar' ||
    ext === '7z' ||
    (bytes.length >= 6 && bytes[0] === 0x37 && bytes[1] === 0x7a && bytes[2] === 0xbc) ||
    (bytes.length >= 4 && bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21)
  ) {
    return inspectRarOr7z(buffer, fileName)
  }

  // 4. ZIP
  if (
    ext === 'zip' ||
    (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04)
  ) {
    return extractZipHash(buffer, fileName)
  }

  throw new Error(`暂不支持识别或提取该类型的文件扩展名 (.${ext})`)
}
