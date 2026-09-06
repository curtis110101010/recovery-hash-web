import React, { useState, useRef, useEffect } from 'react'
import {
  ShieldCheck,
  Lock,
  FileCheck,
  Download,
  Copy,
  Check,
  AlertTriangle,
  UploadCloud,
  KeyRound,
  RefreshCw,
  Cpu,
  WifiOff,
} from 'lucide-react'
import { extractHashFromFile } from './extractor'
import type { HashPackage, ExtractionOptions } from './extractor'
import './App.css'

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<HashPackage | null>(null)
  const [copied, setCopied] = useState<boolean>(false)
  const [isDragOver, setIsDragOver] = useState<boolean>(false)
  const [duration, setDuration] = useState<number>(0)
  const [isOffline, setIsOffline] = useState<boolean>(!navigator.onLine)

  // Target options
  const [pdfTarget, setPdfTarget] = useState<'open' | 'permission'>('open')
  const [officeTarget, setOfficeTarget] = useState<'open' | 'permission'>('open')

  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const handleOnline = () => setIsOffline(false)
    const handleOffline = () => setIsOffline(true)
    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)
    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [])

  const handleProcess = async (selectedFile: File, overrideOpts?: ExtractionOptions) => {
    setFile(selectedFile)
    setLoading(true)
    setError(null)
    setResult(null)
    setCopied(false)

    const startTime = performance.now()
    try {
      const opts: ExtractionOptions = {
        pdfTarget,
        officeTarget,
        ...overrideOpts,
      }
      const pkg = await extractHashFromFile(selectedFile, opts)
      setResult(pkg)
      setDuration(Math.round(performance.now() - startTime))
    } catch (err: any) {
      setError(err.message || '文件解析失败，请检查文件格式或加密类型')
    } finally {
      setLoading(false)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleProcess(e.target.files[0])
    }
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleProcess(e.dataTransfer.files[0])
    }
  }

  const handleDownload = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${result.sourceName}.recovery-hash`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleCopy = () => {
    if (!result?.hash) return
    navigator.clipboard.writeText(result.hash)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between font-sans">
      {/* Top Banner */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white">安全恢复哈希提取器</h1>
                <span className="bg-emerald-500/20 text-emerald-300 text-xs px-2 py-0.5 rounded font-medium border border-emerald-500/30 font-mono">
                  v1.2.0 (最新版)
                </span>
                <span className="bg-sky-500/20 text-sky-300 text-xs px-2 py-0.5 rounded font-medium border border-sky-500/30">
                  淘宝@大希软件服务
                </span>
              </div>
              <p className="text-xs text-slate-400">纯本地浏览器计算 · 零文件上传 · 绝对隐私保障</p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs">
            {isOffline ? (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300">
                <WifiOff className="w-3.5 h-3.5" /> 断网离线运行中
              </span>
            ) : (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
                <Check className="w-3.5 h-3.5" /> 离线缓存就绪
              </span>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-4xl w-full mx-auto px-4 py-8 flex-1">
        {/* Security Announcement */}
        <div className="mb-6 p-4 rounded-xl bg-slate-900/80 border border-sky-500/30 flex items-start gap-3 shadow-lg">
          <Lock className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
          <div className="text-xs leading-relaxed text-slate-300">
            <strong className="text-sky-300 block mb-1 text-sm font-semibold">🔒 100% 客户端本地计算承诺</strong>
            本网页通过 WebAssembly 与 JavaScript 在您电脑本地浏览器内存中直接提取加密元数据，
            <span className="text-amber-300 font-medium">绝不向任何服务器上传您的文档内容</span>
            。哪怕是几 GB 的大文件，您也可以在断开网络后放心提取。
          </div>
        </div>

        {/* Target Options */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5 text-sky-400" /> PDF 提取目标
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPdfTarget('open')}
                className={`flex-1 py-2 px-3 text-xs rounded-lg font-medium transition border ${
                  pdfTarget === 'open'
                    ? 'bg-sky-600 text-white border-sky-500 shadow'
                    : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:bg-slate-800'
                }`}
              >
                打开密码 (默认)
              </button>
              <button
                type="button"
                onClick={() => setPdfTarget('permission')}
                className={`flex-1 py-2 px-3 text-xs rounded-lg font-medium transition border ${
                  pdfTarget === 'permission'
                    ? 'bg-purple-600 text-white border-purple-500 shadow'
                    : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:bg-slate-800'
                }`}
              >
                权限/编辑密码 (25400)
              </button>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5 text-emerald-400" /> Office 提取目标
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setOfficeTarget('open')}
                className={`flex-1 py-2 px-3 text-xs rounded-lg font-medium transition border ${
                  officeTarget === 'open'
                    ? 'bg-sky-600 text-white border-sky-500 shadow'
                    : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:bg-slate-800'
                }`}
              >
                打开密码 (Word/Excel/PPT)
              </button>
              <button
                type="button"
                onClick={() => setOfficeTarget('permission')}
                className={`flex-1 py-2 px-3 text-xs rounded-lg font-medium transition border ${
                  officeTarget === 'permission'
                    ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                    : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:bg-slate-800'
                }`}
              >
                工作表/限制编辑 (25300/XOR)
              </button>
            </div>
          </div>
        </div>

        {/* Drop Zone */}
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setIsDragOver(true)
          }}
          onDragLeave={() => setIsDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-200 ${
            isDragOver
              ? 'border-sky-400 bg-sky-500/10 scale-[1.01]'
              : 'border-slate-700 hover:border-slate-500 bg-slate-900/40 hover:bg-slate-900/60'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            accept=".pdf,.doc,.docx,.docm,.xls,.xlsx,.xlsm,.ppt,.pptx,.pptm,.zip,.rar,.7z"
            onChange={handleFileChange}
          />
          <div className="flex flex-col items-center justify-center gap-3">
            <div className="p-4 rounded-2xl bg-sky-500/10 border border-sky-500/20 text-sky-400 shadow-inner">
              <UploadCloud className="w-10 h-10" />
            </div>
            <div>
              <p className="text-base font-medium text-white mb-1">
                点击选择受保护的文件，或直接拖拽文件到这里
              </p>
              <p className="text-xs text-slate-400">
                支持 PDF、Word、Excel、Powerpoint、ZIP、RAR、7Z文件
              </p>
            </div>
          </div>
        </div>

        {/* Processing State */}
        {loading && (
          <div className="mt-6 p-6 rounded-xl bg-slate-900 border border-slate-800 text-center flex flex-col items-center gap-3">
            <RefreshCw className="w-7 h-7 text-sky-400 animate-spin" />
            <p className="text-sm font-medium text-slate-200">正在浏览器本地解析文件加密结构...</p>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mt-6 p-4 rounded-xl bg-red-950/40 border border-red-800/60 flex items-start gap-3 text-red-200">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs flex-1">
              <strong className="block text-red-300 font-semibold mb-0.5">解析提示</strong>
              <p className="leading-relaxed">{error}</p>
              {error.includes('切换为「权限/编辑密码 (25400)」') && file && (
                <button
                  type="button"
                  onClick={() => {
                    setPdfTarget('permission')
                    handleProcess(file, { pdfTarget: 'permission', officeTarget })
                  }}
                  className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-medium text-xs transition shadow cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  一键切换为「权限/编辑密码 (25400)」并重新提取
                </button>
              )}
              {error.includes('切换为「工作表/限制编辑') && file && (
                <button
                  type="button"
                  onClick={() => {
                    setOfficeTarget('permission')
                    handleProcess(file, { pdfTarget, officeTarget: 'permission' })
                  }}
                  className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium text-xs transition shadow cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  一键切换为「工作表/限制编辑」并重新提取
                </button>
              )}
            </div>
          </div>
        )}

        {/* Interception / Blocked Result */}
        {result && result.status === 'blocked' && (
          <div className="mt-6 p-5 rounded-xl bg-amber-950/40 border border-amber-800/60">
            <div className="flex items-center gap-2 mb-2 text-amber-300 font-semibold text-sm">
              <AlertTriangle className="w-5 h-5" /> 智能拦截：{result.blockedReason}
            </div>
            <p className="text-xs text-amber-200 leading-relaxed mb-3">{result.blockedMessage}</p>
            <div className="text-[11px] text-amber-400 font-mono bg-amber-950/60 p-2 rounded border border-amber-900">
              错误代码: {result.blockedCode}
            </div>
          </div>
        )}

        {/* Success Result Card */}
        {result && result.status === 'ok' && (
          <div className="mt-6 rounded-2xl bg-slate-900 border border-emerald-500/40 p-6 shadow-2xl space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  <FileCheck className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    {result.sourceName}
                    <span className="px-2 py-0.5 text-xs rounded bg-emerald-500/20 text-emerald-300 font-medium border border-emerald-500/40">
                      提取成功 ({duration} ms)
                    </span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">{result.details}</p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 font-mono text-sky-400">
                  Hashcat Mode: {result.hashMode || '直接破解'}
                </span>
              </div>
            </div>

            {/* Hash Preview */}
            <div>
              <div className="flex items-center justify-between mb-1.5 text-xs text-slate-400">
                <span className="font-medium">恢复哈希签名特征 (已安全截断脱敏)：</span>
                <span className="font-mono text-[11px]">{result.hash.length} 字符</span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-sky-200 break-all max-h-32 overflow-y-auto select-all">
                {result.hash}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap gap-3 pt-2">
              <button
                type="button"
                onClick={handleDownload}
                className="flex-1 min-w-[200px] flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs transition shadow-lg shadow-sky-900/30"
              >
                <Download className="w-4 h-4" /> 下载 .recovery-hash 文件
              </button>
              <button
                type="button"
                onClick={handleCopy}
                className="flex-1 min-w-[160px] flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs border border-slate-700 transition"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                {copied ? '已复制到剪贴板' : '一键复制哈希文本'}
              </button>
            </div>

            {/* Customer Instruction Banner */}
            <div className="p-4 rounded-xl bg-sky-950/40 border border-sky-800/40 text-xs text-sky-200 leading-relaxed flex items-start gap-3">
              <Cpu className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold text-sky-300 mb-0.5">下一步操作指引：</strong>
                请将下载的 <code className="bg-sky-900/50 px-1.5 py-0.5 rounded text-sky-100 font-mono">.recovery-hash</code> 文件或复制的哈希文本发送给{' '}
                <strong className="text-white underline decoration-sky-400 underline-offset-4 font-bold">
                  淘宝@大希软件服务
                </strong>
                。我们将在专用 GPU 算力集群上为您快速找回密码！
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-5 text-center text-xs text-slate-500">
        <div className="max-w-5xl mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-2">
          <p>© 2026 恢复哈希提取器 · 纯前端离线单页应用</p>
          <p className="text-slate-400">
            官方技术服务与算力支持：<strong className="text-sky-400">淘宝@大希软件服务</strong>
          </p>
        </div>
      </footer>
    </div>
  )
}
