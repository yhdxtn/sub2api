import { ImageInputError, inspectImageFile } from './inspect-image'

function checkAborted(signal: AbortSignal) {
  if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
}

function decodePixels(imageData: ImageData, signal: AbortSignal): Promise<string | null> {
  checkAborted(signal)
  return new Promise((resolve, reject) => {
    let worker: Worker | undefined
    let timer: ReturnType<typeof setTimeout> | undefined
    let finished = false
    const finish = (error: Error | null, uri: string | null = null) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      signal.removeEventListener('abort', cancel)
      worker?.terminate()
      if (error) reject(error)
      else resolve(uri)
    }
    const cancel = () => finish(new DOMException('Cancelled', 'AbortError'))
    try {
      worker = new Worker(new URL('./qr-worker.ts', import.meta.url), { type: 'module' })
      worker.onmessage = ({ data }: MessageEvent<{ uri: string | null; error?: boolean }>) =>
        finish(data.error ? new ImageInputError('decodeFailed') : null, data.uri)
      worker.onerror = () => finish(new ImageInputError('workerUnavailable'))
      signal.addEventListener('abort', cancel, { once: true })
      timer = setTimeout(() => finish(new ImageInputError('decodeTimeout')), 12_000)
      const pixels = imageData.data.buffer as ArrayBuffer
      worker.postMessage({ pixels, width: imageData.width, height: imageData.height }, [pixels])
    } catch {
      finish(signal.aborted ? new DOMException('Cancelled', 'AbortError') : new ImageInputError('workerUnavailable'))
    }
  })
}

interface OpenedImage {
  source: CanvasImageSource
  width: number
  height: number
  close: () => void
}

async function openImage(file: File, signal: AbortSignal): Promise<OpenedImage> {
  checkAborted(signal)
  if (typeof createImageBitmap === 'function') {
    let bitmap: ImageBitmap
    try { bitmap = await createImageBitmap(file) }
    catch { throw new ImageInputError('invalidImage') }
    if (signal.aborted) {
      bitmap.close()
      checkAborted(signal)
    }
    return { source: bitmap, width: bitmap.width, height: bitmap.height, close: () => bitmap.close() }
  }
  const url = URL.createObjectURL(file)
  const img = new Image()
  try {
    await new Promise<void>((resolve, reject) => {
      const cancel = () => { img.src = ''; reject(new DOMException('Cancelled', 'AbortError')) }
      const cleanup = () => signal.removeEventListener('abort', cancel)
      img.onload = () => { cleanup(); resolve() }
      img.onerror = () => { cleanup(); reject(new ImageInputError('invalidImage')) }
      signal.addEventListener('abort', cancel, { once: true })
      img.src = url
    })
    checkAborted(signal)
    return { source: img, width: img.naturalWidth, height: img.naturalHeight,
      close: () => { img.src = ''; URL.revokeObjectURL(url) } }
  } catch (error) {
    img.src = ''
    URL.revokeObjectURL(url)
    throw error
  }
}

export async function decodeImageLocally(file: File, signal: AbortSignal): Promise<string | null> {
  // Recheck the compressed header even when called outside the import UI.
  await inspectImageFile(file)
  checkAborted(signal)
  let opened: OpenedImage | undefined
  let canvas: HTMLCanvasElement | undefined
  try {
    opened = await openImage(file, signal)
    if (!opened.width || !opened.height || opened.width * opened.height > 16_000_000) {
      throw new ImageInputError('imageDimensions')
    }
    canvas = document.createElement('canvas')
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) throw new ImageInputError('canvasUnavailable')
    const firstScale = Math.min(1, 1600 / Math.max(opened.width, opened.height))
    for (const scale of firstScale < 1 ? [firstScale, 1] : [1]) {
      checkAborted(signal)
      canvas.width = Math.max(1, Math.round(opened.width * scale))
      canvas.height = Math.max(1, Math.round(opened.height * scale))
      context.fillStyle = '#ffffff'
      context.fillRect(0, 0, canvas.width, canvas.height)
      context.drawImage(opened.source, 0, 0, canvas.width, canvas.height)
      const uri = await decodePixels(context.getImageData(0, 0, canvas.width, canvas.height), signal)
      if (uri) return uri
    }
    return null
  } finally {
    opened?.close()
    if (canvas) { canvas.width = 0; canvas.height = 0 }
  }
}
