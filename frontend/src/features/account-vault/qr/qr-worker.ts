import jsQR from 'jsqr'

const worker = self as unknown as {
  onmessage: ((event: MessageEvent<{ pixels: ArrayBuffer; width: number; height: number }>) => void) | null
  postMessage: (value: { uri: string | null; error?: boolean }) => void
}

worker.onmessage = ({ data }) => {
  const pixels = new Uint8ClampedArray(data.pixels)
  try {
    const result = jsQR(pixels, data.width, data.height, { inversionAttempts: 'attemptBoth' })
    worker.postMessage({ uri: result?.data ?? null })
  } catch {
    worker.postMessage({ uri: null, error: true })
  } finally {
    pixels.fill(0)
  }
}
