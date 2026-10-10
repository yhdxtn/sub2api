export class ImageInputError extends Error {
  constructor(public readonly key: string) { super(key); this.name = 'ImageInputError' }
}

const MAX_PIXELS = 16_000_000;
const invalid = () => new ImageInputError('invalidImage');
const animationError = () => new ImageInputError('animatedImage');

function dimensions(width: number, height: number) {
  if (!width || !height) throw invalid();
  if (width * height > MAX_PIXELS) throw new ImageInputError('imageDimensions');
  return { width, height };
}

/** Inspect the compressed file before creating an object URL or decoding pixels. */
export async function inspectImageFile(file: File) {
  if (!file.size || file.size > 5 * 1024 * 1024) throw new ImageInputError('imageSize');
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const ascii = (at: number, count: number) => String.fromCharCode(...bytes.subarray(at, at + count));
  const u24 = (at: number) => bytes[at] + (bytes[at + 1] << 8) + (bytes[at + 2] << 16);
  let size: { width: number; height: number } | undefined;
  let type: string;

  if (bytes.length >= 33 && bytes[0] === 137 && ascii(1, 3) === 'PNG' && bytes[4] === 13 && bytes[5] === 10 && bytes[6] === 26 && bytes[7] === 10) {
    type = 'image/png';
    if (view.getUint32(8) !== 13 || ascii(12, 4) !== 'IHDR') throw invalid();
    size = dimensions(view.getUint32(16), view.getUint32(20));
    let at = 8;
    let sawEnd = false;
    while (at + 12 <= bytes.length) {
      const length = view.getUint32(at);
      const chunk = ascii(at + 4, 4);
      if (at + 12 + length > bytes.length) throw invalid();
      if (chunk === 'acTL' || chunk === 'fcTL' || chunk === 'fdAT') throw animationError();
      at += length + 12;
      if (chunk === 'IEND') { sawEnd = true; break; }
    }
    if (!sawEnd) throw invalid();
  } else if (bytes.length >= 4 && bytes[0] === 255 && bytes[1] === 216) {
    type = 'image/jpeg';
    let at = 2;
    const frameMarkers = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
    while (at < bytes.length) {
      if (bytes[at] !== 255) throw invalid();
      while (at < bytes.length && bytes[at] === 255) at += 1;
      if (at >= bytes.length) throw invalid();
      const marker = bytes[at++];
      if (marker === 0xd9 || marker === 0xda) break;
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) continue;
      if (at + 2 > bytes.length) throw invalid();
      const length = view.getUint16(at);
      if (length < 2 || at + length > bytes.length) throw invalid();
      if (frameMarkers.has(marker)) {
        if (length < 8) throw invalid();
        size = dimensions(view.getUint16(at + 5), view.getUint16(at + 3));
        break;
      }
      at += length;
    }
    if (!size) throw invalid();
  } else if (bytes.length >= 20 && ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') {
    type = 'image/webp';
    const total = view.getUint32(4, true) + 8;
    if (total !== bytes.length) throw invalid();
    let at = 12;
    let sawPixels = false;
    while (at + 8 <= total) {
      const chunk = ascii(at, 4);
      const length = view.getUint32(at + 4, true);
      const start = at + 8;
      if (start + length > total) throw invalid();
      if (chunk === 'ANIM' || chunk === 'ANMF') throw animationError();
      if (chunk === 'VP8X') {
        if (length < 10) throw invalid();
        if (bytes[start] & 0x02) throw animationError();
        size = dimensions(u24(start + 4) + 1, u24(start + 7) + 1);
      } else if (chunk === 'VP8 ') {
        if (length < 10 || bytes[start + 3] !== 0x9d || bytes[start + 4] !== 0x01 || bytes[start + 5] !== 0x2a) throw invalid();
        const frame = dimensions(view.getUint16(start + 6, true) & 0x3fff, view.getUint16(start + 8, true) & 0x3fff);
        if (!size) size = frame;
        sawPixels = true;
      } else if (chunk === 'VP8L') {
        if (length < 5 || bytes[start] !== 0x2f) throw invalid();
        const packed = view.getUint32(start + 1, true);
        const frame = dimensions((packed & 0x3fff) + 1, ((packed >>> 14) & 0x3fff) + 1);
        if (!size) size = frame;
        sawPixels = true;
      }
      at = start + length + (length % 2);
    }
    if (!size || !sawPixels || at !== total) throw invalid();
  } else throw invalid();

  if (file.type && file.type.toLowerCase() !== type) throw new ImageInputError('imageTypeMismatch');
  if (!size) throw invalid();
  return { ...size, type };
}
