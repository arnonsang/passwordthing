const _buf = new Uint32Array(256);
let _idx = 256;

export function nextUint32(): number {
  if (_idx >= _buf.length) {
    globalThis.crypto.getRandomValues(_buf);
    _idx = 0;
  }
  return _buf[_idx++]!;
}
