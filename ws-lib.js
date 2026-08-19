'use strict';
/*
 * Familja Chat — WebSocket minimal i implementuar në Node të pastër (RFC 6455).
 * Mbështet: tekst, ping/pong, close, fragmentim (continuation frames).
 */
const crypto = require('crypto');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

class WSConn {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.frags = null;      // fragmentim në vazhdim
    this.fragOp = 0;
    this.closed = false;
    this.lastActivity = Date.now();
    this.onmessage = null;  // (text) => void
    this.onclose = null;    // () => void

    socket.on('data', (d) => {
      if (this.closed) return;
      this.buffer = Buffer.concat([this.buffer, d]);
      this._process();
    });
    socket.on('error', () => this._end());
    socket.on('close', () => this._end());
  }

  _end() {
    if (this.closed) return;
    this.closed = true;
    if (this.onclose) this.onclose();
  }

  _process() {
    while (!this.closed) {
      let f;
      try { f = this._parse(); } catch (e) { this.close(1002); return; }
      if (!f) return;
      this.lastActivity = Date.now();
      if (f.opcode === 8) { // close
        try { this.socket.end(Buffer.from([0x88, 0x00])); } catch (e) {}
        this._end();
        return;
      }
      if (f.opcode === 9) { this._sendFrame(10, f.payload); continue; } // ping -> pong
      if (f.opcode === 10) continue; // pong
      if (f.opcode === 0) { // continuation
        if (this.frags) {
          this.frags.push(f.payload);
          if (f.fin) {
            const full = Buffer.concat(this.frags);
            const op = this.fragOp;
            this.frags = null;
            this._emit(op, full);
          }
        }
        continue;
      }
      if (f.opcode === 1 || f.opcode === 2) {
        if (f.fin) this._emit(f.opcode, f.payload);
        else { this.frags = [f.payload]; this.fragOp = f.opcode; }
        continue;
      }
      this.close(1002); // opcode i panjohur
      return;
    }
  }

  _emit(op, payload) {
    if (op === 1 && this.onmessage) this.onmessage(payload.toString('utf8'));
  }

  _parse() {
    const buf = this.buffer;
    if (buf.length < 2) return null;
    const b0 = buf[0], b1 = buf[1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let off = 2;
    if (len === 126) {
      if (buf.length < 4) return null;
      len = buf.readUInt16BE(2); off = 4;
    } else if (len === 127) {
      if (buf.length < 10) return null;
      const big = buf.readBigUInt64BE(2);
      if (big > BigInt(2 * 1024 * 1024)) { this.close(1009); return null; }
      len = Number(big); off = 10;
    }
    let mask = null;
    if (masked) {
      if (buf.length < off + 4) return null;
      mask = buf.subarray(off, off + 4);
      off += 4;
    }
    if (buf.length < off + len) return null;
    let payload = buf.subarray(off, off + len);
    if (masked) {
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
      payload = out;
    }
    this.buffer = buf.subarray(off + len);
    return { fin, opcode, payload };
  }

  _sendFrame(opcode, payload) {
    if (this.closed) return;
    const len = payload.length;
    let header;
    if (len < 126) { header = Buffer.allocUnsafe(2); header[1] = len; }
    else if (len < 65536) { header = Buffer.allocUnsafe(4); header[1] = 126; header.writeUInt16BE(len, 2); }
    else { header = Buffer.allocUnsafe(10); header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
    header[0] = 0x80 | opcode;
    try { this.socket.write(Buffer.concat([header, payload])); } catch (e) {}
  }

  send(str) { this._sendFrame(1, Buffer.from(String(str), 'utf8')); }
  sendObj(obj) { this.send(JSON.stringify(obj)); }
  ping() { this._sendFrame(9, Buffer.alloc(0)); }
  close(code = 1000) {
    if (this.closed) return;
    const b = Buffer.allocUnsafe(2);
    b.writeUInt16BE(code, 0);
    this._sendFrame(8, b);
    try { this.socket.end(); } catch (e) {}
    this._end();
  }
}

function acceptKey(key) {
  return crypto.createHash('sha1').update(key + GUID).digest('base64');
}

module.exports = { WSConn, acceptKey };
