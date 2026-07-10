/**
 * Minimal read-only ZIP parser in pure Node (fs + zlib only) so `npx confessor`
 * can open export zips with zero dependencies. Supports stored (0) and
 * deflated (8) entries plus basic ZIP64 offsets. Reads the central directory,
 * then extracts only the entries the caller asks for — a multi-GB ChatGPT
 * export with images never gets fully loaded into memory.
 */
import * as fs from 'node:fs';
import * as zlib from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const ZIP64_EOCD_LOCATOR_SIG = 0x07064b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

const MAX_ENTRY_BYTES = 1024 * 1024 * 1024; // refuse to inflate >1 GiB single entries

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

export class ZipReader {
  private fd: number;
  private size: number;
  readonly entries: ZipEntry[];

  constructor(private filePath: string) {
    this.fd = fs.openSync(filePath, 'r');
    this.size = fs.fstatSync(this.fd).size;
    try {
      this.entries = this.readCentralDirectory();
    } catch (err) {
      this.close();
      throw err;
    }
  }

  close(): void {
    try {
      fs.closeSync(this.fd);
    } catch {
      /* already closed */
    }
  }

  private readAt(offset: number, length: number): Buffer {
    const buf = Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const n = fs.readSync(this.fd, buf, done, length - done, offset + done);
      if (n <= 0) break;
      done += n;
    }
    if (done !== length) throw new Error(`zip: short read at ${offset}`);
    return buf;
  }

  private readCentralDirectory(): ZipEntry[] {
    if (this.size < 22) throw new Error('zip: file too small');
    // EOCD is in the last 22..(22+65535) bytes (variable-length comment).
    const tailLen = Math.min(this.size, 22 + 65535);
    const tail = this.readAt(this.size - tailLen, tailLen);
    let eocdPos = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === EOCD_SIG) {
        eocdPos = i;
        break;
      }
    }
    if (eocdPos === -1) throw new Error('zip: end-of-central-directory not found (is this a zip file?)');

    let entryCount: number = tail.readUInt16LE(eocdPos + 10);
    let cdSize: number = tail.readUInt32LE(eocdPos + 12);
    let cdOffset: number = tail.readUInt32LE(eocdPos + 16);

    // ZIP64: sentinel values mean the real numbers live in the ZIP64 EOCD.
    if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const locatorPos = this.size - tailLen + eocdPos - 20;
      if (locatorPos >= 0) {
        const locator = this.readAt(locatorPos, 20);
        if (locator.readUInt32LE(0) === ZIP64_EOCD_LOCATOR_SIG) {
          const zip64EocdOffset = Number(locator.readBigUInt64LE(8));
          const z = this.readAt(zip64EocdOffset, 56);
          if (z.readUInt32LE(0) === ZIP64_EOCD_SIG) {
            entryCount = Number(z.readBigUInt64LE(32));
            cdSize = Number(z.readBigUInt64LE(40));
            cdOffset = Number(z.readBigUInt64LE(48));
          }
        }
      }
    }

    if (cdSize > 512 * 1024 * 1024) throw new Error('zip: central directory implausibly large');
    const cd = this.readAt(cdOffset, cdSize);
    const entries: ZipEntry[] = [];
    let p = 0;
    for (let i = 0; i < entryCount && p + 46 <= cd.length; i++) {
      if (cd.readUInt32LE(p) !== CENTRAL_SIG) break;
      const method = cd.readUInt16LE(p + 10);
      let compressedSize: number = cd.readUInt32LE(p + 20);
      let uncompressedSize: number = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      let localHeaderOffset: number = cd.readUInt32LE(p + 42);
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString('utf8');

      // ZIP64 extra field (id 0x0001) overrides any 0xffffffff fields, in order:
      // uncompressed size, compressed size, local header offset.
      if (
        uncompressedSize === 0xffffffff ||
        compressedSize === 0xffffffff ||
        localHeaderOffset === 0xffffffff
      ) {
        let ep = p + 46 + nameLen;
        const eend = ep + extraLen;
        while (ep + 4 <= eend) {
          const id = cd.readUInt16LE(ep);
          const len = cd.readUInt16LE(ep + 2);
          if (id === 0x0001) {
            let fp = ep + 4;
            if (uncompressedSize === 0xffffffff && fp + 8 <= ep + 4 + len) {
              uncompressedSize = Number(cd.readBigUInt64LE(fp));
              fp += 8;
            }
            if (compressedSize === 0xffffffff && fp + 8 <= ep + 4 + len) {
              compressedSize = Number(cd.readBigUInt64LE(fp));
              fp += 8;
            }
            if (localHeaderOffset === 0xffffffff && fp + 8 <= ep + 4 + len) {
              localHeaderOffset = Number(cd.readBigUInt64LE(fp));
              fp += 8;
            }
            break;
          }
          ep += 4 + len;
        }
      }

      entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
      p += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  }

  /** Extract one entry fully into memory. */
  read(entry: ZipEntry): Buffer {
    if (entry.compressedSize > MAX_ENTRY_BYTES || entry.uncompressedSize > MAX_ENTRY_BYTES) {
      throw new Error(`zip: entry ${entry.name} too large`);
    }
    const header = this.readAt(entry.localHeaderOffset, 30);
    if (header.readUInt32LE(0) !== LOCAL_SIG) {
      throw new Error(`zip: bad local header for ${entry.name}`);
    }
    const nameLen = header.readUInt16LE(26);
    const extraLen = header.readUInt16LE(28);
    const dataOffset = entry.localHeaderOffset + 30 + nameLen + extraLen;
    const compressed = this.readAt(dataOffset, entry.compressedSize);
    if (entry.method === 0) return compressed;
    if (entry.method === 8) return zlib.inflateRawSync(compressed);
    throw new Error(`zip: unsupported compression method ${entry.method} for ${entry.name}`);
  }

  /** Find entries whose path matches a predicate. */
  find(predicate: (name: string) => boolean): ZipEntry[] {
    return this.entries.filter((e) => !e.name.endsWith('/') && predicate(e.name));
  }
}
