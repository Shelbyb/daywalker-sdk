import fs from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import type { KeyStore, StoredSigningKey } from "../types.js";
import { parseStoredSigningKey } from "./index.js";

export interface FileKeyStoreOptions {
  /** Default `.daywalker/signing-key.json` in the working directory. Keep it out of version control. */
  path?: string;
}

/** Largest key file read. A real one is a few hundred bytes. */
const MAX_FILE_BYTES = 4096;

/**
 * Keeps the key in a file (Node.js only), for VMs and containers with a persistent volume.
 * - Written to a private 0600 temp file, then hard-linked into place inside a 0700 directory: `link()` fails
 *   when the file exists, so of several processes starting at once exactly one publishes its key, and no reader
 *   ever sees a half-written file.
 * - Never follows a symlink and refuses a file that isn't a regular file, isn't owned by this user, or is
 *   readable or writable by group or others, like ssh does for private keys.
 */
export function fileKeyStore(options: FileKeyStoreOptions = {}): KeyStore {
  const file = path.resolve(options.path ?? path.join(".daywalker", "signing-key.json"));
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;

  async function load(): Promise<StoredSigningKey | null> {
    let handle: fs.FileHandle;
    try {
      // O_NONBLOCK: a FIFO at the path would otherwise block here, before the regular-file check.
      handle = await fs.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return null;
      if (code === "ELOOP") throw new Error(`${file} is a symlink; refusing to read a signing key through it`);
      throw err;
    }
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) throw new Error(`${file} is not a regular file`);
      if (process.platform !== "win32") {
        if ((stat.mode & 0o077) !== 0) throw new Error(`${file} is readable or writable by others (mode ${(stat.mode & 0o777).toString(8)}); chmod 600 it`);
        if (uid !== undefined && stat.uid !== uid) throw new Error(`${file} is not owned by this user`);
      }
      if (stat.size > MAX_FILE_BYTES) throw new Error(`${file} is too large to be a signing key`);
      let parsed: unknown;
      try {
        parsed = JSON.parse(await handle.readFile("utf8"));
      } catch {
        // JSON.parse's message quotes part of the input, i.e. of the private key.
        throw new Error(`${file} is not valid JSON`);
      }
      return parseStoredSigningKey(parsed);
    } finally {
      await handle.close();
    }
  }

  async function saveIfAbsent(key: StoredSigningKey): Promise<boolean> {
    const record = parseStoredSigningKey(key);
    const dir = path.dirname(file);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    // Written in full to a private temp file first, then hard-linked into place: link() fails if the target
    // exists, so publishing is atomic and a reader never sees a half-written key.
    const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`);
    const handle = await fs.open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
      await handle.sync();
      await handle.close();
      try {
        await fs.link(tmp, file);
        return true;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw err;
      }
    } finally {
      await handle.close().catch(() => {});
      await fs.rm(tmp, { force: true });
    }
  }

  return Object.freeze({ load, saveIfAbsent });
}
