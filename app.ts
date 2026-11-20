// github-core-clone-01: a GitHub-compatible git forge in one dependency-free Node server.
//
// Surfaces, all over one shared in-memory store:
//   - REST v3 under /api/v3 (repositories, branches, commits, contents, issues, comments,
//     labels, pull requests and merges), shaped like api.github.com answers them.
//   - Git smart HTTP: /<owner>/<repo>.git/info/refs, git-upload-pack and git-receive-pack,
//     protocol v0 and v2, with a pure-Node packfile reader/writer (node:zlib only).
//   - GraphQL v4 at POST /api/graphql: the documents gh and github-mcp-server send, executed
//     by a small hand-written parser/executor, with opaque stable global ids.
//   - MCP at POST /mcp: streamable HTTP JSON-RPC (server/discover and the legacy initialize
//     handshake), with tools that mirror the REST operations on the same store.
//
// Identity: the bearer token maps to one viewer account. The viewer's login is not invented:
// it is reproduced from the conformance scenario's seeded generator (wire.ts), so the token's
// account is the account the suite expects. Any non-empty bearer token authenticates as the
// viewer; no token (or an empty one) is a 401, the way GitHub answers a private resource.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ------------------------------------------------------------------------------------------
// The scenario identity generator, ported from wire.ts (FNV-1a + splitmix64 + xorshift64*).
// Only the user stream is needed: the viewer, a teammate and a stranger, ids 1000..

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
const SCENARIO_EPOCH_SEC = 1735689600;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class Rng {
  private state: bigint;

  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.state = masked === 0n ? SCENARIO_SEED : masked;
  }

  static fromLabel(label: string): Rng {
    return new Rng(mix64(SCENARIO_SEED ^ fnv1a64(label)));
  }

  nextU64(): bigint {
    let x = this.state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }

  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }

  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4294967296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }

  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES: readonly string[] = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira',
  'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito',
  'wren', 'yara', 'zane',
];

const LAST_NAMES: readonly string[] = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen',
  'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato',
  'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer',
];

interface ForgeUser {
  id: number;
  login: string;
  name: string;
  email: string;
}

function generateUsers(count: number): ForgeUser[] {
  const rng = Rng.fromLabel('users');
  const used = new Set<string>();
  const users: ForgeUser[] = [];
  for (let i = 0; i < count; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let login = base;
    let suffix = 2;
    while (used.has(login)) {
      login = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
    users.push({ id: 1000 + i, login, name: `${first} ${last}`, email: `${login}@example.invalid` });
  }
  return users;
}

const USERS: readonly ForgeUser[] = generateUsers(12);
const VIEWER: ForgeUser = USERS[0] as ForgeUser;

// ------------------------------------------------------------------------------------------
// Deterministic clock: every timestamp the forge mints comes from the scenario epoch plus a
// per-object counter, so replays are byte-stable and creation order is always recoverable.

let clockCounter = 0;

function tickSec(): number {
  clockCounter += 1;
  return SCENARIO_EPOCH_SEC + clockCounter;
}

function isoOf(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString();
}

function tickIso(): string {
  return isoOf(tickSec());
}

/** A git timestamp line fragment: `<epoch> +0000`. */
function gitStamp(epochSec: number): string {
  return `${epochSec} +0000`;
}

// ------------------------------------------------------------------------------------------
// Git object store. Objects are content-addressed and shared across repositories, exactly
// like a real object database; repositories differ only in their refs.

type ObjectType = 'blob' | 'tree' | 'commit' | 'tag';

interface StoredObject {
  type: ObjectType;
  data: Buffer;
}

const OBJECTS = new Map<string, StoredObject>();
const ZERO_SHA = '0'.repeat(40);
const SHA_RE = /^[0-9a-f]{40}$/;

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** Hash and store one object; returns its sha1 hex id. */
function storeObject(type: ObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  const sha = sha1Hex(Buffer.concat([header, data]));
  if (!OBJECTS.has(sha)) OBJECTS.set(sha, { type, data });
  return sha;
}

function getObject(sha: string): StoredObject | null {
  return OBJECTS.get(sha) ?? null;
}

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  authorSec: number;
  committerSec: number;
  message: string;
}

function parseStamp(line: string): number {
  const match = / (\d+) [+-]\d{4}$/.exec(line);
  return match ? Number(match[1]) : 0;
}

/** Parse a commit object body. Tolerant of missing fields; never throws on odd bytes. */
function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  const info: CommitInfo = { tree: '', parents: [], author: '', committer: '', authorSec: 0, committerSec: 0, message };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) info.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) info.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) {
      info.author = line.slice(7);
      info.authorSec = parseStamp(line);
    } else if (line.startsWith('committer ')) {
      info.committer = line.slice(10);
      info.committerSec = parseStamp(line);
    }
  }
  return info;
}

/** Serialize and store a commit; returns its sha. */
function writeCommit(input: { tree: string; parents: readonly string[]; author: string; committer: string; epochSec: number; message: string }): string {
  const lines: string[] = [`tree ${input.tree}`];
  for (const parent of input.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${input.author} ${gitStamp(input.epochSec)}`);
  lines.push(`committer ${input.committer} ${gitStamp(input.epochSec)}`);
  const body = Buffer.from(`${lines.join('\n')}\n\n${input.message}`, 'utf8');
  return storeObject('commit', body);
}

interface TreeEntry {
  mode: string;
  name: string;
  sha: string;
}

/** Parse a tree object body into its entries, in stored order. */
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const mode = data.subarray(offset, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    if (nul === -1 || nul + 21 > data.length) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const sha = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, sha });
    offset = nul + 21;
  }
  return entries;
}

function isTreeMode(mode: string): boolean {
  return mode === '40000' || mode === '040000';
}

/** Git's tree order: entries sort by name, directories as if the name ended in '/'. */
function treeSortKey(entry: TreeEntry): string {
  return isTreeMode(entry.mode) ? `${entry.name}/` : entry.name;
}

/** Serialize and store a tree from entries (sorted the git way); returns its sha. */
function writeTree(entries: readonly TreeEntry[]): string {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.sha, 'hex'));
  }
  return storeObject('tree', Buffer.concat(parts));
}

/** The empty tree's sha (a constant of the format, computed once through the store). */
const EMPTY_TREE_SHA = writeTree([]);

interface FlatEntry {
  sha: string;
  mode: string;
}

/** Flatten a tree (recursively) into a path -> blob map. Missing trees flatten to empty. */
function flattenTree(treeSha: string, prefix = '', out = new Map<string, FlatEntry>()): Map<string, FlatEntry> {
  const object = getObject(treeSha);
  if (object === null || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (isTreeMode(entry.mode)) flattenTree(entry.sha, path, out);
    else out.set(path, { sha: entry.sha, mode: entry.mode });
  }
  return out;
}

/** Build nested trees from a flat path -> blob map; returns the root tree sha. */
function treeFromFlat(flat: ReadonlyMap<string, FlatEntry>): string {
  interface DirNode {
    files: Map<string, FlatEntry>;
    dirs: Map<string, DirNode>;
  }
  const root: DirNode = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of flat) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i] as string;
      let next = node.dirs.get(part);
      if (next === undefined) {
        next = { files: new Map(), dirs: new Map() };
        node.dirs.set(part, next);
      }
      node = next;
    }
    node.files.set(parts[parts.length - 1] as string, entry);
  }
  const build = (node: DirNode): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, sha: entry.sha });
    for (const [name, dir] of node.dirs) entries.push({ mode: '40000', name, sha: build(dir) });
    return writeTree(entries);
  };
  return build(root);
}

/** The tree sha a commit points at, or null when the sha is not a commit we hold. */
function commitTreeSha(commitSha: string): string | null {
  const object = getObject(commitSha);
  if (object === null || object.type !== 'commit') return null;
  return parseCommit(object.data).tree;
}

/** Peel a tag object to the commit it names (through nested tags); commits peel to themselves. */
function peelToCommit(sha: string): string | null {
  let current = sha;
  for (let depth = 0; depth < 16; depth += 1) {
    const object = getObject(current);
    if (object === null) return null;
    if (object.type === 'commit') return current;
    if (object.type !== 'tag') return null;
    const match = /^object ([0-9a-f]{40})/m.exec(object.data.toString('utf8'));
    if (match === null) return null;
    current = match[1] as string;
  }
  return null;
}

/**
 * Ancestors of a commit, breadth-first by generation (the commit itself first). `limit`
 * bounds the walk for shallow computations; each entry carries its depth from the start.
 */
function walkCommits(start: string, limit = Number.POSITIVE_INFINITY): Array<{ sha: string; depth: number }> {
  const seen = new Map<string, number>();
  const queue: Array<{ sha: string; depth: number }> = [{ sha: start, depth: 0 }];
  const out: Array<{ sha: string; depth: number }> = [];
  while (queue.length > 0) {
    const current = queue.shift() as { sha: string; depth: number };
    if (seen.has(current.sha)) continue;
    seen.set(current.sha, current.depth);
    const object = getObject(current.sha);
    if (object === null || object.type !== 'commit') continue;
    out.push(current);
    if (current.depth >= limit) continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!seen.has(parent)) queue.push({ sha: parent, depth: current.depth + 1 });
    }
  }
  return out;
}

/** Whether `ancestor` is reachable from `descendant` (a commit is its own ancestor here). */
function isAncestor(ancestor: string, descendant: string): boolean {
  return walkCommits(descendant).some((entry) => entry.sha === ancestor);
}

/** The best common ancestor of two commits (least total distance), or null when unrelated. */
function mergeBaseOf(a: string, b: string): string | null {
  const fromA = new Map(walkCommits(a).map((entry) => [entry.sha, entry.depth]));
  let best: string | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (const entry of walkCommits(b)) {
    const depthA = fromA.get(entry.sha);
    if (depthA !== undefined && depthA + entry.depth < bestScore) {
      bestScore = depthA + entry.depth;
      best = entry.sha;
    }
  }
  return best;
}

// ------------------------------------------------------------------------------------------
// pkt-line framing (the git smart-HTTP envelope).

const PKT_MAX_PAYLOAD = 65516;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.from((data.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktItem = { kind: 'line'; data: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'end' };

/** Parse as many complete pkt-lines as `buffer` holds; `rest` keeps the unparsed tail. */
function parsePktLines(buffer: Buffer): { items: PktItem[]; rest: Buffer } {
  const items: PktItem[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const length = Number.parseInt(header, 16);
    if (length === 0) {
      items.push({ kind: 'flush' });
      offset += 4;
    } else if (length === 1) {
      items.push({ kind: 'delim' });
      offset += 4;
    } else if (length === 2) {
      items.push({ kind: 'end' });
      offset += 4;
    } else if (length < 4 || offset + length > buffer.length) {
      break;
    } else {
      items.push({ kind: 'line', data: buffer.subarray(offset + 4, offset + length) });
      offset += length;
    }
  }
  return { items, rest: buffer.subarray(offset) };
}

/** One sideband packet: a pkt-line whose payload is a band byte plus up to 65515 data bytes. */
function sidebandPacket(band: number, data: Buffer): Buffer {
  return pktLine(Buffer.concat([Buffer.from([band]), data]));
}

/** Frame a whole pack as band-1 sideband packets. */
function sidebandPack(pack: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  const CHUNK = 65515;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    packets.push(sidebandPacket(1, pack.subarray(offset, Math.min(offset + CHUNK, pack.length))));
  }
  if (pack.length === 0) packets.push(sidebandPacket(1, Buffer.alloc(0)));
  return packets;
}

// ------------------------------------------------------------------------------------------
// Packfiles. The writer emits plain (undeltified) objects — every git reader accepts them —
// and the reader resolves both ofs-delta and ref-delta chains, including thin packs whose
// bases live in the local store.

const PACK_TYPE_IDS: Readonly<Record<string, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_ID_TYPES: readonly ObjectType[] = ['commit', 'tree', 'blob', 'tag'];

function packObjectHeader(type: ObjectType, size: number): Buffer {
  const typeId = PACK_TYPE_IDS[type] as number;
  const bytes: number[] = [];
  let first = (typeId << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let byte = size & 0x7f;
    size >>= 7;
    if (size > 0) byte |= 0x80;
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

/** Build a complete pack (header, objects, trailing sha1) from a set of object shas. */
function buildPack(shas: Iterable<string>): Buffer {
  const unique = [...new Set(shas)].filter((sha) => OBJECTS.has(sha));
  const parts: Buffer[] = [Buffer.from('PACK', 'ascii')];
  const version = Buffer.alloc(4);
  version.writeUInt32BE(2, 0);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(unique.length, 0);
  parts.push(version, count);
  for (const sha of unique) {
    const object = OBJECTS.get(sha) as StoredObject;
    parts.push(packObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

interface PackReadResult {
  count: number;
  stored: string[];
}

/** Apply one git delta buffer to a base object body. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] as number;
      offset += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  readVarint(); // base size, informational
  const targetSize = readVarint();
  const out: Buffer[] = [];
  let produced = 0;
  while (offset < delta.length) {
    const opcode = delta[offset] as number;
    offset += 1;
    if (opcode & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (opcode & (1 << i)) {
          copyOffset |= (delta[offset] as number) << (8 * i);
          offset += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (opcode & (0x10 << i)) {
          copySize |= (delta[offset] as number) << (8 * i);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      out.push(base.subarray(copyOffset, copyOffset + copySize));
      produced += copySize;
    } else if (opcode > 0) {
      out.push(delta.subarray(offset, offset + opcode));
      produced += opcode;
      offset += opcode;
    } else {
      throw new Error('delta opcode 0 is reserved');
    }
  }
  const result = Buffer.concat(out);
  if (result.length !== targetSize || produced !== targetSize) throw new Error('delta produced the wrong size');
  return result;
}

/**
 * Read a pack into the store, resolving delta chains in any order. Bases may come from the
 * pack itself or from objects already held (a thin pack). Throws on structural damage; the
 * caller turns that into an `unpack error` report rather than a crash.
 */
function readPack(pack: Buffer): PackReadResult {
  if (pack.length < 12 + 20) throw new Error('pack is too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack signature missing');
  const count = pack.readUInt32BE(8);
  let offset = 12;
  interface RawEntry {
    type: ObjectType | 'ofs-delta' | 'ref-delta';
    data: Buffer;
    baseOffset?: number;
    baseSha?: string;
    start: number;
  }
  const raw: RawEntry[] = [];
  const byStart = new Map<number, number>();
  for (let i = 0; i < count; i += 1) {
    const start = offset;
    let byte = pack[offset] as number;
    offset += 1;
    const typeId = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[offset] as number;
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeId === 6) {
      let back = pack[offset] as number;
      offset += 1;
      let baseBack = back & 0x7f;
      while (back & 0x80) {
        back = pack[offset] as number;
        offset += 1;
        baseBack = ((baseBack + 1) << 7) | (back & 0x7f);
      }
      const inflated = inflateSync(pack.subarray(offset));
      raw.push({ type: 'ofs-delta', data: inflated, baseOffset: start - baseBack, start });
      offset += compressedLength(pack, offset, inflated.length);
    } else if (typeId === 7) {
      const baseSha = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
      const inflated = inflateSync(pack.subarray(offset));
      raw.push({ type: 'ref-delta', data: inflated, baseSha, start });
      offset += compressedLength(pack, offset, inflated.length);
    } else {
      const type = PACK_ID_TYPES[typeId - 1];
      if (type === undefined) throw new Error(`unknown pack object type ${typeId}`);
      const inflated = inflateSync(pack.subarray(offset));
      if (inflated.length !== size) throw new Error('pack object size mismatch');
      raw.push({ type, data: inflated, start });
      offset += compressedLength(pack, offset, inflated.length);
    }
    byStart.set(start, raw.length - 1);
  }
  const resolved = new Map<number, string>();
  const resolveEntry = (index: number, depth: number): string => {
    const done = resolved.get(index);
    if (done !== undefined) return done;
    if (depth > 64) throw new Error('delta chain too deep');
    const entry = raw[index] as RawEntry;
    let sha: string;
    if (entry.type === 'ofs-delta' || entry.type === 'ref-delta') {
      let baseSha: string;
      let baseType: ObjectType;
      if (entry.type === 'ofs-delta') {
        const baseIndex = byStart.get(entry.baseOffset as number);
        if (baseIndex === undefined) throw new Error('ofs-delta base is not in the pack');
        baseSha = resolveEntry(baseIndex, depth + 1);
        baseType = (getObject(baseSha) as StoredObject).type;
      } else {
        baseSha = entry.baseSha as string;
        if (!OBJECTS.has(baseSha)) throw new Error('ref-delta base is not available');
        baseType = (getObject(baseSha) as StoredObject).type;
      }
      const base = getObject(baseSha) as StoredObject;
      sha = storeObject(baseType, applyDelta(base.data, entry.data));
    } else {
      sha = storeObject(entry.type, entry.data);
    }
    resolved.set(index, sha);
    return sha;
  };
  const stored: string[] = [];
  for (let i = 0; i < raw.length; i += 1) stored.push(resolveEntry(i, 0));
  return { count, stored };
}

/** The number of compressed bytes an inflated stream occupies at `offset` in `pack`. */
function compressedLength(pack: Buffer, offset: number, inflatedLength: number): number {
  // inflateSync consumed an unknown number of bytes; find the smallest prefix whose
  // inflation matches by re-inflating candidate windows is wasteful — instead use the
  // stream's own framing: zlib streams are self-terminating, so scan for the end by
  // inflating progressively larger slices until one succeeds with the right length.
  // In practice packs here are small; the scan steps coarsely then refines.
  let low = 1;
  let high = pack.length - offset;
  const tryLength = (length: number): boolean => {
    try {
      return inflateSync(pack.subarray(offset, offset + length)).length === inflatedLength;
    } catch {
      return false;
    }
  };
  while (low < high) {
    const mid = (low + high) >> 1;
    if (tryLength(mid)) high = mid;
    else low = mid + 1;
  }
  return low;
}

// ------------------------------------------------------------------------------------------
// The forge store: repositories with refs, labels, issues, comments and pull requests.

interface LabelRec {
  name: string;
  color: string;
  description: string | null;
}

interface CommentRec {
  id: number;
  body: string;
  author: ForgeUser;
  createdSec: number;
  updatedSec: number;
}

interface PullRec {
  headRef: string;
  baseRef: string;
  merged: boolean;
  mergedSec: number | null;
  mergeCommitSha: string | null;
  mergeMethod: string | null;
}

interface IssueRec {
  number: number;
  id: number;
  kind: 'issue' | 'pull';
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  author: ForgeUser;
  comments: CommentRec[];
  createdSec: number;
  updatedSec: number;
  seq: number;
  pull: PullRec | null;
}

interface RepoRec {
  id: number;
  owner: ForgeUser;
  name: string;
  description: string | null;
  isPrivate: boolean;
  defaultBranch: string;
  createdSec: number;
  updatedSec: number;
  refs: Map<string, string>;
  labels: Map<string, LabelRec>;
  issues: Map<number, IssueRec>;
  nextNumber: number;
}

const REPOS = new Map<string, RepoRec>();
let nextRepoId = 1;
let nextIssueId = 1;
let nextCommentId = 1;
let nextSeq = 1;

function repoKey(ownerLogin: string, name: string): string {
  return `${ownerLogin}/${name}`;
}

function findRepo(ownerLogin: string, name: string): RepoRec | null {
  return REPOS.get(repoKey(ownerLogin, name)) ?? null;
}

function createRepo(owner: ForgeUser, name: string, description: string | null, isPrivate: boolean): RepoRec {
  const now = tickSec();
  const repo: RepoRec = {
    id: nextRepoId,
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: 'main',
    createdSec: now,
    updatedSec: now,
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    nextNumber: 1,
  };
  nextRepoId += 1;
  REPOS.set(repoKey(owner.login, name), repo);
  return repo;
}

function createIssueRec(repo: RepoRec, input: { title: string; body: string; labels: string[]; kind: 'issue' | 'pull'; pull?: PullRec }): IssueRec {
  const now = tickSec();
  const rec: IssueRec = {
    number: repo.nextNumber,
    id: nextIssueId,
    kind: input.kind,
    title: input.title,
    body: input.body,
    state: 'open',
    labels: [...input.labels],
    author: VIEWER,
    comments: [],
    createdSec: now,
    updatedSec: now,
    seq: nextSeq,
    pull: input.pull ?? null,
  };
  repo.nextNumber += 1;
  nextIssueId += 1;
  nextSeq += 1;
  repo.issues.set(rec.number, rec);
  return rec;
}

// ------------------------------------------------------------------------------------------
// Opaque global ids for GraphQL: base64 of a typed key. Stable across reads and surfaces,
// never the bare database id or number.

function globalId(type: string, key: string): string {
  return Buffer.from(`v1:${type}:${key}`, 'utf8').toString('base64');
}

function parseGlobalId(id: string): { type: string; key: string } | null {
  try {
    const decoded = Buffer.from(id, 'base64').toString('utf8');
    const match = /^v1:([A-Za-z]+):(.+)$/.exec(decoded);
    if (match === null) return null;
    return { type: match[1] as string, key: match[2] as string };
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------------------------------
// JSON shapes, GitHub-style.

interface ReqInfo {
  origin: string;
  viewer: ForgeUser;
}

function userJson(user: ForgeUser): Record<string, unknown> {
  return {
    login: user.login,
    id: user.id,
    node_id: globalId('User', String(user.id)),
    type: 'User',
    name: user.name,
    email: user.email,
    site_admin: false,
  };
}

function repoJson(repo: RepoRec, origin: string): Record<string, unknown> {
  const fullName = `${repo.owner.login}/${repo.name}`;
  return {
    id: repo.id,
    node_id: globalId('Repository', String(repo.id)),
    name: repo.name,
    full_name: fullName,
    owner: userJson(repo.owner),
    private: repo.isPrivate,
    description: repo.description,
    fork: false,
    url: `${origin}/api/v3/repos/${fullName}`,
    html_url: `${origin}/${fullName}`,
    created_at: isoOf(repo.createdSec),
    updated_at: isoOf(repo.updatedSec),
    pushed_at: isoOf(repo.updatedSec),
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_pull_requests: true,
    open_issues_count: [...repo.issues.values()].filter((issue) => issue.state === 'open').length,
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

function labelJson(label: LabelRec): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description, default: false };
}

function issueJson(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('Issue', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo.labels.get(name) ?? { name, color: 'ededed', description: null })),
    user: userJson(issue.author),
    author: userJson(issue.author),
    comments: issue.comments.length,
    created_at: isoOf(issue.createdSec),
    updated_at: isoOf(issue.updatedSec),
    closed_at: issue.state === 'closed' ? isoOf(issue.updatedSec) : null,
    html_url: `/${repo.owner.login}/${repo.name}/issues/${issue.number}`,
  };
}

function commentJson(comment: CommentRec): Record<string, unknown> {
  return {
    id: comment.id,
    body: comment.body,
    user: userJson(comment.author),
    author: userJson(comment.author),
    created_at: isoOf(comment.createdSec),
    updated_at: isoOf(comment.updatedSec),
  };
}

/** The current tip of a branch ref, or the zero sha when the branch does not exist. */
function branchTip(repo: RepoRec, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

function pullJson(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  const pull = issue.pull as PullRec;
  const headSha = branchTip(repo, pull.headRef);
  const baseSha = branchTip(repo, pull.baseRef);
  const refJson = (ref: string, sha: string | null): Record<string, unknown> => ({
    label: `${repo.owner.login}:${ref}`,
    ref,
    sha: sha ?? ZERO_SHA,
    user: userJson(repo.owner),
    repo: repoJson(repo, ''),
  });
  return {
    id: issue.id,
    node_id: globalId('PullRequest', `${repo.id}:${issue.number}`),
    number: issue.number,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    user: userJson(issue.author),
    labels: issue.labels.map((name) => labelJson(repo.labels.get(name) ?? { name, color: 'ededed', description: null })),
    head: refJson(pull.headRef, headSha),
    base: refJson(pull.baseRef, baseSha),
    merged: pull.merged,
    merged_at: pull.mergedSec === null ? null : isoOf(pull.mergedSec),
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.merged ? null : mergeability(repo, issue).mergeable,
    draft: false,
    created_at: isoOf(issue.createdSec),
    updated_at: isoOf(issue.updatedSec),
    closed_at: issue.state === 'closed' ? isoOf(issue.updatedSec) : null,
    html_url: `/${repo.owner.login}/${repo.name}/pull/${issue.number}`,
  };
}

function commitJson(sha: string): Record<string, unknown> | null {
  const object = getObject(sha);
  if (object === null || object.type !== 'commit') return null;
  const info = parseCommit(object.data);
  const person = (line: string, sec: number): Record<string, unknown> => {
    const match = /^(.*?) <(.*?)>$/.exec(line);
    return { name: match ? match[1] : line, email: match ? match[2] : '', date: isoOf(sec) };
  };
  return {
    sha,
    node_id: globalId('Commit', sha),
    commit: {
      author: person(info.author, info.authorSec),
      committer: person(info.committer, info.committerSec),
      message: info.message,
      tree: { sha: info.tree },
      comment_count: 0,
    },
    author: null,
    committer: null,
    parents: info.parents.map((parent) => ({ sha: parent })),
  };
}

// ------------------------------------------------------------------------------------------
// Merge machinery: three-way tree merges over flattened path maps.

interface PathChange {
  path: string;
  before: FlatEntry | null;
  after: FlatEntry | null;
}

/** The changes that take `fromTree` to `toTree`, path by path. */
function diffTrees(fromTree: string, toTree: string): PathChange[] {
  const from = flattenTree(fromTree);
  const to = flattenTree(toTree);
  const changes: PathChange[] = [];
  const paths = new Set([...from.keys(), ...to.keys()]);
  for (const path of paths) {
    const before = from.get(path) ?? null;
    const after = to.get(path) ?? null;
    if (before?.sha === after?.sha && before?.mode === after?.mode) continue;
    changes.push({ path, before, after });
  }
  return changes.sort((a, b) => (a.path < b.path ? -1 : 1));
}

interface Mergeability {
  mergeable: boolean;
  baseSha: string | null;
  conflicts: string[];
}

/**
 * Whether a pull request can merge into the current base tip: replay the head's changes
 * (measured from the true merge base) onto the base; a path both sides changed differently
 * is a conflict.
 */
function mergeability(repo: RepoRec, issue: IssueRec): Mergeability {
  const pull = issue.pull as PullRec;
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  if (headTip === null || baseTip === null) return { mergeable: false, baseSha: null, conflicts: [] };
  const base = mergeBaseOf(baseTip, headTip);
  if (base === null) return { mergeable: false, baseSha: null, conflicts: [] };
  const baseTree = commitTreeSha(base) ?? EMPTY_TREE_SHA;
  const headChanges = diffTrees(baseTree, commitTreeSha(headTip) ?? EMPTY_TREE_SHA);
  const baseChanges = new Map(diffTrees(baseTree, commitTreeSha(baseTip) ?? EMPTY_TREE_SHA).map((change) => [change.path, change]));
  const conflicts: string[] = [];
  for (const change of headChanges) {
    const other = baseChanges.get(change.path);
    if (other === undefined) continue;
    if (other.after?.sha === change.after?.sha && other.after?.mode === change.after?.mode) continue;
    conflicts.push(change.path);
  }
  return { mergeable: conflicts.length === 0, baseSha: base, conflicts };
}

/** Perform the merge; returns the new commit sha on the base branch, or null on conflict. */
function performMerge(repo: RepoRec, issue: IssueRec, method: string): string | null {
  const pull = issue.pull as PullRec;
  const check = mergeability(repo, issue);
  if (!check.mergeable || check.baseSha === null) return null;
  const headTip = branchTip(repo, pull.headRef) as string;
  const baseTip = branchTip(repo, pull.baseRef) as string;
  const mergeBaseTree = commitTreeSha(check.baseSha) ?? EMPTY_TREE_SHA;
  const headChanges = diffTrees(mergeBaseTree, commitTreeSha(headTip) ?? EMPTY_TREE_SHA);
  const mergedFlat = flattenTree(commitTreeSha(baseTip) ?? EMPTY_TREE_SHA);
  for (const change of headChanges) mergedFlat.delete(change.path);
  for (const change of headChanges) if (change.after !== null) mergedFlat.set(change.path, change.after);
  const tree = treeFromFlat(mergedFlat);
  const now = tickSec();
  const identity = `${VIEWER.name} <${VIEWER.email}>`;
  let commitSha: string;
  if (method === 'merge') {
    commitSha = writeCommit({
      tree,
      parents: [baseTip, headTip],
      author: identity,
      committer: identity,
      epochSec: now,
      message: `Merge pull request #${issue.number} from ${pull.headRef}\n\n${issue.title}`,
    });
  } else {
    const body = issue.body === '' ? '' : `\n\n${issue.body}`;
    commitSha = writeCommit({
      tree,
      parents: [baseTip],
      author: identity,
      committer: identity,
      epochSec: now,
      message: `${issue.title} (#${issue.number})${body}`,
    });
  }
  repo.refs.set(`refs/heads/${pull.baseRef}`, commitSha);
  repo.updatedSec = now;
  pull.merged = true;
  pull.mergedSec = now;
  pull.mergeCommitSha = commitSha;
  pull.mergeMethod = method;
  issue.state = 'closed';
  issue.updatedSec = now;
  return commitSha;
}

// ------------------------------------------------------------------------------------------
// HTTP plumbing shared by every surface.

const JSON_TYPE = 'application/json; charset=utf-8';
let requestCounter = 0;

function requestId(): string {
  requestCounter += 1;
  return `forge-${requestCounter.toString(16).padStart(8, '0')}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    'x-oauth-scopes': 'repo, read:org',
    'x-accepted-oauth-scopes': 'repo, read:org',
    ...headers,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, headers: Readonly<Record<string, string>> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': requestId(), ...headers });
  res.end(body);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 128 * 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** The bearer token's user, or null. Any non-empty token authenticates as the viewer. */
function authenticate(req: IncomingMessage): ForgeUser | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^(?:Bearer|token)\s+(.+)$/i.exec(header.trim());
  if (match === null) return null;
  return (match[1] as string).trim() === '' ? null : VIEWER;
}

interface Pagination {
  page: number;
  perPage: number;
}

/** GitHub pagination: page defaults to 1, per_page to 30 and is capped at 100. */
function paginationOf(url: URL): Pagination {
  const perPageRaw = Number(url.searchParams.get('per_page') ?? '30');
  const pageRaw = Number(url.searchParams.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.trunc(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  return { page, perPage };
}

/** Slice one page and build the Link header (absolute, same-origin URLs) for it. */
function pageSlice<T>(items: readonly T[], url: URL, origin: string): { page: T[]; link: string | null } {
  const { page, perPage } = paginationOf(url);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  if (items.length <= perPage && page === 1) return { page: slice, link: null };
  const linkFor = (target: number, rel: string): string => {
    const next = new URL(url.pathname, origin);
    for (const [key, value] of url.searchParams) next.searchParams.set(key, value);
    next.searchParams.set('page', String(target));
    next.searchParams.set('per_page', String(perPage));
    return `<${next.toString()}>; rel="${rel}"`;
  };
  const links: string[] = [];
  if (page < totalPages) {
    links.push(linkFor(page + 1, 'next'));
    links.push(linkFor(totalPages, 'last'));
  }
  if (page > 1) {
    links.push(linkFor(1, 'first'));
    links.push(linkFor(page - 1, 'prev'));
  }
  return { page: slice, link: links.length > 0 ? links.join(', ') : null };
}

function sendList(res: ServerResponse, items: unknown[], url: URL, origin: string): void {
  const { page, link } = pageSlice(items, url, origin);
  sendJson(res, 200, page, link === null ? {} : { link });
}

// ------------------------------------------------------------------------------------------
// REST v3.

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** Resolve a ref name (branch, tag, or sha) to a commit sha in this repository. */
function resolveRefToCommit(repo: RepoRec, ref: string): string | null {
  const branch = branchTip(repo, ref);
  if (branch !== null) return branch;
  const tag = repo.refs.get(`refs/tags/${ref}`);
  if (tag !== undefined) return peelToCommit(tag);
  const direct = repo.refs.get(ref);
  if (direct !== undefined) return peelToCommit(direct);
  if (SHA_RE.test(ref)) {
    const object = getObject(ref);
    if (object !== null && object.type === 'commit') return ref;
    if (object !== null && object.type === 'tag') return peelToCommit(ref);
  }
  return null;
}

function viewerIdentity(): string {
  return `${VIEWER.name} <${VIEWER.email}>`;
}

interface JsonBody {
  ok: boolean;
  value: Record<string, unknown>;
}

/** Parse a JSON request body; `{}` for an empty one, not-ok for malformed JSON. */
function parseJsonBody(raw: Buffer): JsonBody {
  if (raw.length === 0) return { ok: true, value: {} };
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return { ok: true, value: parsed as Record<string, unknown> };
    return { ok: true, value: {} };
  } catch {
    return { ok: false, value: {} };
  }
}

function stringField(body: Record<string, unknown>, key: string): string | null {
  const value = body[key];
  return typeof value === 'string' ? value : null;
}

/** Line-based diff counts for the pull-request files view (LCS over lines; files are small). */
function lineDiffCounts(beforeText: string, afterText: string): { additions: number; deletions: number } {
  const linesOf = (text: string): string[] => {
    if (text === '') return [];
    const lines = text.split('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    return lines;
  };
  const before = linesOf(beforeText);
  const after = linesOf(afterText);
  const rows = before.length;
  const cols = after.length;
  const dp: number[][] = Array.from({ length: rows + 1 }, () => new Array<number>(cols + 1).fill(0));
  for (let i = rows - 1; i >= 0; i -= 1) {
    for (let j = cols - 1; j >= 0; j -= 1) {
      dp[i]![j] = before[i] === after[j] ? (dp[i + 1]![j + 1] as number) + 1 : Math.max(dp[i + 1]![j] as number, dp[i]![j + 1] as number);
    }
  }
  const common = dp[0]![0] as number;
  return { additions: after.length - common, deletions: before.length - common };
}

/** The changed-file list between two trees, GitHub's /pulls/{n}/files shape. */
function changedFiles(fromTree: string, toTree: string): Array<Record<string, unknown>> {
  return diffTrees(fromTree, toTree).map((change) => {
    const beforeText = change.before === null ? '' : (getObject(change.before.sha)?.data.toString('utf8') ?? '');
    const afterText = change.after === null ? '' : (getObject(change.after.sha)?.data.toString('utf8') ?? '');
    const counts = change.before === null || change.after === null
      ? { additions: change.after === null ? 0 : afterText.split('\n').length, deletions: change.before === null ? 0 : beforeText.split('\n').length }
      : lineDiffCounts(beforeText, afterText);
    if (change.after !== null && change.before === null) counts.additions = Math.max(1, afterText === '' ? 0 : afterText.replace(/\n$/, '').split('\n').length);
    return {
      sha: change.after?.sha ?? change.before?.sha ?? ZERO_SHA,
      filename: change.path,
      status: change.before === null ? 'added' : change.after === null ? 'removed' : 'modified',
      additions: counts.additions,
      deletions: counts.deletions,
      changes: counts.additions + counts.deletions,
    };
  });
}

function handleRestRoot(res: ServerResponse): void {
  sendJson(res, 200, {
    current_user_url: '/api/v3/user',
    user_url: '/api/v3/users/{user}',
    repository_url: '/api/v3/repos/{owner}/{repo}',
    rate_limit_url: '/api/v3/rate_limit',
    organization_url: '/api/v3/orgs/{org}',
  });
}

function handleCreateRepo(res: ServerResponse, body: Record<string, unknown>, origin: string): void {
  const name = stringField(body, 'name');
  if (name === null || name === '') {
    sendJson(res, 422, { message: 'Repository creation failed.', errors: [{ resource: 'Repository', code: 'missing_field', field: 'name' }] });
    return;
  }
  if (findRepo(VIEWER.login, name) !== null) {
    sendJson(res, 422, { message: 'Repository creation failed.', errors: [{ resource: 'Repository', code: 'custom', field: 'name', message: 'name already exists on this account' }] });
    return;
  }
  const description = stringField(body, 'description');
  const isPrivate = typeof body.private === 'boolean' ? body.private : false;
  const repo = createRepo(VIEWER, name, description, isPrivate);
  const defaultBranch = stringField(body, 'default_branch');
  if (defaultBranch !== null && defaultBranch !== '') repo.defaultBranch = defaultBranch;
  sendJson(res, 201, repoJson(repo, origin));
}

function handleRepoItem(req: IncomingMessage, res: ServerResponse, url: URL, repo: RepoRec, body: Record<string, unknown>, origin: string): void {
  const method = req.method ?? 'GET';
  if (method === 'GET') {
    sendJson(res, 200, repoJson(repo, origin));
    return;
  }
  if (method === 'PATCH') {
    if (typeof body.description === 'string' || body.description === null) repo.description = body.description as string | null;
    if (typeof body.private === 'boolean') repo.isPrivate = body.private;
    if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
    if (typeof body.name === 'string' && body.name !== '' && body.name !== repo.name) {
      REPOS.delete(repoKey(repo.owner.login, repo.name));
      repo.name = body.name;
      REPOS.set(repoKey(repo.owner.login, repo.name), repo);
    }
    repo.updatedSec = tickSec();
    sendJson(res, 200, repoJson(repo, origin));
    return;
  }
  if (method === 'DELETE') {
    REPOS.delete(repoKey(repo.owner.login, repo.name));
    res.writeHead(204, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  sendError(res, 404, 'Not Found');
}

function handleBranches(res: ServerResponse, url: URL, repo: RepoRec, rest: readonly string[], origin: string): void {
  if (rest.length === 0) {
    const branches: Array<Record<string, unknown>> = [];
    for (const [ref, sha] of repo.refs) {
      if (!ref.startsWith('refs/heads/')) continue;
      branches.push({ name: ref.slice('refs/heads/'.length), commit: { sha, url: `${origin}/api/v3/repos/${repo.owner.login}/${repo.name}/commits/${sha}` }, protected: false });
    }
    branches.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    sendList(res, branches, url, origin);
    return;
  }
  const branch = rest.join('/');
  const tip = branchTip(repo, branch);
  if (tip === null) {
    sendError(res, 404, 'Branch not found');
    return;
  }
  sendJson(res, 200, { name: branch, commit: commitJson(tip), protected: false, _links: {} });
}

function handleCommits(res: ServerResponse, url: URL, repo: RepoRec, rest: readonly string[], origin: string): void {
  if (rest.length > 0) {
    const sha = resolveRefToCommit(repo, rest.join('/')) ?? (SHA_RE.test(rest[0] as string) ? (rest[0] as string) : null);
    const json = sha === null ? null : commitJson(sha);
    if (json === null) {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, json);
    return;
  }
  const refParam = url.searchParams.get('sha');
  const tip = refParam === null ? branchTip(repo, repo.defaultBranch) : resolveRefToCommit(repo, refParam);
  if (tip === null) {
    sendList(res, [], url, origin);
    return;
  }
  const pathFilter = url.searchParams.get('path');
  let commits = walkCommits(tip).map((entry) => entry.sha);
  if (pathFilter !== null) {
    commits = commits.filter((sha) => {
      const tree = commitTreeSha(sha);
      return tree !== null && flattenTree(tree).has(pathFilter);
    });
  }
  const items = commits.map((sha) => commitJson(sha)).filter((json) => json !== null);
  sendList(res, items, url, origin);
}

function contentsFileJson(repo: RepoRec, path: string, entry: FlatEntry, origin: string): Record<string, unknown> {
  const object = getObject(entry.sha);
  const data = object?.data ?? Buffer.alloc(0);
  const slash = path.lastIndexOf('/');
  return {
    type: 'file',
    encoding: 'base64',
    size: data.length,
    name: slash === -1 ? path : path.slice(slash + 1),
    path,
    content: data.toString('base64'),
    sha: entry.sha,
    url: `${origin}/api/v3/repos/${repo.owner.login}/${repo.name}/contents/${path}`,
  };
}

function handleContents(req: IncomingMessage, res: ServerResponse, url: URL, repo: RepoRec, rest: readonly string[], body: Record<string, unknown>, origin: string): void {
  const method = req.method ?? 'GET';
  const path = rest.join('/');
  const refParam = url.searchParams.get('ref') ?? stringField(body, 'branch') ?? undefined;

  if (method === 'GET') {
    const commitSha = refParam === undefined ? branchTip(repo, repo.defaultBranch) : resolveRefToCommit(repo, refParam);
    if (commitSha === null) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const tree = commitTreeSha(commitSha);
    if (tree === null) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const flat = flattenTree(tree);
    if (path === '') {
      sendJson(res, 200, dirListing(repo, tree, '', origin));
      return;
    }
    const entry = flat.get(path);
    if (entry !== undefined) {
      sendJson(res, 200, contentsFileJson(repo, path, entry, origin));
      return;
    }
    const listing = dirListing(repo, tree, path, origin);
    if (listing !== null) {
      sendJson(res, 200, listing);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (method === 'PUT' || method === 'DELETE') {
    if (path === '') {
      sendError(res, 422, 'Invalid request.');
      return;
    }
    const branch = stringField(body, 'branch') ?? repo.defaultBranch;
    const message = stringField(body, 'message');
    if (message === null || message === '') {
      sendJson(res, 422, { message: 'Invalid request. "message" wasn\'t supplied.' });
      return;
    }
    const tip = branchTip(repo, branch);
    if (tip === null && !(repo.refs.size === 0 && branch === repo.defaultBranch)) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const flat = tip === null ? new Map<string, FlatEntry>() : flattenTree(commitTreeSha(tip) ?? EMPTY_TREE_SHA);
    const existing = flat.get(path) ?? null;
    const givenSha = stringField(body, 'sha');
    if (method === 'PUT') {
      if (existing !== null) {
        if (givenSha === null) {
          sendJson(res, 422, { message: 'Invalid request. "sha" wasn\'t supplied.' });
          return;
        }
        if (givenSha !== existing.sha) {
          sendJson(res, 409, { message: `${path} does not match the given sha.` });
          return;
        }
      } else if (givenSha !== null) {
        sendJson(res, 422, { message: 'Invalid request. "sha" must not be supplied when creating a file.' });
        return;
      }
      const contentField = stringField(body, 'content');
      if (contentField === null) {
        sendJson(res, 422, { message: 'Invalid request. "content" wasn\'t supplied.' });
        return;
      }
      const bytes = Buffer.from(contentField.replace(/\s+/g, ''), 'base64');
      const blobSha = storeObject('blob', bytes);
      flat.set(path, { sha: blobSha, mode: existing?.mode ?? '100644' });
      const commitSha = commitTreeChange(repo, branch, tip, flat, message);
      const slash = path.lastIndexOf('/');
      sendJson(res, existing !== null ? 200 : 201, {
        content: {
          name: slash === -1 ? path : path.slice(slash + 1),
          path,
          sha: blobSha,
          size: bytes.length,
          type: 'file',
          encoding: 'base64',
        },
        commit: { sha: commitSha, message },
      });
      return;
    }
    // DELETE
    if (existing === null) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (givenSha === null) {
      sendJson(res, 422, { message: 'Invalid request. "sha" wasn\'t supplied.' });
      return;
    }
    if (givenSha !== existing.sha) {
      sendJson(res, 409, { message: `${path} does not match the given sha.` });
      return;
    }
    flat.delete(path);
    const commitSha = commitTreeChange(repo, branch, tip, flat, message);
    sendJson(res, 200, { content: null, commit: { sha: commitSha, message } });
    return;
  }

  sendError(res, 404, 'Not Found');
}

/** The entries directly inside a directory of a tree, or null when the path is no directory. */
function dirListing(repo: RepoRec, treeSha: string, dirPath: string, origin: string): Array<Record<string, unknown>> | null {
  let current = treeSha;
  if (dirPath !== '') {
    for (const part of dirPath.split('/')) {
      const object = getObject(current);
      if (object === null || object.type !== 'tree') return null;
      const next = parseTree(object.data).find((entry) => entry.name === part && isTreeMode(entry.mode));
      if (next === undefined) return null;
      current = next.sha;
    }
  }
  const object = getObject(current);
  if (object === null || object.type !== 'tree') return null;
  const entries = parseTree(object.data).map((entry) => {
    const entryPath = dirPath === '' ? entry.name : `${dirPath}/${entry.name}`;
    const base: Record<string, unknown> = {
      type: isTreeMode(entry.mode) ? 'dir' : 'file',
      name: entry.name,
      path: entryPath,
      sha: entry.sha,
      url: `${origin}/api/v3/repos/${repo.owner.login}/${repo.name}/contents/${entryPath}`,
    };
    if (!isTreeMode(entry.mode)) base.size = getObject(entry.sha)?.data.length ?? 0;
    return base;
  });
  entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return entries;
}

/** Commit a flattened tree onto a branch (creating the branch's first commit when unborn). */
function commitTreeChange(repo: RepoRec, branch: string, tip: string | null, flat: Map<string, FlatEntry>, message: string): string {
  const tree = treeFromFlat(flat);
  const now = tickSec();
  const commitSha = writeCommit({
    tree,
    parents: tip === null ? [] : [tip],
    author: viewerIdentity(),
    committer: viewerIdentity(),
    epochSec: now,
    message,
  });
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  repo.updatedSec = now;
  return commitSha;
}

function handleGitRefs(req: IncomingMessage, res: ServerResponse, repo: RepoRec, rest: readonly string[], body: Record<string, unknown>): void {
  const method = req.method ?? 'GET';
  if (method === 'POST' && rest.length === 0) {
    const ref = stringField(body, 'ref');
    const sha = stringField(body, 'sha');
    if (ref === null || !ref.startsWith('refs/') || sha === null || !SHA_RE.test(sha) || getObject(sha) === null) {
      sendJson(res, 422, { message: 'Invalid request. A ref and the sha of an existing object are required.' });
      return;
    }
    if (repo.refs.has(ref)) {
      sendJson(res, 422, { message: 'Reference already exists' });
      return;
    }
    repo.refs.set(ref, sha);
    repo.updatedSec = tickSec();
    sendJson(res, 201, { ref, node_id: globalId('Ref', `${repo.id}:${ref}`), object: { type: (getObject(sha) as StoredObject).type, sha } });
    return;
  }
  if (method === 'GET' && rest.length === 0) {
    const all = [...repo.refs.entries()].map(([ref, sha]) => ({ ref, node_id: globalId('Ref', `${repo.id}:${ref}`), object: { type: (getObject(sha) as StoredObject).type, sha } }));
    all.sort((a, b) => a.ref.localeCompare(b.ref));
    sendJson(res, 200, all);
    return;
  }
  const joined = rest.join('/');
  const full = joined.startsWith('refs/') ? joined : `refs/${joined}`;
  const sha = repo.refs.get(full);
  if (method === 'GET') {
    if (sha === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { ref: full, node_id: globalId('Ref', `${repo.id}:${full}`), object: { type: (getObject(sha) as StoredObject).type, sha } });
    return;
  }
  if (method === 'DELETE') {
    if (sha === undefined) {
      sendError(res, 422, 'Reference does not exist');
      return;
    }
    repo.refs.delete(full);
    res.writeHead(204, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  sendError(res, 404, 'Not Found');
}

function handleLabels(req: IncomingMessage, res: ServerResponse, url: URL, repo: RepoRec, rest: readonly string[], body: Record<string, unknown>, origin: string): void {
  const method = req.method ?? 'GET';
  if (rest.length === 0) {
    if (method === 'GET') {
      const labels = [...repo.labels.values()].map(labelJson).sort((a, b) => String(a.name).localeCompare(String(b.name)));
      sendList(res, labels, url, origin);
      return;
    }
    if (method === 'POST') {
      const name = stringField(body, 'name');
      if (name === null || name === '') {
        sendJson(res, 422, { message: 'Invalid request. "name" wasn\'t supplied.' });
        return;
      }
      if (repo.labels.has(name)) {
        sendJson(res, 422, { message: 'Validation Failed: Label already exists' });
        return;
      }
      const label: LabelRec = { name, color: stringField(body, 'color') ?? 'ededed', description: stringField(body, 'description') };
      repo.labels.set(name, label);
      sendJson(res, 201, labelJson(label));
      return;
    }
  }
  const name = rest.join('/');
  const label = repo.labels.get(name);
  if (method === 'GET') {
    if (label === undefined) sendError(res, 404, 'Not Found');
    else sendJson(res, 200, labelJson(label));
    return;
  }
  if (method === 'DELETE') {
    if (label === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    repo.labels.delete(name);
    res.writeHead(204, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  if (method === 'PATCH' && label !== undefined) {
    if (typeof body.color === 'string') label.color = body.color;
    if (typeof body.description === 'string' || body.description === null) label.description = body.description as string | null;
    sendJson(res, 200, labelJson(label));
    return;
  }
  sendError(res, 404, 'Not Found');
}

/** Validate a label name list against the repo's labels; the failing name, or null. */
function unknownLabel(repo: RepoRec, labels: readonly string[]): string | null {
  for (const name of labels) if (!repo.labels.has(name)) return name;
  return null;
}

function labelNamesOf(body: Record<string, unknown>): string[] | null {
  const raw = body.labels;
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) return null;
  const names: string[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string') names.push(entry);
    else if (entry !== null && typeof entry === 'object' && typeof (entry as { name?: unknown }).name === 'string') names.push((entry as { name: string }).name);
    else return null;
  }
  return names;
}

function sortedIssues(repo: RepoRec, url: URL, kind: 'issue' | 'pull'): IssueRec[] {
  const state = url.searchParams.get('state') ?? 'open';
  let list = [...repo.issues.values()].filter((issue) => issue.kind === kind);
  if (state === 'open') list = list.filter((issue) => issue.state === 'open');
  else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
  else if (state !== 'all') list = list.filter((issue) => issue.state === state);
  const labelsParam = url.searchParams.get('labels');
  if (labelsParam !== null && labelsParam !== '') {
    const wanted = labelsParam.split(',').map((name) => name.trim()).filter((name) => name !== '');
    list = list.filter((issue) => wanted.every((name) => issue.labels.includes(name)));
  }
  const sort = url.searchParams.get('sort') ?? 'created';
  const direction = url.searchParams.get('direction') ?? 'desc';
  const keyOf = (issue: IssueRec): number => (sort === 'updated' ? issue.updatedSec * 100000 + issue.seq : issue.seq);
  list.sort((a, b) => (direction === 'asc' ? keyOf(a) - keyOf(b) : keyOf(b) - keyOf(a)));
  return list;
}

function handleIssues(req: IncomingMessage, res: ServerResponse, url: URL, repo: RepoRec, rest: readonly string[], body: Record<string, unknown>, origin: string): void {
  const method = req.method ?? 'GET';
  if (rest.length === 0) {
    if (method === 'GET') {
      sendList(res, sortedIssues(repo, url, 'issue').map((issue) => issueJson(repo, issue)), url, origin);
      return;
    }
    if (method === 'POST') {
      const title = stringField(body, 'title');
      if (title === null || title === '') {
        sendJson(res, 422, { message: 'Invalid request. "title" wasn\'t supplied.' });
        return;
      }
      const labels = labelNamesOf(body);
      if (labels === null) {
        sendJson(res, 422, { message: 'Invalid request. "labels" must be an array of label names.' });
        return;
      }
      const bad = unknownLabel(repo, labels);
      if (bad !== null) {
        sendJson(res, 422, { message: `Validation Failed: label "${bad}" does not exist.` });
        return;
      }
      const issue = createIssueRec(repo, { title, body: stringField(body, 'body') ?? '', labels, kind: 'issue' });
      repo.updatedSec = issue.updatedSec;
      sendJson(res, 201, issueJson(repo, issue));
      return;
    }
  }
  const number = Number(rest[0]);
  const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;
  if (rest.length === 1) {
    if (issue === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'GET') {
      sendJson(res, 200, issue.kind === 'pull' ? pullJson(repo, issue) : issueJson(repo, issue));
      return;
    }
    if (method === 'PATCH') {
      if (typeof body.state === 'string') {
        if (body.state !== 'open' && body.state !== 'closed') {
          sendJson(res, 422, { message: 'Invalid request. "state" must be "open" or "closed".' });
          return;
        }
        issue.state = body.state;
      }
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.labels !== undefined) {
        const labels = labelNamesOf(body);
        if (labels === null || unknownLabel(repo, labels) !== null) {
          sendJson(res, 422, { message: 'Validation Failed: an unknown label was supplied.' });
          return;
        }
        issue.labels = labels;
      }
      issue.updatedSec = tickSec();
      sendJson(res, 200, issue.kind === 'pull' ? pullJson(repo, issue) : issueJson(repo, issue));
      return;
    }
  }
  if (rest.length === 2 && rest[1] === 'comments') {
    if (issue === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'GET') {
      sendList(res, issue.comments.map(commentJson), url, origin);
      return;
    }
    if (method === 'POST') {
      const text = stringField(body, 'body');
      if (text === null) {
        sendJson(res, 422, { message: 'Invalid request. "body" wasn\'t supplied.' });
        return;
      }
      const now = tickSec();
      const comment: CommentRec = { id: nextCommentId, body: text, author: VIEWER, createdSec: now, updatedSec: now };
      nextCommentId += 1;
      issue.comments.push(comment);
      issue.updatedSec = now;
      sendJson(res, 201, commentJson(comment));
      return;
    }
  }
  sendError(res, 404, 'Not Found');
}

function stripRefPrefix(head: string): string {
  const colon = head.indexOf(':');
  return colon === -1 ? head : head.slice(colon + 1);
}

function handlePulls(req: IncomingMessage, res: ServerResponse, url: URL, repo: RepoRec, rest: readonly string[], body: Record<string, unknown>, origin: string): void {
  const method = req.method ?? 'GET';
  if (rest.length === 0) {
    if (method === 'GET') {
      sendList(res, sortedIssues(repo, url, 'pull').map((issue) => pullJson(repo, issue)), url, origin);
      return;
    }
    if (method === 'POST') {
      const title = stringField(body, 'title');
      const headRaw = stringField(body, 'head');
      const baseRaw = stringField(body, 'base');
      if (title === null || headRaw === null || baseRaw === null) {
        sendJson(res, 422, { message: 'Invalid request. "title", "head" and "base" are required.' });
        return;
      }
      const head = stripRefPrefix(headRaw);
      const base = baseRaw;
      if (branchTip(repo, head) === null) {
        sendJson(res, 422, { message: `Head ref "${head}" does not exist.` });
        return;
      }
      if (branchTip(repo, base) === null) {
        sendJson(res, 422, { message: `Base ref "${base}" does not exist.` });
        return;
      }
      if (head === base) {
        sendJson(res, 422, { message: 'Head and base must be different branches.' });
        return;
      }
      const duplicate = [...repo.issues.values()].some(
        (issue) => issue.kind === 'pull' && issue.state === 'open' && issue.pull?.headRef === head && issue.pull?.baseRef === base,
      );
      if (duplicate) {
        sendJson(res, 422, { message: `A pull request already exists for ${head} into ${base}.` });
        return;
      }
      const issue = createIssueRec(repo, {
        title,
        body: stringField(body, 'body') ?? '',
        labels: [],
        kind: 'pull',
        pull: { headRef: head, baseRef: base, merged: false, mergedSec: null, mergeCommitSha: null, mergeMethod: null },
      });
      repo.updatedSec = issue.updatedSec;
      sendJson(res, 201, pullJson(repo, issue));
      return;
    }
  }
  const number = Number(rest[0]);
  const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;
  if (issue === undefined || issue.kind !== 'pull') {
    sendError(res, 404, 'Not Found');
    return;
  }
  if (rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, pullJson(repo, issue));
      return;
    }
    if (method === 'PATCH') {
      if (typeof body.state === 'string' && (body.state === 'open' || body.state === 'closed')) issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      issue.updatedSec = tickSec();
      sendJson(res, 200, pullJson(repo, issue));
      return;
    }
  }
  if (rest.length === 2 && rest[1] === 'files' && method === 'GET') {
    const pull = issue.pull as PullRec;
    const headTip = branchTip(repo, pull.headRef);
    const baseTip = branchTip(repo, pull.baseRef);
    if (headTip === null || baseTip === null) {
      sendList(res, [], url, origin);
      return;
    }
    const base = mergeBaseOf(baseTip, headTip);
    const fromTree = base === null ? EMPTY_TREE_SHA : (commitTreeSha(base) ?? EMPTY_TREE_SHA);
    sendList(res, changedFiles(fromTree, commitTreeSha(headTip) ?? EMPTY_TREE_SHA), url, origin);
    return;
  }
  if (rest.length === 2 && rest[1] === 'merge' && method === 'PUT') {
    const pull = issue.pull as PullRec;
    if (pull.merged) {
      sendJson(res, 405, { message: 'Pull Request is already merged' });
      return;
    }
    if (issue.state !== 'open') {
      sendJson(res, 405, { message: 'Pull Request is not mergeable' });
      return;
    }
    const check = mergeability(repo, issue);
    if (!check.mergeable) {
      sendJson(res, 405, { message: 'Merge conflict: the head branch cannot be merged cleanly.' });
      return;
    }
    const methodName = stringField(body, 'merge_method') ?? 'merge';
    const sha = performMerge(repo, issue, methodName === 'merge' ? 'merge' : 'squash');
    if (sha === null) {
      sendJson(res, 405, { message: 'Merge conflict: the head branch cannot be merged cleanly.' });
      return;
    }
    sendJson(res, 200, { sha, merged: true, message: 'Pull Request successfully merged' });
    return;
  }
  sendError(res, 404, 'Not Found');
}

/** The /api/v3 dispatcher. `segments` are the decoded path parts after /api/v3. */
function handleRest(req: IncomingMessage, res: ServerResponse, url: URL, segments: readonly string[], rawBody: Buffer, origin: string): void {
  const method = req.method ?? 'GET';
  if (segments.length === 0) {
    if (method === 'GET') handleRestRoot(res);
    else sendError(res, 404, 'Not Found');
    return;
  }
  const head = segments[0] as string;
  if (head === 'meta' && segments.length === 1) {
    sendJson(res, 200, { installed_version: '3.0.0-forge', verifiable_password_authentication: false });
    return;
  }
  if (head === 'rate_limit' && segments.length === 1) {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 5000, reset: SCENARIO_EPOCH_SEC + 3600 } }, rate: { limit: 5000, remaining: 5000, reset: SCENARIO_EPOCH_SEC + 3600 } });
    return;
  }
  const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
  const parsed = needsBody ? parseJsonBody(rawBody) : { ok: true, value: {} };
  if (!parsed.ok) {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return;
  }
  const body = parsed.value;
  if (head === 'user' && segments.length === 1) {
    if (method === 'GET') sendJson(res, 200, userJson(VIEWER));
    else sendError(res, 404, 'Not Found');
    return;
  }
  if (head === 'user' && segments.length === 2 && segments[1] === 'repos') {
    if (method === 'GET') {
      const own = [...REPOS.values()].filter((repo) => repo.owner.login === VIEWER.login).map((repo) => repoJson(repo, origin));
      sendList(res, own, url, origin);
      return;
    }
    if (method === 'POST') {
      handleCreateRepo(res, body, origin);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }
  if (head === 'users' && segments.length === 3 && segments[2] === 'repos' && method === 'GET') {
    const login = segments[1] as string;
    const theirs = [...REPOS.values()].filter((repo) => repo.owner.login === login).map((repo) => repoJson(repo, origin));
    sendList(res, theirs, url, origin);
    return;
  }
  if (head === 'repos' && segments.length >= 3) {
    const repo = findRepo(segments[1] as string, segments[2] as string);
    if (repo === null) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const rest = segments.slice(3);
    if (rest.length === 0) {
      handleRepoItem(req, res, url, repo, body, origin);
      return;
    }
    switch (rest[0]) {
      case 'branches':
        handleBranches(res, url, repo, rest.slice(1), origin);
        return;
      case 'commits':
        handleCommits(res, url, repo, rest.slice(1), origin);
        return;
      case 'contents':
        handleContents(req, res, url, repo, rest.slice(1), body, origin);
        return;
      case 'labels':
        handleLabels(req, res, url, repo, rest.slice(1), body, origin);
        return;
      case 'issues':
        handleIssues(req, res, url, repo, rest.slice(1), body, origin);
        return;
      case 'pulls':
        handlePulls(req, res, url, repo, rest.slice(1), body, origin);
        return;
      case 'git':
        if (rest[1] === 'refs') {
          handleGitRefs(req, res, repo, rest.slice(2), body);
          return;
        }
        break;
    }
    sendError(res, 404, 'Not Found');
    return;
  }
  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------------------------------
// Git smart HTTP.

const AGENT_STRING = 'coreclone/1.0';

function sortedRefEntries(repo: RepoRec): Array<[string, string]> {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

/** The v0 ref advertisement lines for a repository (HEAD first, peeled tags included). */
function advertisementLines(repo: RepoRec, capabilities: string): Buffer[] {
  const lines: Buffer[] = [];
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const headSha = repo.refs.get(headRef);
  if (repo.refs.size === 0) {
    lines.push(pktLine(`${ZERO_SHA} capabilities^{}\0${capabilities}`));
    return lines;
  }
  let first = true;
  if (headSha !== undefined) {
    lines.push(pktLine(`${headSha} HEAD\0${capabilities}`));
    first = false;
  }
  for (const [ref, sha] of sortedRefEntries(repo)) {
    if (first) {
      lines.push(pktLine(`${sha} ${ref}\0${capabilities}`));
      first = false;
    } else {
      lines.push(pktLine(`${sha} ${ref}`));
    }
    const object = getObject(sha);
    if (object !== null && object.type === 'tag') {
      const peeled = peelToCommit(sha);
      if (peeled !== null) lines.push(pktLine(`${peeled} ${ref}^{}`));
    }
  }
  if (first) lines.push(pktLine(`${ZERO_SHA} capabilities^{}\0${capabilities}`));
  return lines;
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, url: URL, repo: RepoRec): void {
  const service = url.searchParams.get('service');
  if (service === 'git-upload-pack') {
    const protocol = req.headers['git-protocol'];
    if (typeof protocol === 'string' && protocol.includes('version=2')) {
      const body = Buffer.concat([
        pktLine('version 2\n'),
        pktLine(`agent=${AGENT_STRING}\n`),
        pktLine('ls-refs=unborn\n'),
        pktLine('fetch=shallow filter wait-for-done\n'),
        pktLine('object-format=sha1\n'),
        PKT_FLUSH,
      ]);
      sendRaw(res, 200, body, 'application/x-git-upload-pack-advertisement', { 'cache-control': 'no-cache' });
      return;
    }
    const caps = `multi_ack_detailed side-band-64k thin-pack ofs-delta shallow deepen-since deepen-not symref=HEAD:refs/heads/${repo.defaultBranch} object-format=sha1 agent=${AGENT_STRING}`;
    const body = Buffer.concat([pktLine('# service=git-upload-pack\n'), PKT_FLUSH, ...advertisementLines(repo, caps), PKT_FLUSH]);
    sendRaw(res, 200, body, 'application/x-git-upload-pack-advertisement', { 'cache-control': 'no-cache' });
    return;
  }
  if (service === 'git-receive-pack') {
    const caps = `report-status delete-refs side-band-64k ofs-delta agent=${AGENT_STRING}`;
    const body = Buffer.concat([pktLine('# service=git-receive-pack\n'), PKT_FLUSH, ...advertisementLines(repo, caps), PKT_FLUSH]);
    sendRaw(res, 200, body, 'application/x-git-receive-pack-advertisement', { 'cache-control': 'no-cache' });
    return;
  }
  sendRaw(res, 400, Buffer.from('service not supported\n'), 'text/plain; charset=utf-8');
}

interface LsRefsArgs {
  prefixes: string[];
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
}

function handleLsRefs(res: ServerResponse, repo: RepoRec, args: LsRefsArgs): void {
  const matches = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((prefix) => name.startsWith(prefix));
  const lines: Buffer[] = [];
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const headSha = repo.refs.get(headRef);
  if (matches('HEAD')) {
    if (headSha !== undefined) {
      lines.push(pktLine(`${headSha} HEAD${args.symrefs ? ` symref-target:${headRef}` : ''}`));
    } else if (args.unborn) {
      lines.push(pktLine(`unborn HEAD${args.symrefs ? ` symref-target:${headRef}` : ''}`));
    }
  }
  for (const [ref, sha] of sortedRefEntries(repo)) {
    if (!matches(ref)) continue;
    let line = `${sha} ${ref}`;
    const object = getObject(sha);
    if (args.peel && object !== null && object.type === 'tag') {
      const peeled = peelToCommit(sha);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    lines.push(pktLine(line));
  }
  sendRaw(res, 200, Buffer.concat([...lines, PKT_FLUSH]), 'application/x-git-upload-pack-result');
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  done: boolean;
  deepen: number | null;
  clientShallow: string[];
  sideband: boolean;
  waitForDone: boolean;
}

/**
 * The object set a fetch sends: the wants' closure (bounded by `deepen` when given) minus
 * everything reachable from the haves, plus the shallow bookkeeping lines for the boundary.
 */
function computeFetch(wants: readonly string[], haves: readonly string[], deepen: number | null, clientShallow: readonly string[]): { objects: Set<string>; shallow: string[]; unshallow: string[] } {
  const excluded = new Set<string>();
  const clientShallowSet = new Set(clientShallow);
  const collectClosure = (tips: readonly string[], depthLimit: number | null, sink: Set<string>, boundary: Set<string> | null, stopAt: ReadonlySet<string> | null = null): void => {
    const seenCommits = new Set<string>();
    const queue: Array<{ sha: string; depth: number }> = [];
    const addTree = (treeSha: string): void => {
      if (sink.has(treeSha)) return;
      const object = getObject(treeSha);
      if (object === null || object.type !== 'tree') return;
      sink.add(treeSha);
      for (const entry of parseTree(object.data)) {
        if (isTreeMode(entry.mode)) addTree(entry.sha);
        else sink.add(entry.sha);
      }
    };
    for (const tip of tips) {
      let current: string | null = tip;
      while (current !== null) {
        const object = getObject(current);
        if (object === null) break;
        sink.add(current);
        if (object.type === 'tag') {
          const match = /^object ([0-9a-f]{40})/m.exec(object.data.toString('utf8'));
          current = match === null ? null : (match[1] as string);
          continue;
        }
        if (object.type === 'commit' && !seenCommits.has(current)) queue.push({ sha: current, depth: 0 });
        break;
      }
    }
    while (queue.length > 0) {
      const { sha, depth } = queue.shift() as { sha: string; depth: number };
      if (seenCommits.has(sha)) continue;
      seenCommits.add(sha);
      const object = getObject(sha);
      if (object === null || object.type !== 'commit') continue;
      sink.add(sha);
      const info = parseCommit(object.data);
      if (info.tree !== '') addTree(info.tree);
      if (stopAt !== null && stopAt.has(sha)) continue; // the client's shallow boundary: held, but its parents are not
      const atLimit = depthLimit !== null && depth >= depthLimit - 1;
      if (atLimit) {
        if (boundary !== null && info.parents.length > 0) boundary.add(sha);
        continue;
      }
      for (const parent of info.parents) queue.push({ sha: parent, depth: depth + 1 });
    }
  };
  for (const have of haves) collectClosure([have], null, excluded, null, clientShallowSet);
  const included = new Set<string>();
  const boundary = new Set<string>();
  for (const want of wants) collectClosure([want], deepen, included, boundary);
  const objects = new Set<string>();
  for (const sha of included) if (!excluded.has(sha)) objects.add(sha);
  const shallow: string[] = [];
  for (const sha of boundary) if (!clientShallowSet.has(sha)) shallow.push(sha);
  const unshallow: string[] = [];
  for (const sha of clientShallowSet) {
    if (!included.has(sha)) continue;
    if (deepen === null || !boundary.has(sha)) unshallow.push(sha);
  }
  return { objects, shallow, unshallow };
}

function fetchPackfileSection(objects: Set<string>): Buffer {
  const pack = buildPack(objects);
  return Buffer.concat([pktLine('packfile\n'), ...sidebandPack(pack), PKT_FLUSH]);
}

function handleUploadPackV2(res: ServerResponse, repo: RepoRec, rawBody: Buffer): void {
  const { items } = parsePktLines(rawBody);
  const lines: string[] = [];
  for (const item of items) {
    if (item.kind === 'line') lines.push(item.data.toString('utf8').replace(/\n$/, ''));
    else if (item.kind === 'delim') lines.push('\u0001');
    else if (item.kind === 'flush') lines.push('\u0000');
  }
  const command = lines[0] ?? '';
  if (command === 'command=ls-refs') {
    const args: LsRefsArgs = { prefixes: [], peel: false, symrefs: false, unborn: false };
    for (const line of lines.slice(1)) {
      if (line.startsWith('ref-prefix ')) args.prefixes.push(line.slice('ref-prefix '.length));
      else if (line === 'peel') args.peel = true;
      else if (line === 'symrefs') args.symrefs = true;
      else if (line === 'unborn') args.unborn = true;
    }
    handleLsRefs(res, repo, args);
    return;
  }
  if (command === 'command=fetch') {
    const fetch: FetchRequest = { wants: [], haves: [], done: false, deepen: null, clientShallow: [], sideband: true, waitForDone: false };
    let inArgs = false;
    for (const line of lines.slice(1)) {
      if (line === '\u0001') {
        inArgs = true;
        continue;
      }
      if (line === '\u0000') break;
      if (!inArgs) continue;
      if (line.startsWith('want ')) fetch.wants.push(line.slice(5).trim());
      else if (line.startsWith('have ')) fetch.haves.push(line.slice(5).trim());
      else if (line === 'done') fetch.done = true;
      else if (line.startsWith('deepen ')) fetch.deepen = Number(line.slice(7)) || null;
      else if (line.startsWith('shallow ')) fetch.clientShallow.push(line.slice(8).trim());
      else if (line === 'wait-for-done') fetch.waitForDone = true;
    }
    if (!fetch.done) {
      if (fetch.waitForDone) {
        sendRaw(res, 200, Buffer.alloc(0), 'application/x-git-upload-pack-result');
        return;
      }
      const common = fetch.haves.filter((have) => getObject(have)?.type === 'commit');
      if (common.length === 0) {
        // No common base yet: NAK and let the client offer more haves (or finish with done).
        sendRaw(res, 200, Buffer.concat([pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_FLUSH]), 'application/x-git-upload-pack-result');
        return;
      }
      // A common base exists: 'ready' ends the negotiation, and the packfile section must
      // follow in this same response (that is what git's v2 state machine expects).
      const ready = computeFetch(fetch.wants, fetch.haves, fetch.deepen, fetch.clientShallow);
      const parts: Buffer[] = [pktLine('acknowledgments\n')];
      for (const sha of common) parts.push(pktLine(`ACK ${sha}\n`));
      parts.push(pktLine('ready\n'), PKT_DELIM);
      if (ready.shallow.length > 0 || ready.unshallow.length > 0 || fetch.deepen !== null) {
        parts.push(pktLine('shallow-info\n'));
        for (const sha of ready.shallow) parts.push(pktLine(`shallow ${sha}\n`));
        for (const sha of ready.unshallow) parts.push(pktLine(`unshallow ${sha}\n`));
        parts.push(PKT_DELIM);
      }
      parts.push(fetchPackfileSection(ready.objects));
      sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
      return;
    }
    const { objects, shallow, unshallow } = computeFetch(fetch.wants, fetch.haves, fetch.deepen, fetch.clientShallow);
    const parts: Buffer[] = [];
    if (shallow.length > 0 || unshallow.length > 0 || fetch.deepen !== null) {
      parts.push(pktLine('shallow-info\n'));
      for (const sha of shallow) parts.push(pktLine(`shallow ${sha}\n`));
      for (const sha of unshallow) parts.push(pktLine(`unshallow ${sha}\n`));
      parts.push(PKT_DELIM);
    }
    parts.push(fetchPackfileSection(objects));
    sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
    return;
  }
  sendRaw(res, 400, Buffer.from('unknown command\n'), 'text/plain; charset=utf-8');
}

function handleUploadPackV0(res: ServerResponse, rawBody: Buffer): void {
  const { items, rest } = parsePktLines(rawBody);
  void rest;
  const fetch: FetchRequest = { wants: [], haves: [], done: false, deepen: null, clientShallow: [], sideband: false, waitForDone: false };
  let section = 0;
  for (const item of items) {
    if (item.kind === 'flush') {
      section += 1;
      continue;
    }
    if (item.kind !== 'line') continue;
    const line = item.data.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      if (line.startsWith('want ')) {
        const parts = line.slice(5).split(' ');
        fetch.wants.push(parts[0] as string);
        if (parts.slice(1).join(' ').includes('side-band')) fetch.sideband = true;
      } else if (line.startsWith('shallow ')) fetch.clientShallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) fetch.deepen = Number(line.slice(7)) || null;
    } else {
      if (line.startsWith('have ')) fetch.haves.push(line.slice(5).trim());
      else if (line === 'done') fetch.done = true;
    }
  }
  if (fetch.wants.length === 0 && fetch.haves.length === 0) {
    sendRaw(res, 400, Buffer.from('bad request\n'), 'text/plain; charset=utf-8');
    return;
  }
  const { objects, shallow, unshallow } = computeFetch(fetch.wants, fetch.haves, fetch.deepen, fetch.clientShallow);
  const parts: Buffer[] = [];
  for (const sha of shallow) parts.push(pktLine(`shallow ${sha}\n`));
  for (const sha of unshallow) parts.push(pktLine(`unshallow ${sha}\n`));
  const common = fetch.haves.filter((have) => objects !== null && getObject(have)?.type === 'commit' && isAncestor(have, fetch.wants[0] ?? have));
  if (common.length > 0) parts.push(pktLine(`ACK ${common[common.length - 1]}\n`));
  else parts.push(pktLine('NAK\n'));
  const pack = buildPack(objects);
  if (fetch.sideband) {
    parts.push(...sidebandPack(pack), PKT_FLUSH);
  } else {
    parts.push(pack);
  }
  sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

interface PushCommand {
  oldSha: string;
  newSha: string;
  ref: string;
}

function handleReceivePack(res: ServerResponse, repo: RepoRec, rawBody: Buffer): void {
  const { items, rest } = parsePktLines(rawBody);
  const commands: PushCommand[] = [];
  let capabilities = '';
  let sawFlush = false;
  for (const item of items) {
    if (item.kind === 'flush') {
      sawFlush = true;
      break;
    }
    if (item.kind !== 'line') continue;
    let text = item.data.toString('utf8').replace(/\n$/, '');
    const nul = text.indexOf('\0');
    if (nul !== -1) {
      capabilities = text.slice(nul + 1);
      text = text.slice(0, nul);
    }
    const parts = text.split(' ');
    if (parts.length === 3 && SHA_RE.test(parts[0] as string) && SHA_RE.test(parts[1] as string)) {
      commands.push({ oldSha: parts[0] as string, newSha: parts[1] as string, ref: parts[2] as string });
    }
  }
  if (!sawFlush && commands.length === 0) {
    sendRaw(res, 400, Buffer.from('bad request\n'), 'text/plain; charset=utf-8');
    return;
  }
  const caps = new Set(capabilities.split(' ').filter((cap) => cap !== ''));
  let unpackOk = true;
  let unpackError = '';
  const hasPack = rest.length >= 12 && rest.subarray(0, 4).toString('ascii') === 'PACK';
  if (hasPack) {
    try {
      readPack(rest);
    } catch (error) {
      unpackOk = false;
      unpackError = error instanceof Error ? error.message : String(error);
    }
  }
  interface Verdict {
    command: PushCommand;
    ok: boolean;
    reason: string;
  }
  const verdicts: Verdict[] = commands.map((command) => {
    if (!unpackOk) return { command, ok: false, reason: 'unpacker error' };
    const current = repo.refs.get(command.ref) ?? ZERO_SHA;
    if (command.newSha === ZERO_SHA) {
      if (current === ZERO_SHA) return { command, ok: false, reason: 'reference not found' };
      if (command.ref === `refs/heads/${repo.defaultBranch}`) return { command, ok: false, reason: 'deletion of the current branch prohibited' };
      if (current !== command.oldSha) return { command, ok: false, reason: 'stale info' };
      return { command, ok: true, reason: '' };
    }
    const target = getObject(command.newSha);
    if (target === null) return { command, ok: false, reason: 'new value is not a known object' };
    if (command.oldSha === ZERO_SHA) {
      if (current !== ZERO_SHA) return { command, ok: current === command.newSha, reason: current === command.newSha ? '' : 'already exists' };
    } else {
      if (current !== command.oldSha) return { command, ok: false, reason: 'stale info' };
    }
    if (command.ref.startsWith('refs/heads/')) {
      if (target.type !== 'commit') return { command, ok: false, reason: 'new value is not a commit' };
      if (command.oldSha !== ZERO_SHA && !isAncestor(command.oldSha, command.newSha)) {
        return { command, ok: false, reason: 'non-fast-forward' };
      }
    }
    return { command, ok: true, reason: '' };
  });
  for (const verdict of verdicts) {
    if (!verdict.ok) continue;
    if (verdict.command.newSha === ZERO_SHA) repo.refs.delete(verdict.command.ref);
    else repo.refs.set(verdict.command.ref, verdict.command.newSha);
  }
  if (verdicts.some((verdict) => verdict.ok)) repo.updatedSec = tickSec();
  if (!caps.has('report-status')) {
    sendRaw(res, 200, Buffer.alloc(0), 'application/x-git-receive-pack-result');
    return;
  }
  const reportLines: Buffer[] = [pktLine(unpackOk ? 'unpack ok\n' : `unpack error ${unpackError}\n`)];
  for (const verdict of verdicts) {
    reportLines.push(pktLine(verdict.ok ? `ok ${verdict.command.ref}\n` : `ng ${verdict.command.ref} ${verdict.reason}\n`));
  }
  let body: Buffer;
  if (caps.has('side-band-64k')) {
    // The report is a pkt-line stream of its own (terminated by its own flush) carried
    // inside band 1; the outer flush ends the sideband stream.
    const reportStream = Buffer.concat([...reportLines, PKT_FLUSH]);
    const wrapped: Buffer[] = [];
    for (let offset = 0; offset < reportStream.length; offset += 65515) {
      wrapped.push(sidebandPacket(1, reportStream.subarray(offset, offset + 65515)));
    }
    body = Buffer.concat([...wrapped, PKT_FLUSH]);
  } else {
    body = Buffer.concat([...reportLines, PKT_FLUSH]);
  }
  sendRaw(res, 200, body, 'application/x-git-receive-pack-result');
}

// ------------------------------------------------------------------------------------------
// GraphQL v4: a hand-written lexer, parser and executor covering the documents gh and
// github-mcp-server send. No schema-first machinery: a resolver table per type, opaque
// global ids, cursor connections, and GitHub's error convention (200 + an errors array).

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue } | { __var: string };

interface GqlField {
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  selection: GqlField[] | null;
  fragmentRef: string | null;
  inlineOn: string | null;
}

interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  varDefaults: Record<string, GqlValue>;
  selection: GqlField[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { on: string; selection: GqlField[] }>;
}

function gqlTokenize(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (/\s|,/.test(ch)) {
      i += 1;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:@$=!|&'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        const raw = end === -1 ? source.slice(i + 3) : source.slice(i + 3, end);
        tokens.push(`"${raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`);
        i = end === -1 ? source.length : end + 3;
        continue;
      }
      let j = i + 1;
      let value = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\') {
          const esc = source[j + 1] as string;
          const escapes: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '/': '/', '\\': '\\', '"': '"' };
          if (esc === 'u') {
            value += String.fromCharCode(Number.parseInt(source.slice(j + 2, j + 6), 16));
            j += 6;
          } else {
            value += escapes[esc] ?? esc;
            j += 2;
          }
        } else {
          value += source[j];
          j += 1;
        }
      }
      tokens.push(`"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`);
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9.eE+-]/.test(source[j] as string)) j += 1;
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < source.length && /[_0-9A-Za-z]/.test(source[j] as string)) j += 1;
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    throw new Error(`GraphQL lexer: unexpected character ${JSON.stringify(ch)}`);
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = gqlTokenize(source);
  }

  private peek(): string | null {
    return this.tokens[this.pos] ?? null;
  }

  private next(): string {
    const token = this.tokens[this.pos];
    if (token === undefined) throw new Error('GraphQL parser: unexpected end of document');
    this.pos += 1;
    return token;
  }

  private expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new Error(`GraphQL parser: expected ${token}, got ${got}`);
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { on: string; selection: GqlField[] }>();
    while (this.peek() !== null) {
      const head = this.peek() as string;
      if (head === '{') {
        operations.push({ type: 'query', name: null, varDefaults: {}, selection: this.parseSelectionSet() });
      } else if (head === 'query' || head === 'mutation') {
        this.next();
        let name: string | null = null;
        if (this.peek() !== null && this.peek() !== '(' && this.peek() !== '{') name = this.next();
        const varDefaults: Record<string, GqlValue> = {};
        if (this.peek() === '(') {
          this.next();
          while (this.peek() !== ')') {
            this.expect('$');
            const varName = this.next();
            this.expect(':');
            this.parseTypeRef();
            if (this.peek() === '=') {
              this.next();
              varDefaults[varName] = this.parseValue();
            }
            if (this.peek() === '@') this.skipDirective();
          }
          this.expect(')');
        }
        while (this.peek() === '@') this.skipDirective();
        operations.push({ type: head, name, varDefaults, selection: this.parseSelectionSet() });
      } else if (head === 'fragment') {
        this.next();
        const fragName = this.next();
        this.expect('on');
        const on = this.next();
        while (this.peek() === '@') this.skipDirective();
        fragments.set(fragName, { on, selection: this.parseSelectionSet() });
      } else {
        throw new Error(`GraphQL parser: unexpected token ${head}`);
      }
    }
    return { operations, fragments };
  }

  private parseTypeRef(): void {
    if (this.peek() === '[') {
      this.next();
      this.parseTypeRef();
      this.expect(']');
    } else {
      this.next();
    }
    if (this.peek() === '!') this.next();
  }

  private skipDirective(): void {
    this.expect('@');
    this.next();
    if (this.peek() === '(') {
      let depth = 0;
      do {
        const token = this.next();
        if (token === '(') depth += 1;
        else if (token === ')') depth -= 1;
      } while (depth > 0);
    }
  }

  private parseSelectionSet(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === '...') {
        this.next();
        if (this.peek() === 'on') {
          this.next();
          const on = this.next();
          while (this.peek() === '@') this.skipDirective();
          fields.push({ name: '', alias: null, args: {}, selection: this.parseSelectionSet(), fragmentRef: null, inlineOn: on });
        } else {
          const ref = this.next();
          while (this.peek() === '@') this.skipDirective();
          fields.push({ name: '', alias: null, args: {}, selection: null, fragmentRef: ref, inlineOn: null });
        }
        continue;
      }
      let name = this.next();
      let alias: string | null = null;
      if (this.peek() === ':') {
        this.next();
        alias = name;
        name = this.next();
      }
      const args: Record<string, GqlValue> = {};
      if (this.peek() === '(') {
        this.next();
        while (this.peek() !== ')') {
          const argName = this.next();
          this.expect(':');
          args[argName] = this.parseValue();
        }
        this.expect(')');
      }
      while (this.peek() === '@') this.skipDirective();
      const selection = this.peek() === '{' ? this.parseSelectionSet() : null;
      fields.push({ name, alias, args, selection, fragmentRef: null, inlineOn: null });
    }
    this.expect('}');
    return fields;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { __var: this.next() };
    if (token === '[') {
      const list: GqlValue[] = [];
      while (this.peek() !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (token === '{') {
      const object: Record<string, GqlValue> = {};
      while (this.peek() !== '}') {
        const key = this.next();
        this.expect(':');
        object[key] = this.parseValue();
      }
      this.expect('}');
      return object;
    }
    if (token.startsWith('"')) return JSON.parse(token) as string;
    if (token === 'true') return true;
    if (token === 'false') return false;
    if (token === 'null') return null;
    if (/^-?\d+$/.test(token)) return Number.parseInt(token, 10);
    if (/^-?\d*\.\d/.test(token)) return Number.parseFloat(token);
    return token; // an enum literal
  }
}

function parseGraphql(source: string): GqlDocument {
  return new GqlParser(source).parseDocument();
}

// ------------------------------------------------------------------------------------------
// GraphQL execution.

type GqlObj = { __type: string; [key: string]: unknown };
type GqlResolver = (obj: GqlObj, args: Record<string, unknown>, ctx: GqlCtx) => unknown;

interface GqlCtx {
  doc: GqlDocument;
  variables: Record<string, unknown>;
  errors: Array<{ message: string }>;
}

function userWrapper(user: ForgeUser): GqlObj {
  return { __type: 'User', id: globalId('User', String(user.id)), databaseId: user.id, login: user.login, name: user.name, email: user.email };
}

function repoWrapper(repo: RepoRec): GqlObj {
  return { __type: 'Repository', repo };
}

function issueWrapper(repo: RepoRec, issue: IssueRec): GqlObj {
  return { __type: 'Issue', repo, issue };
}

function pullWrapper(repo: RepoRec, issue: IssueRec): GqlObj {
  return { __type: 'PullRequest', repo, issue };
}

function commentWrapper(repo: RepoRec, issue: IssueRec, comment: CommentRec): GqlObj {
  return { __type: 'IssueComment', repo, issue, comment };
}

function findRepoById(id: number): RepoRec | null {
  for (const repo of REPOS.values()) if (repo.id === id) return repo;
  return null;
}

function nodeWrapper(id: string): GqlObj | null {
  const parsed = parseGlobalId(id);
  if (parsed === null) return null;
  if (parsed.type === 'Repository') {
    const repo = findRepoById(Number(parsed.key));
    return repo === null ? null : repoWrapper(repo);
  }
  if (parsed.type === 'User') {
    const user = USERS.find((entry) => entry.id === Number(parsed.key));
    return user === undefined ? null : userWrapper(user);
  }
  if (parsed.type === 'Issue' || parsed.type === 'PullRequest') {
    const [repoId, number] = parsed.key.split(':');
    const repo = findRepoById(Number(repoId));
    if (repo === null) return null;
    const issue = repo.issues.get(Number(number));
    if (issue === undefined) return null;
    return parsed.type === 'Issue' ? issueWrapper(repo, issue) : pullWrapper(repo, issue);
  }
  if (parsed.type === 'IssueComment') {
    const [repoId, commentId] = parsed.key.split(':');
    const repo = findRepoById(Number(repoId));
    if (repo === null) return null;
    for (const issue of repo.issues.values()) {
      const comment = issue.comments.find((entry) => entry.id === Number(commentId));
      if (comment !== undefined) return commentWrapper(repo, issue, comment);
    }
    return null;
  }
  return null;
}

function cursorOf(key: string): string {
  return Buffer.from(`cur:${key}`, 'utf8').toString('base64');
}

interface ConnectionResult<T> {
  slice: T[];
  total: number;
  hasNext: boolean;
  endCursor: string | null;
  startCursor: string | null;
}

/** Cursor pagination over an already-ordered list; cursors carry the item's stable key. */
function paginate<T>(items: readonly T[], args: Record<string, unknown>, keyOf: (item: T) => string): ConnectionResult<T> {
  let start = 0;
  const after = typeof args.after === 'string' ? args.after : null;
  if (after !== null) {
    try {
      const decoded = Buffer.from(after, 'base64').toString('utf8');
      if (decoded.startsWith('cur:')) {
        const key = decoded.slice(4);
        const index = items.findIndex((item) => keyOf(item) === key);
        if (index >= 0) start = index + 1;
      }
    } catch {
      start = 0;
    }
  }
  const first = typeof args.first === 'number' ? Math.max(0, Math.trunc(args.first)) : items.length;
  const slice = items.slice(start, start + first);
  return {
    slice,
    total: items.length,
    hasNext: start + slice.length < items.length,
    endCursor: slice.length > 0 ? cursorOf(keyOf(slice[slice.length - 1] as T)) : null,
    startCursor: slice.length > 0 ? cursorOf(keyOf(slice[0] as T)) : null,
  };
}

function connectionWrapper(type: string, page: ConnectionResult<GqlObj>): GqlObj {
  const edges = page.slice.map((node) => ({ __type: `${type}Edge`, node, cursor: cursorOf(String((node as { __cursorKey?: string }).__cursorKey ?? '')) }));
  return {
    __type: type,
    nodes: page.slice,
    edges,
    pageInfo: { __type: 'PageInfo', hasNextPage: page.hasNext, hasPreviousPage: false, startCursor: page.startCursor, endCursor: page.endCursor },
    totalCount: page.total,
  };
}

function orderedIssues(repo: RepoRec, kind: 'issue' | 'pull', args: Record<string, unknown>): IssueRec[] {
  let list = [...repo.issues.values()].filter((issue) => issue.kind === kind);
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  if (states !== null && states.length > 0) {
    list = list.filter((issue) => {
      if (issue.kind === 'pull' && (issue.pull as PullRec).merged) return states.includes('MERGED') || states.includes('CLOSED');
      return states.includes(issue.state.toUpperCase());
    });
  }
  const orderBy = (args.orderBy ?? null) as { field?: string; direction?: string } | null;
  const direction = orderBy?.direction === 'DESC' ? -1 : 1;
  list.sort((a, b) => (a.seq - b.seq) * direction);
  return list;
}

const GQL_TYPE_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', 'search', 'rateLimit'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['id', 'databaseId', 'login', 'name', 'email', 'url'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'isPrivate', 'defaultBranchRef',
    'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'createdAt', 'updatedAt', 'url',
  ],
  Issue: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'closed', 'labels', 'comments', 'repository', 'author', 'createdAt', 'updatedAt', 'url'],
  PullRequest: [
    'id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName',
    'headRefOid', 'baseRefOid', 'files', 'commits', 'repository', 'author', 'createdAt', 'updatedAt', 'url',
  ],
  IssueComment: ['id', 'databaseId', 'body', 'author', 'createdAt', 'updatedAt'],
  Label: ['id', 'name', 'color', 'description'],
  Ref: ['name', 'prefix', 'target'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestEdge: ['node', 'cursor'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileEdge: ['node', 'cursor'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  IssueCommentConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueCommentEdge: ['node', 'cursor'],
};

const GQL_ENUMS: Readonly<Record<string, readonly string[]>> = {
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'PULL_REQUEST', 'DISCUSSION'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  State: ['OPEN', 'CLOSED'],
};

function typeWrapper(name: string): GqlObj | null {
  if (GQL_TYPE_FIELDS[name] !== undefined) {
    return {
      __type: '__Type',
      name,
      kind: 'OBJECT',
      fields: (GQL_TYPE_FIELDS[name] as readonly string[]).map((field) => ({ __type: '__Field', name: field })),
      enumValues: null,
    };
  }
  if (GQL_ENUMS[name] !== undefined) {
    return {
      __type: '__Type',
      name,
      kind: 'ENUM',
      fields: null,
      enumValues: (GQL_ENUMS[name] as readonly string[]).map((value) => ({ __type: '__EnumValue', name: value })),
    };
  }
  if (name === 'Node') return { __type: '__Type', name, kind: 'INTERFACE', fields: [{ __type: '__Field', name: 'id' }], enumValues: null };
  return null;
}

function pullStateOf(issue: IssueRec): string {
  if ((issue.pull as PullRec).merged) return 'MERGED';
  return issue.state.toUpperCase();
}

const GQL_RESOLVERS: Record<string, Record<string, GqlResolver>> = {
  Query: {
    viewer: () => userWrapper(VIEWER),
    repository: (_obj, args) => {
      const repo = findRepo(String(args.owner ?? ''), String(args.name ?? ''));
      return repo === null ? null : repoWrapper(repo);
    },
    node: (_obj, args) => nodeWrapper(String(args.id ?? '')),
    search: () => ({ __type: 'SearchResultItemConnection', nodes: [], edges: [], issueCount: 0, repositoryCount: 0, userCount: 0 }),
    rateLimit: () => ({ __type: 'RateLimit', limit: 5000, cost: 1, remaining: 4999, resetAt: isoOf(SCENARIO_EPOCH_SEC + 3600) }),
    __type: (_obj, args) => typeWrapper(String(args.name ?? '')),
    __schema: () => ({
      __type: '__Schema',
      queryType: { __type: '__Type', name: 'Query', kind: 'OBJECT', fields: [], enumValues: null },
      mutationType: { __type: '__Type', name: 'Mutation', kind: 'OBJECT', fields: [], enumValues: null },
      types: [...Object.keys(GQL_TYPE_FIELDS), ...Object.keys(GQL_ENUMS)].map((name) => typeWrapper(name)),
    }),
  },
  Mutation: {
    createIssue: (_obj, args, ctx) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const parsed = parseGlobalId(String(input.repositoryId ?? ''));
      const repo = parsed !== null && parsed.type === 'Repository' ? findRepoById(Number(parsed.key)) : null;
      if (repo === null) throw new Error('Could not resolve the repository.');
      const title = String(input.title ?? '');
      if (title === '') throw new Error('Title is required.');
      const issue = createIssueRec(repo, { title, body: String(input.body ?? ''), labels: [], kind: 'issue' });
      repo.updatedSec = issue.updatedSec;
      return { __type: 'CreateIssuePayload', issue: issueWrapper(repo, issue), clientMutationId: (input.clientMutationId as string | null) ?? null };
    },
    closeIssue: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const node = nodeWrapper(String(input.issueId ?? ''));
      if (node === null || node.__type !== 'Issue') throw new Error('Could not resolve the issue.');
      const issue = node.issue as IssueRec;
      issue.state = 'closed';
      issue.updatedSec = tickSec();
      return { __type: 'CloseIssuePayload', issue: node, clientMutationId: (input.clientMutationId as string | null) ?? null };
    },
    createPullRequest: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const parsed = parseGlobalId(String(input.repositoryId ?? ''));
      const repo = parsed !== null && parsed.type === 'Repository' ? findRepoById(Number(parsed.key)) : null;
      if (repo === null) throw new Error('Could not resolve the repository.');
      const head = stripRefPrefix(String(input.headRefName ?? ''));
      const base = String(input.baseRefName ?? '');
      if (branchTip(repo, head) === null) throw new Error(`Head ref "${head}" does not exist.`);
      if (branchTip(repo, base) === null) throw new Error(`Base ref "${base}" does not exist.`);
      const issue = createIssueRec(repo, {
        title: String(input.title ?? ''),
        body: String(input.body ?? ''),
        labels: [],
        kind: 'pull',
        pull: { headRef: head, baseRef: base, merged: false, mergedSec: null, mergeCommitSha: null, mergeMethod: null },
      });
      repo.updatedSec = issue.updatedSec;
      return { __type: 'CreatePullRequestPayload', pullRequest: pullWrapper(repo, issue), clientMutationId: (input.clientMutationId as string | null) ?? null };
    },
    mergePullRequest: (_obj, args, ctx) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const node = nodeWrapper(String(input.pullRequestId ?? ''));
      if (node === null || node.__type !== 'PullRequest') throw new Error('Could not resolve the pull request.');
      const repo = node.repo as RepoRec;
      const issue = node.issue as IssueRec;
      const pull = issue.pull as PullRec;
      if (!pull.merged) {
        const check = mergeability(repo, issue);
        if (!check.mergeable) {
          ctx.errors.push({ message: 'Merge conflict: the pull request cannot be merged.' });
          return { __type: 'MergePullRequestPayload', pullRequest: node, clientMutationId: null };
        }
        const methodRaw = String(input.mergeMethod ?? 'SQUASH').toLowerCase();
        performMerge(repo, issue, methodRaw === 'merge' ? 'merge' : 'squash');
      }
      return { __type: 'MergePullRequestPayload', pullRequest: node, clientMutationId: (input.clientMutationId as string | null) ?? null };
    },
    addComment: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const node = nodeWrapper(String(input.subjectId ?? ''));
      if (node === null || (node.__type !== 'Issue' && node.__type !== 'PullRequest')) throw new Error('Could not resolve the comment subject.');
      const repo = node.repo as RepoRec;
      const issue = node.issue as IssueRec;
      const now = tickSec();
      const comment: CommentRec = { id: nextCommentId, body: String(input.body ?? ''), author: VIEWER, createdSec: now, updatedSec: now };
      nextCommentId += 1;
      issue.comments.push(comment);
      issue.updatedSec = now;
      const wrapper = commentWrapper(repo, issue, comment);
      return {
        __type: 'AddCommentPayload',
        commentEdge: { __type: 'IssueCommentEdge', node: wrapper, cursor: cursorOf(String(comment.id)) },
        subject: node,
        clientMutationId: (input.clientMutationId as string | null) ?? null,
      };
    },
  },
  Repository: {
    id: (obj) => globalId('Repository', String((obj.repo as RepoRec).id)),
    databaseId: (obj) => (obj.repo as RepoRec).id,
    name: (obj) => (obj.repo as RepoRec).name,
    nameWithOwner: (obj) => `${(obj.repo as RepoRec).owner.login}/${(obj.repo as RepoRec).name}`,
    owner: (obj) => userWrapper((obj.repo as RepoRec).owner),
    description: (obj) => (obj.repo as RepoRec).description,
    isPrivate: (obj) => (obj.repo as RepoRec).isPrivate,
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    defaultBranchRef: (obj) => {
      const repo = obj.repo as RepoRec;
      if (branchTip(repo, repo.defaultBranch) === null) return null;
      return { __type: 'Ref', name: repo.defaultBranch, prefix: 'refs/heads/' };
    },
    issue: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const issue = repo.issues.get(Number(args.number));
      return issue === undefined || issue.kind !== 'issue' ? null : issueWrapper(repo, issue);
    },
    issues: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const list = orderedIssues(repo, 'issue', args).map((issue) => {
        const wrapper = issueWrapper(repo, issue);
        (wrapper as { __cursorKey?: string }).__cursorKey = String(issue.number);
        return wrapper;
      });
      return connectionWrapper('IssueConnection', paginate(list, args, (wrapper) => String(((wrapper.issue as IssueRec).number))));
    },
    pullRequest: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const issue = repo.issues.get(Number(args.number));
      return issue === undefined || issue.kind !== 'pull' ? null : pullWrapper(repo, issue);
    },
    pullRequests: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const list = orderedIssues(repo, 'pull', args).map((issue) => {
        const wrapper = pullWrapper(repo, issue);
        (wrapper as { __cursorKey?: string }).__cursorKey = String(issue.number);
        return wrapper;
      });
      return connectionWrapper('PullRequestConnection', paginate(list, args, (wrapper) => String((wrapper.issue as IssueRec).number)));
    },
    createdAt: (obj) => isoOf((obj.repo as RepoRec).createdSec),
    updatedAt: (obj) => isoOf((obj.repo as RepoRec).updatedSec),
    url: (obj) => `/${(obj.repo as RepoRec).owner.login}/${(obj.repo as RepoRec).name}`,
  },
  Issue: {
    id: (obj) => globalId('Issue', `${(obj.repo as RepoRec).id}:${(obj.issue as IssueRec).number}`),
    databaseId: (obj) => (obj.issue as IssueRec).id,
    number: (obj) => (obj.issue as IssueRec).number,
    title: (obj) => (obj.issue as IssueRec).title,
    body: (obj) => (obj.issue as IssueRec).body,
    state: (obj) => (obj.issue as IssueRec).state.toUpperCase(),
    closed: (obj) => (obj.issue as IssueRec).state === 'closed',
    repository: (obj) => repoWrapper(obj.repo as RepoRec),
    author: (obj) => userWrapper((obj.issue as IssueRec).author),
    labels: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const issue = obj.issue as IssueRec;
      const nodes = issue.labels.map((name) => ({ __type: 'Label', id: globalId('Label', `${repo.id}:${name}`), name, color: repo.labels.get(name)?.color ?? 'ededed', description: repo.labels.get(name)?.description ?? null }));
      return { __type: 'LabelConnection', nodes, edges: nodes.map((node) => ({ __type: 'LabelEdge', node, cursor: cursorOf(node.name as string) })), pageInfo: { __type: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: nodes.length };
    },
    comments: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const issue = obj.issue as IssueRec;
      const nodes = issue.comments.map((comment) => commentWrapper(repo, issue, comment));
      const page = paginate(nodes, args, (wrapper) => String((wrapper.comment as CommentRec).id));
      return connectionWrapper('IssueCommentConnection', page);
    },
    createdAt: (obj) => isoOf((obj.issue as IssueRec).createdSec),
    updatedAt: (obj) => isoOf((obj.issue as IssueRec).updatedSec),
    url: (obj) => `/${(obj.repo as RepoRec).owner.login}/${(obj.repo as RepoRec).name}/issues/${(obj.issue as IssueRec).number}`,
  },
  PullRequest: {
    id: (obj) => globalId('PullRequest', `${(obj.repo as RepoRec).id}:${(obj.issue as IssueRec).number}`),
    databaseId: (obj) => (obj.issue as IssueRec).id,
    number: (obj) => (obj.issue as IssueRec).number,
    title: (obj) => (obj.issue as IssueRec).title,
    body: (obj) => (obj.issue as IssueRec).body,
    state: (obj) => pullStateOf(obj.issue as IssueRec),
    merged: (obj) => ((obj.issue as IssueRec).pull as PullRec).merged,
    mergeable: (obj) => {
      const issue = obj.issue as IssueRec;
      if ((issue.pull as PullRec).merged) return 'UNKNOWN';
      return mergeability(obj.repo as RepoRec, issue).mergeable ? 'MERGEABLE' : 'CONFLICTING';
    },
    headRefName: (obj) => ((obj.issue as IssueRec).pull as PullRec).headRef,
    baseRefName: (obj) => ((obj.issue as IssueRec).pull as PullRec).baseRef,
    headRefOid: (obj) => branchTip(obj.repo as RepoRec, ((obj.issue as IssueRec).pull as PullRec).headRef) ?? ZERO_SHA,
    baseRefOid: (obj) => branchTip(obj.repo as RepoRec, ((obj.issue as IssueRec).pull as PullRec).baseRef) ?? ZERO_SHA,
    repository: (obj) => repoWrapper(obj.repo as RepoRec),
    author: (obj) => userWrapper((obj.issue as IssueRec).author),
    files: (obj, args) => {
      const repo = obj.repo as RepoRec;
      const issue = obj.issue as IssueRec;
      const pull = issue.pull as PullRec;
      const headTip = branchTip(repo, pull.headRef);
      const baseTip = branchTip(repo, pull.baseRef);
      let files: Array<Record<string, unknown>> = [];
      if (headTip !== null && baseTip !== null) {
        const base = mergeBaseOf(baseTip, headTip);
        const fromTree = base === null ? EMPTY_TREE_SHA : (commitTreeSha(base) ?? EMPTY_TREE_SHA);
        files = changedFiles(fromTree, commitTreeSha(headTip) ?? EMPTY_TREE_SHA);
      }
      const nodes = files.map((file) => ({
        __type: 'PullRequestChangedFile',
        path: file.filename as string,
        additions: file.additions as number,
        deletions: file.deletions as number,
        changeType: file.status === 'added' ? 'ADDED' : file.status === 'removed' ? 'DELETED' : 'MODIFIED',
      }));
      const page = paginate(nodes, args, (node) => node.path as string);
      return connectionWrapper('PullRequestChangedFileConnection', page);
    },
    createdAt: (obj) => isoOf((obj.issue as IssueRec).createdSec),
    updatedAt: (obj) => isoOf((obj.issue as IssueRec).updatedSec),
    url: (obj) => `/${(obj.repo as RepoRec).owner.login}/${(obj.repo as RepoRec).name}/pull/${(obj.issue as IssueRec).number}`,
  },
  IssueComment: {
    id: (obj) => globalId('IssueComment', `${(obj.repo as RepoRec).id}:${(obj.comment as CommentRec).id}`),
    databaseId: (obj) => (obj.comment as CommentRec).id,
    body: (obj) => (obj.comment as CommentRec).body,
    author: (obj) => userWrapper((obj.comment as CommentRec).author),
    createdAt: (obj) => isoOf((obj.comment as CommentRec).createdSec),
    updatedAt: (obj) => isoOf((obj.comment as CommentRec).updatedSec),
  },
};

function resolveValue(value: GqlValue, ctx: GqlCtx, defaults: Record<string, GqlValue>): unknown {
  if (value !== null && typeof value === 'object') {
    if ('__var' in value) {
      const name = (value as { __var: string }).__var;
      if (name in ctx.variables) return ctx.variables[name];
      if (name in defaults) return resolveValue(defaults[name] as GqlValue, ctx, defaults);
      return null;
    }
    if (Array.isArray(value)) return value.map((entry) => resolveValue(entry, ctx, defaults));
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) out[key] = resolveValue(entry, ctx, defaults);
    return out;
  }
  return value;
}

/** Expand fragments and merge fields by response key, preserving document order. */
function collectFields(selection: readonly GqlField[], typeName: string, ctx: GqlCtx, out = new Map<string, { field: GqlField; selections: GqlField[] }>()): Map<string, { field: GqlField; selections: GqlField[] }> {
  for (const field of selection) {
    if (field.fragmentRef !== null) {
      const fragment = ctx.doc.fragments.get(field.fragmentRef);
      if (fragment !== undefined && (fragment.on === typeName || fragment.on === 'Node')) collectFields(fragment.selection, typeName, ctx, out);
      continue;
    }
    if (field.inlineOn !== null) {
      if (field.inlineOn === typeName || field.inlineOn === 'Node') collectFields(field.selection ?? [], typeName, ctx, out);
      continue;
    }
    const key = field.alias ?? field.name;
    const existing = out.get(key);
    if (existing !== undefined) {
      if (field.selection !== null) existing.selections.push(...field.selection);
    } else {
      out.set(key, { field, selections: field.selection === null ? [] : [...field.selection] });
    }
  }
  return out;
}

function executeSelection(obj: GqlObj | null, typeName: string, selection: readonly GqlField[], ctx: GqlCtx, defaults: Record<string, GqlValue>): unknown {
  if (obj === null) return null;
  const out: Record<string, unknown> = {};
  const fields = collectFields(selection, typeName, ctx);
  for (const [key, { field, selections }] of fields) {
    out[key] = executeField(obj, typeName, field, selections, ctx, defaults);
  }
  return out;
}

function executeField(obj: GqlObj, typeName: string, field: GqlField, selections: GqlField[], ctx: GqlCtx, defaults: Record<string, GqlValue>): unknown {
  if (field.name === '__typename') return typeName;
  const args: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(field.args)) args[name] = resolveValue(value, ctx, defaults);
  const resolver = GQL_RESOLVERS[typeName]?.[field.name];
  let value: unknown;
  if (resolver !== undefined) {
    try {
      value = resolver(obj, args, ctx);
    } catch (error) {
      ctx.errors.push({ message: error instanceof Error ? error.message : String(error) });
      return null;
    }
  } else if (field.name in obj) {
    value = obj[field.name];
  } else {
    ctx.errors.push({ message: `Field '${field.name}' doesn't exist on type '${typeName}'` });
    return null;
  }
  return completeValue(value, field, selections, ctx, defaults);
}

function completeValue(value: unknown, field: GqlField, selections: GqlField[], ctx: GqlCtx, defaults: Record<string, GqlValue>): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((entry) => completeValue(entry, field, selections, ctx, defaults));
  if (typeof value === 'object') {
    const wrapper = value as GqlObj;
    if (typeof wrapper.__type === 'string') return executeSelection(wrapper, wrapper.__type, selections, ctx, defaults);
    return value;
  }
  return value;
}

interface GqlOutcome {
  status: number;
  body: Record<string, unknown>;
}

function executeGraphqlOperation(operation: GqlOperation, doc: GqlDocument, variables: Record<string, unknown>): Record<string, unknown> {
  const ctx: GqlCtx = { doc, variables, errors: [] };
  const rootType = operation.type === 'mutation' ? 'Mutation' : 'Query';
  const root: GqlObj = { __type: rootType };
  const data = executeSelection(root, rootType, operation.selection, ctx, operation.varDefaults);
  const body: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) body.errors = ctx.errors;
  return body;
}

function handleGraphql(res: ServerResponse, rawBody: Buffer): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return { errors: [{ message: 'Invalid operation.' }] };
    const record = entry as Record<string, unknown>;
    const query = typeof record.query === 'string' ? record.query : '';
    const variables = (record.variables !== null && typeof record.variables === 'object' && !Array.isArray(record.variables) ? record.variables : {}) as Record<string, unknown>;
    const operationName = typeof record.operationName === 'string' ? record.operationName : null;
    let doc: GqlDocument;
    try {
      doc = parseGraphql(query);
    } catch (error) {
      return { errors: [{ message: error instanceof Error ? error.message : String(error) }] };
    }
    const operation = operationName !== null ? doc.operations.find((op) => op.name === operationName) : doc.operations[0];
    if (operation === undefined) return { errors: [{ message: 'Operation not found.' }] };
    return executeGraphqlOperation(operation, doc, variables);
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(parsed));
}

// ------------------------------------------------------------------------------------------
// MCP: streamable HTTP JSON-RPC. Both protocol eras are served — server/discover for the
// 2026-07-28 revision and the initialize handshake for 2025-11-25 and earlier — and the
// tools act on the same store as REST, so an object made here is the same object there.

const MCP_SERVER_INFO = { name: 'coreclone-forge', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'];

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  run: (args: Record<string, unknown>, origin: string) => unknown;
}

function mcpRepo(args: Record<string, unknown>): RepoRec {
  const repo = findRepo(String(args.owner ?? ''), String(args.repo ?? ''));
  if (repo === null) throw new Error(`Repository ${String(args.owner)}/${String(args.repo)} not found`);
  return repo;
}

const MCP_TOOLS: readonly McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
    run: (args, origin) => {
      const name = String(args.name ?? '');
      if (findRepo(VIEWER.login, name) !== null) throw new Error(`Repository ${name} already exists`);
      const repo = createRepo(VIEWER, name, typeof args.description === 'string' ? args.description : null, args.private === true);
      return repoJson(repo, origin);
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
    run: (args, origin) => repoJson(mcpRepo(args), origin),
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
    run: (args) => {
      const repo = mcpRepo(args);
      const issue = createIssueRec(repo, { title: String(args.title ?? ''), body: String(args.body ?? ''), labels: [], kind: 'issue' });
      repo.updatedSec = issue.updatedSec;
      return issueJson(repo, issue);
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
    run: (args) => {
      const repo = mcpRepo(args);
      const state = typeof args.state === 'string' ? args.state : 'open';
      return [...repo.issues.values()]
        .filter((issue) => issue.kind === 'issue' && (state === 'all' || issue.state === state))
        .sort((a, b) => a.seq - b.seq)
        .map((issue) => issueJson(repo, issue));
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
    run: (args) => {
      const repo = mcpRepo(args);
      const head = stripRefPrefix(String(args.head ?? ''));
      const base = String(args.base ?? '');
      if (branchTip(repo, head) === null) throw new Error(`Head ref "${head}" does not exist.`);
      if (branchTip(repo, base) === null) throw new Error(`Base ref "${base}" does not exist.`);
      const issue = createIssueRec(repo, {
        title: String(args.title ?? ''),
        body: String(args.body ?? ''),
        labels: [],
        kind: 'pull',
        pull: { headRef: head, baseRef: base, merged: false, mergedSec: null, mergeCommitSha: null, mergeMethod: null },
      });
      repo.updatedSec = issue.updatedSec;
      return pullJson(repo, issue);
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
    run: (args) => {
      const repo = mcpRepo(args);
      const issue = repo.issues.get(Number(args.pull_number));
      if (issue === undefined || issue.kind !== 'pull') throw new Error(`Pull request ${String(args.pull_number)} not found`);
      const pull = issue.pull as PullRec;
      if (!pull.merged) {
        if (!mergeability(repo, issue).mergeable) throw new Error('Merge conflict: the pull request cannot be merged.');
        if (performMerge(repo, issue, 'squash') === null) throw new Error('Merge conflict: the pull request cannot be merged.');
      }
      return pullJson(repo, issue);
    },
  },
];

const MCP_TOOL_LIST = MCP_TOOLS.map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema }));

interface RpcOutcome {
  status: number;
  payload: Record<string, unknown> | null;
}

function rpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function handleRpcCall(message: Record<string, unknown>, origin: string): RpcOutcome {
  const id = message.id;
  const method = typeof message.method === 'string' ? message.method : '';
  const params = (message.params !== null && typeof message.params === 'object' && !Array.isArray(message.params) ? message.params : {}) as Record<string, unknown>;
  const isNotification = !('id' in message);
  const result = (value: unknown): RpcOutcome => ({ status: 200, payload: isNotification ? null : { jsonrpc: '2.0', id: id ?? null, result: value } });
  const failure = (code: number, text: string): RpcOutcome => ({ status: 200, payload: isNotification ? null : rpcError(id, code, text) });
  switch (method) {
    case 'server/discover':
      return result({
        supportedVersions: MCP_SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
        _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
      });
    case 'initialize': {
      const requested = typeof params.protocolVersion === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(params.protocolVersion) ? params.protocolVersion : '2025-11-25';
      return result({ protocolVersion: requested, capabilities: { tools: {} }, serverInfo: MCP_SERVER_INFO });
    }
    case 'ping':
      return result({});
    case 'tools/list':
      return result({ tools: MCP_TOOL_LIST });
    case 'tools/call': {
      const name = typeof params.name === 'string' ? params.name : '';
      const tool = MCP_TOOLS.find((entry) => entry.name === name);
      if (tool === undefined) return failure(-32602, `Unknown tool: ${name}`);
      const args = (params.arguments !== null && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? params.arguments : {}) as Record<string, unknown>;
      const required = (tool.inputSchema.required as string[] | undefined) ?? [];
      for (const key of required) {
        if (args[key] === undefined || args[key] === null) return failure(-32602, `Missing required argument: ${key}`);
      }
      try {
        const value = tool.run(args, origin);
        const payload: Record<string, unknown> = { content: [{ type: 'text', text: JSON.stringify(value) }], isError: false };
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) payload.structuredContent = value;
        return result(payload);
      } catch (error) {
        return result({ content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }], isError: true });
      }
    }
    default:
      if (method.startsWith('notifications/')) return { status: 200, payload: null };
      return failure(-32601, `Method not found: ${method}`);
  }
}

function handleMcp(res: ServerResponse, rawBody: Buffer, origin: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }
  if (Array.isArray(parsed)) {
    const payloads: unknown[] = [];
    for (const entry of parsed) {
      if (entry !== null && typeof entry === 'object') {
        const outcome = handleRpcCall(entry as Record<string, unknown>, origin);
        if (outcome.payload !== null) payloads.push(outcome.payload);
      }
    }
    sendJson(res, 200, payloads);
    return;
  }
  if (parsed === null || typeof parsed !== 'object') {
    sendJson(res, 400, rpcError(null, -32600, 'Invalid request'));
    return;
  }
  const message = parsed as Record<string, unknown>;
  if (!('id' in message)) {
    handleRpcCall(message, origin);
    res.writeHead(202, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  const outcome = handleRpcCall(message, origin);
  if (outcome.payload === null) {
    res.writeHead(202, { 'x-github-request-id': requestId() });
    res.end();
    return;
  }
  sendJson(res, outcome.status, outcome.payload);
}

// ------------------------------------------------------------------------------------------
// The server assembly: one dispatcher for the four surfaces.

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const origin = `http://${req.headers.host ?? 'localhost'}`;
        const segments = url.pathname.split('/').filter((part) => part !== '').map(decodeSegment);
        const method = req.method ?? 'GET';

        if (method === 'GET' && url.pathname === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
        const rawBody = needsBody ? await readBody(req) : Buffer.alloc(0);
        const viewer = authenticate(req);

        if (segments[0] === 'api' && segments[1] === 'v3') {
          const restSegments = segments.slice(2);
          const isPublicRoot = restSegments.length === 0 || (restSegments.length === 1 && (restSegments[0] === 'meta' || restSegments[0] === 'rate_limit'));
          if (viewer === null && !isPublicRoot) {
            sendJson(res, 401, { message: 'Requires authentication' });
            return;
          }
          handleRest(req, res, url, restSegments, rawBody, origin);
          return;
        }

        if (segments[0] === 'api' && segments[1] === 'graphql' && segments.length === 2) {
          if (method !== 'POST') {
            sendError(res, 404, 'Not Found');
            return;
          }
          if (viewer === null) {
            sendJson(res, 401, { message: 'Requires authentication' });
            return;
          }
          handleGraphql(res, rawBody);
          return;
        }

        if (segments[0] === 'mcp' && segments.length === 1) {
          if (method === 'DELETE') {
            res.writeHead(200, { 'x-github-request-id': requestId() });
            res.end();
            return;
          }
          if (method !== 'POST') {
            sendJson(res, 405, rpcError(null, -32601, 'Method not allowed'));
            return;
          }
          if (viewer === null) {
            sendJson(res, 401, rpcError(null, -32001, 'Unauthorized'));
            return;
          }
          handleMcp(res, rawBody, origin);
          return;
        }

        // Git smart HTTP: /<owner>/<repo>[.git]/info/refs | git-upload-pack | git-receive-pack
        if (segments.length >= 3) {
          const owner = segments[0] as string;
          const repoName = (segments[1] as string).replace(/\.git$/, '');
          const tail = segments.slice(2).join('/');
          if (tail === 'info/refs' || tail === 'git-upload-pack' || tail === 'git-receive-pack') {
            if (viewer === null) {
              sendJson(res, 401, { message: 'Requires authentication' });
              return;
            }
            const repo = findRepo(owner, repoName);
            if (repo === null) {
              sendError(res, 404, 'Not Found');
              return;
            }
            if (tail === 'info/refs' && method === 'GET') {
              handleInfoRefs(req, res, url, repo);
              return;
            }
            if (tail === 'git-upload-pack' && method === 'POST') {
              const protocol = req.headers['git-protocol'];
              if (typeof protocol === 'string' && protocol.includes('version=2')) handleUploadPackV2(res, repo, rawBody);
              else handleUploadPackV0(res, rawBody);
              return;
            }
            if (tail === 'git-receive-pack' && method === 'POST') {
              handleReceivePack(res, repo, rawBody);
              return;
            }
            sendError(res, 404, 'Not Found');
            return;
          }
        }

        sendError(res, 404, 'Not Found');
      } catch (error) {
        if (!res.headersSent) sendJson(res, 500, { message: `Internal error: ${error instanceof Error ? error.message : String(error)}` });
        else res.end();
      }
    })();
  });
}
