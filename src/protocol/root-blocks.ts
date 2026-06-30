import type { RootBlockData } from '../proto/index_pb.js';

// ── Block decoding ────────────────────────────────────────────────────────────
//
// Raw block layout (from db/storage encoding.go):
//   PreviousHash(8) | StartTime(8) | Content(V) | Length(1-8) | RawType(1) | CurrentHash(8)
//
// RawType values: BlockType8=7(1B len), BlockType16=8(2B), BlockType32=9(4B), BlockType64=10(8B)
//
// Content is an EncodeEntryBasic record:
//   ContentType(1) | ContentLen(1-4) | Sig(64) | SignKeyID(8) | ProcID(8) | Time(8) | Data(V)
//
// ContentType: ContentType8=11(1B), ContentType16=12(2B), ContentType32=13(4B)

const RAW_TYPE_LEN: Record<number, number> = { 7: 1, 8: 2, 9: 4, 10: 8 };
const CONTENT_TYPE_LEN: Record<number, number> = { 11: 1, 12: 2, 13: 4 };
const ENTRY_HEADER = 64 + 8 + 8 + 8; // Sig + SignKeyID + ProcID + Time

// StartTypeObject is always the first 37 bytes of object-1 files.
// FileBlockIndex treats the entire file (StartTypeObject + first data block) as
// a single "block 0", so ReadNextBlock(0) returns all those bytes together.
// Detect the StartTypeObject by its RawType byte at offset 28 (value = 1) and skip it.
const START_TYPE_OBJECT_SIZE = 37;
const START_TYPE_OBJECT_RAWTYPE = 1;

export function decodeRootBlock(block: RootBlockData): string {
  let data = block.Data;
  if (data.length < 28) return '';

  // Strip StartTypeObject prefix if present
  if (data.length > START_TYPE_OBJECT_SIZE && data[START_TYPE_OBJECT_SIZE - 9] === START_TYPE_OBJECT_RAWTYPE) {
    data = data.slice(START_TYPE_OBJECT_SIZE);
  }

  const rawType = data[data.length - 9] ?? 0;
  const lenBytes = RAW_TYPE_LEN[rawType];
  if (!lenBytes) return '';

  // Extract content between the 16-byte prefix and the trailing (lenBytes+1+8) bytes
  const content = data.slice(16, data.length - 1 - lenBytes - 8);
  if (content.length < 2) return '';

  const contentType = content[0] ?? 0;
  const lenBytes2 = CONTENT_TYPE_LEN[contentType];
  if (!lenBytes2) return '';

  const payloadStart = 1 + lenBytes2;
  const dataStart = payloadStart + ENTRY_HEADER;
  if (content.length <= dataStart) return '';

  return new TextDecoder().decode(content.slice(dataStart));
}

// ── Config string types ───────────────────────────────────────────────────────

export interface FieldSpec {
  fieldID: number;
  name: string;
  fieldTypeID: number;
}

export interface ValidationSpec {
  fieldID: number;
  validationName: string;
  params: string[];
}

export interface ObjectDef {
  typeID: number;
  name: string;
  isBasic: boolean;
  fields: FieldSpec[];
  validations: ValidationSpec[];
  servers: ServerDef[];
  updateServers: ServerDef[];
}

export interface ServerDef {
  objectTypeID: number;
  fileIndex: number;
  key: string;
  level: number;
}

export interface LinkFieldSpec extends FieldSpec {}

export interface LinkDef {
  linkTypeID: number;
  linkType: number;
  name: string;
  fromTypes: number[];
  toTypes: number[];
  fields: LinkFieldSpec[];
  servers: LinkServerDef[];
}

export interface LinkServerDef {
  objectTypeID: number;
  linkTypeID: number;
  side: 'from' | 'to';
  fileIndex: number;
  key: string;
  level: number;
}

export interface RoleDef {
  name: string;
  objectTypeID: number;
  objectID: number;
  fieldID: number;
  permType: number;
  members: string[]; // key IDs assigned via permission.link.enable
}

export interface TrustedServer {
  key: string;
  level: number;
}

export interface ComunitiStructure {
  id: string;
  type: 'public' | 'private';
  name: string;
  saltPublic: string;
  saltPrivate: string;
  trustedServers: TrustedServer[];
  objects: ObjectDef[];
  links: LinkDef[];
  roles: RoleDef[];
}

// ── Config string parser ──────────────────────────────────────────────────────

function p(s: string | undefined, base = 10): number {
  return parseInt(s ?? '0', base) || 0;
}

export function parseRootConfig(configString: string): ComunitiStructure {
  const result: ComunitiStructure = {
    id: '', type: 'public', name: '',
    saltPublic: '', saltPrivate: '',
    trustedServers: [], objects: [], links: [], roles: [],
  };

  const objectIndex = new Map<number, ObjectDef>();
  const linkIndex = new Map<number, LinkDef>();
  const roleIndex = new Map<string, RoleDef>();

  for (const rawLine of configString.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    const colonIdx = line.indexOf(': ');
    if (colonIdx === -1) continue;

    const key = line.slice(0, colonIdx).trim();
    const valueStr = line.slice(colonIdx + 2).trim();
    const parts = valueStr.split(' | ').map(s => s.trim());

    switch (key) {
      case 'comuniti.id':          result.id = parts[0] ?? ''; break;
      case 'comuniti.type':        result.type = parts[0] === '0' ? 'public' : 'private'; break;
      case 'comuniti.name.add':    result.name = parts[0] ?? ''; break;
      case 'comuniti.salt.public': result.saltPublic = parts[0] ?? ''; break;
      case 'comuniti.salt.private':result.saltPrivate = parts[0] ?? ''; break;

      case 'comuniti.trust.server':
        result.trustedServers.push({ key: parts[0] ?? '', level: p(parts[1]) });
        break;

      case 'object.enable': {
        const typeID = p(parts[0]);
        const obj: ObjectDef = {
          typeID, name: parts[1] ?? '', isBasic: parts[2] === '1',
          fields: [], validations: [], servers: [], updateServers: [],
        };
        objectIndex.set(typeID, obj);
        result.objects.push(obj);
        break;
      }

      case 'object.field.enable': {
        const obj = objectIndex.get(p(parts[0]));
        if (obj) obj.fields.push({ fieldID: p(parts[1]), name: parts[2] ?? '', fieldTypeID: p(parts[3]) });
        break;
      }

      case 'object.field.validation.enable': {
        const obj = objectIndex.get(p(parts[0]));
        if (obj) obj.validations.push({ fieldID: p(parts[1]), validationName: parts[2] ?? '', params: parts.slice(5) });
        break;
      }

      case 'object.setServer': {
        const obj = objectIndex.get(p(parts[0]));
        if (obj) obj.servers.push({ objectTypeID: p(parts[0]), fileIndex: p(parts[1]), key: parts[2] ?? '', level: p(parts[3]) });
        break;
      }

      case 'object.setUpdateServer': {
        const obj = objectIndex.get(p(parts[0]));
        if (obj) obj.updateServers.push({ objectTypeID: p(parts[0]), fileIndex: p(parts[1]), key: parts[2] ?? '', level: p(parts[3]) });
        break;
      }

      case 'link.enable': {
        const linkTypeID = p(parts[0]);
        const fromTypes = (parts[5] ?? '').split(',').map(s => p(s.trim())).filter(Boolean);
        const toTypes = (parts[6] ?? '').split(',').map(s => p(s.trim())).filter(Boolean);
        const link: LinkDef = {
          linkTypeID, linkType: p(parts[1]), name: parts[2] ?? '',
          fromTypes, toTypes, fields: [], servers: [],
        };
        linkIndex.set(linkTypeID, link);
        result.links.push(link);
        break;
      }

      case 'link.field.enable': {
        const link = linkIndex.get(p(parts[0]));
        if (link) link.fields.push({ fieldID: p(parts[1]), name: parts[2] ?? '', fieldTypeID: p(parts[3]) });
        break;
      }

      case 'link.setServer': {
        const link = linkIndex.get(p(parts[1]));
        if (link) link.servers.push({
          objectTypeID: p(parts[0]), linkTypeID: p(parts[1]),
          side: (parts[2] ?? '') === 'from' ? 'from' : 'to',
          fileIndex: p(parts[3]), key: parts[4] ?? '', level: p(parts[5]),
        });
        break;
      }

      case 'permission.role.enable': {
        const name = parts[0] ?? '';
        if (name && !roleIndex.has(name)) {
          const role: RoleDef = { name, objectTypeID: p(parts[1]), objectID: p(parts[2]), fieldID: p(parts[3]), permType: p(parts[4]), members: [] };
          roleIndex.set(name, role);
          result.roles.push(role);
        }
        break;
      }

      case 'permission.link.enable': {
        // permission.link.enable: <roleName> | <keyID> | ...
        const role = roleIndex.get(parts[0] ?? '');
        if (role && parts[1]) role.members.push(parts[1]);
        break;
      }
    }
  }

  return result;
}
