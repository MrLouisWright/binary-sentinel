import type { Report, PolicyOptions, Severity } from './core.js';
export * from './core.js';
export interface PESection { name: string; virtualAddress: number; virtualSize: number; rawPointer: number; rawSize: number; characteristics: number; read: boolean; write: boolean; execute: boolean; entropy: number; md5: string | null; }
export interface PEImport { dll: string; delayed: boolean; functions: { name?: string; ordinal?: number }[]; }
export interface PEInfo { format: 'pe'; bits: 32 | 64; machine: string; timestamp: number; timestampIso: string | null; subsystem: string; entryPoint: number; entrySection: string | null; imageBase: string; sizeOfImage: number; sizeOfHeaders: number; checksum: number; flags: Record<string, boolean>; directories: Record<string, { va: number; size: number }>; dotnet: boolean; signed: boolean; sections: PESection[]; imports: PEImport[]; importError: string | null; imphash: string | null; exports: { dll: string; count: number; names: string[] } | null; tlsCallbacks: number; rich: { key: string; hash: string; entries: { product: number; build: number; count: number }[] } | null; overlay: { offset: number; size: number; entropy: number; magic: string } | null; anomalies: string[]; }
export interface ELFInfo { format: 'elf'; bits: 32 | 64; endian: 'little' | 'big'; osabi: string; type: string; machine: string; entryPoint: string; entrySection: string | null; entryInLoad: boolean; interpreter: string | null; segments: { type: string; offset: number; vaddr: string; fileSize: number; memSize: number; read: boolean; write: boolean; execute: boolean }[]; sections: { name: string; type: number; offset: number; size: number; addr: string; write: boolean; alloc: boolean; execute: boolean; entropy: number }[]; needed: string[]; soname: string | null; rpath: string | null; runpath: string | null; imports: string[]; exports: string[]; importHash: string | null; stripped: boolean; hardening: { pie: boolean; nx: boolean; execStack: boolean; relro: 'none' | 'partial' | 'full'; bindNow: boolean; canary: boolean; fortify: boolean }; anomalies: string[]; }
export interface Capability { id: string; label: string; attack: string; apis: string[]; }
export interface TriageOptions extends PolicyOptions { profile?: 'triage' | 'hardening'; details?: boolean; }
export declare const VERSION: string;
export declare const RULES: Record<string, { severity: Severity; title: string; group: string }>;
export declare const PROFILES: Record<string, Record<string, Severity>>;
export declare const PACKER_SECTIONS: Record<string, string>;
export declare function entropy(buf: Uint8Array, start?: number, end?: number): number;
export declare function hashes(buf: Uint8Array): { md5: string; sha1: string; sha256: string; sha512: string };
export declare function detectType(buf: Uint8Array): string;
export declare function parsePE(buf: Buffer): PEInfo;
export declare function parseELF(buf: Buffer): ELFInfo;
export declare function parseBinary(buf: Buffer): PEInfo | ELFInfo | null;
export declare function capabilities(importNames: string[]): Capability[];
export declare function peChecksum(buf: Buffer, checksumOffset: number): number;
export declare function analyzeBuffer(buf: Buffer, name: string, opts?: { now?: string | Date }): { info: (PEInfo | ELFInfo | { format: string }) & { hashes?: object; capabilities?: Capability[] }; raw: object[]; summary: Record<string, unknown> };
export declare function triage(inputs: (string | { name: string; buffer: Uint8Array })[], opts?: TriageOptions): Report;
