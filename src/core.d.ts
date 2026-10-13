export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface Finding { rule: string; severity: Severity; target: string; location?: string; file?: string; line?: number; message: string; fix?: string; evidence?: string; [k: string]: unknown; }
export interface AllowEntry { rule: string; target?: string; match?: string; reason: string; expires?: string; }
export interface PolicyOptions { allow?: AllowEntry[]; severity?: Record<string, Severity | 'off'>; now?: string | Date; reportUnusedAllow?: boolean; }
export interface TargetResult<S = Record<string, unknown>, D = unknown> { target: string; fatal?: boolean; summary?: S; data?: D; findings: Finding[]; errors: string[]; }
export interface Report<S = Record<string, unknown>, D = unknown> { tool: string; version: string; generatedAt: string; targets: TargetResult<S, D>[]; findings: Finding[]; suppressed: (Finding & { allowedBy: { reason: string; expires?: string } })[]; counts: Record<Severity, number>; errors: { target: string; error: string }[]; [k: string]: unknown; }
export interface RuleInfo { severity: Severity; title: string; group?: string; }
export declare const SEVERITIES: Severity[];
export declare class ConfigError extends Error {}
export declare function exceeds(report: Report, failOn?: Severity | 'none'): boolean;
export declare function exitCode(report: Report, failOn?: Severity | 'none'): 0 | 1 | 2;
export declare function formatText(report: Report, opts?: { color?: boolean; failOn?: Severity | 'none'; fixes?: boolean }): string;
export declare function formatJson(report: Report): string;
export declare function formatSarif(report: Report, tool: { name: string; version: string; rules: Record<string, RuleInfo> }): string;
export declare function formatMarkdown(report: Report, opts?: { failOn?: Severity | 'none'; title?: string; emoji?: string }): string;
