/** Shell-escape a value by wrapping in single quotes and escaping embedded single quotes */
export const shellEsc = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
