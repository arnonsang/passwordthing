/**
 * @module react
 *
 * React hooks for password management and passkey authentication.
 *
 * @example
 * ```ts
 * import { usePassword, usePasskey } from 'passwordthing/react';
 * ```
 */

export type { UsePasswordConfig, BreachStatus, UsePasswordReturn } from './usePassword.js';
export { usePassword } from './usePassword.js';

export type { UsePasskeyReturn } from './usePasskey.js';
export { usePasskey } from './usePasskey.js';
