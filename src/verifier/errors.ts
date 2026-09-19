// SPDX-License-Identifier: GPL-2.0-or-later

export type VerifierErrorKind = 'invalid' | 'unsupported' | 'input';

/** Stable failure categories; messages never turn a partial check into a pass. */
export class VerifierError extends Error {
  readonly code: string;
  readonly kind: VerifierErrorKind;

  constructor(code: string, message: string, kind: VerifierErrorKind = 'invalid') {
    super(message);
    this.name = 'VerifierError';
    this.code = code;
    this.kind = kind;
  }
}
