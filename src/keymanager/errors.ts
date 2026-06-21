export class KeyManagerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyManagerError';
  }
}

// Named subclasses — throw `new XxxError()` at each site so the stack trace
// points to the throw, not to this module-level declaration.
export class KeyNotFoundError extends KeyManagerError {
  constructor() { super('key not found'); this.name = 'KeyNotFoundError'; }
}
export class WrongKeyTypeError extends KeyManagerError {
  constructor() { super('wrong key type'); this.name = 'WrongKeyTypeError'; }
}
export class KeyRevokedError extends KeyManagerError {
  constructor() { super('key is revoked'); this.name = 'KeyRevokedError'; }
}
export class NoL2PasswordError extends KeyManagerError {
  constructor() { super('L2 password required for private key operations'); this.name = 'NoL2PasswordError'; }
}
export class CorruptError extends KeyManagerError {
  constructor() { super('key store is corrupt'); this.name = 'CorruptError'; }
}
export class TamperedError extends KeyManagerError {
  constructor() { super('key store has been tampered with'); this.name = 'TamperedError'; }
}
export class InvalidKeyError extends KeyManagerError {
  constructor() { super('invalid key size or format'); this.name = 'InvalidKeyError'; }
}
export class KeyExistsError extends KeyManagerError {
  constructor() { super('key already exists'); this.name = 'KeyExistsError'; }
}
export class RotationNotSupportedError extends KeyManagerError {
  constructor() { super('key rotation not supported for this key type'); this.name = 'RotationNotSupportedError'; }
}
export class VersionNotFoundError extends KeyManagerError {
  constructor() { super('no field key version found for the given date'); this.name = 'VersionNotFoundError'; }
}
export class AltSaltNotFoundError extends KeyManagerError {
  constructor() { super('alt salt not found'); this.name = 'AltSaltNotFoundError'; }
}
export class LabelAlreadyInUseError extends KeyManagerError {
  constructor() { super('label already assigned to a different key'); this.name = 'LabelAlreadyInUseError'; }
}
export class LabelNotAssignedError extends KeyManagerError {
  constructor() { super('label not assigned to this key'); this.name = 'LabelNotAssignedError'; }
}
export class LabelNotFoundError extends KeyManagerError {
  constructor() { super('label not found'); this.name = 'LabelNotFoundError'; }
}

// Backward-compatible singleton exports — kept so external code can access
// .message without constructing an instance. Internal throw sites use `new
// XxxError()` above for correct stack traces.
export const ErrKeyNotFound = new KeyNotFoundError();
export const ErrWrongKeyType = new WrongKeyTypeError();
export const ErrKeyRevoked = new KeyRevokedError();
export const ErrNoL2Password = new NoL2PasswordError();
export const ErrCorrupt = new CorruptError();
export const ErrTampered = new TamperedError();
export const ErrInvalidKey = new InvalidKeyError();
export const ErrKeyExists = new KeyExistsError();
export const ErrRotationNotSupported = new RotationNotSupportedError();
export const ErrVersionNotFound = new VersionNotFoundError();
export const ErrAltSaltNotFound = new AltSaltNotFoundError();
export const ErrLabelAlreadyInUse = new LabelAlreadyInUseError();
export const ErrLabelNotAssigned = new LabelNotAssignedError();
export const ErrLabelNotFound = new LabelNotFoundError();
