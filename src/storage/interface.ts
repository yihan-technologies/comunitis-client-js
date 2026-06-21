export interface StorageOptions {
  prefix?: string;
  password?: string;
}

export interface IStorage {
  get<T = unknown>(key: string, options?: StorageOptions): Promise<T | null>;
  set<T = unknown>(key: string, value: T, options?: StorageOptions): Promise<void>;
  delete(key: string, options?: StorageOptions): Promise<void>;
  has(key: string, options?: StorageOptions): Promise<boolean>;
}
