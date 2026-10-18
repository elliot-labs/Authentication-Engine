import type { tags } from 'typia';

/** UUID type representing a string formatted as a UUID. */
export type Uuid = string & tags.Format<'uuid'>;
