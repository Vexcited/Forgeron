import { type ByteStringBuffer } from "./util";

export interface MessageDigest {
  readonly algorithm: "md5" | "sha1" | "sha256" | "sha384" | "sha512" | "sha512/224" | "sha512/256";
  readonly blockLength: number;
  readonly digestLength: number;
  messageLength: number;
  fullMessageLength: number[] | null;
  readonly messageLengthSize: number;
  update(msg: string, encoding?: "raw" | "utf8"): this;
  digest(): ByteStringBuffer;
}
