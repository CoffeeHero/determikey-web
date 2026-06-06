const CHAR_POOLS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  special: "!@#$%^&*",
};

const CATEGORIES = [
  ["lowercase", "Lowercase"],
  ["uppercase", "Uppercase"],
  ["numbers", "Numbers"],
  ["special", "Specials"],
];

export function validateInputString(value, name) {
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code < 0x20 || code > 0x7e) {
      const hex = code.toString(16).toUpperCase().padStart(4, "0");
      throw new Error(`${name} contains invalid character: U+${hex}`);
    }
  }
}

export function validateMetadata(meta) {
  const errors = [];
  for (const [cat, suffix] of CATEGORIES) {
    if (!meta[`allow${suffix}`] && meta[`require${suffix}`]) {
      errors.push(`${cat}: allow is false but require is true`);
    }
  }
  const allFalse = CATEGORIES.every(([, suffix]) => !meta[`allow${suffix}`]);
  if (allFalse) {
    errors.push("All allow flags are false; no characters available");
  }
  const length = meta.length;
  if (!Number.isInteger(length)) errors.push(`length (${length}) must be a positive integer`);
  if (length <= 0) errors.push(`length (${length}) must be > 0`);
  if (length > 88) errors.push(`length (${length}) must be <= 88`);
  const requiredCount = CATEGORIES.filter(([, suffix]) => meta[`require${suffix}`]).length;
  if (length < requiredCount) {
    errors.push(`length (${length}) is less than required categories (${requiredCount})`);
  }
  if (errors.length) {
    throw new Error("Metadata validation failed:\n  " + errors.join("\n  "));
  }
}

export function buildAllowedChars(meta) {
  let allowed = "";
  for (const [cat, suffix] of CATEGORIES) {
    if (meta[`allow${suffix}`]) allowed += CHAR_POOLS[cat];
  }
  return allowed;
}

export function padSalt(saltBytes) {
  if (saltBytes.length >= 8) return saltBytes;
  const out = new Uint8Array(8);
  out.set(saltBytes, 0);
  return out;
}

export function bytesToBase64(bytes) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += chars[b0 >> 2];
    out += chars[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? chars[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < bytes.length ? chars[b2 & 63] : "=";
  }
  return out;
}

export async function runArgon2id(seed, masterKey, argon2id) {
  const enc = new TextEncoder();
  const password = enc.encode(masterKey);
  const salt = padSalt(enc.encode(seed));
  return await argon2id({
    password,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,
    hashLength: 64,
    outputType: "binary",
  });
}

export function formatPassword(rawBytes, meta) {
  const allowed = buildAllowedChars(meta);
  const length = meta.length;
  const b64 = bytesToBase64(rawBytes);
  const candidates = [];
  for (const c of b64) {
    candidates.push(allowed[c.charCodeAt(0) % allowed.length]);
  }
  const result = candidates.slice(0, length);
  let inject = "";
  for (const [cat, suffix] of CATEGORIES) {
    if (meta[`require${suffix}`]) inject += CHAR_POOLS[cat][0];
  }
  for (let i = 0; i < inject.length; i++) result[i] = inject[i];
  return result.join("");
}

export async function generatePassword({ masterKey, seed, metadata, argon2id }) {
  validateInputString(seed, "seed");
  validateInputString(masterKey, "masterKey");
  if (masterKey.length === 0) {
    throw new Error("masterKey must not be empty");
  }
  validateMetadata(metadata);
  const raw = await runArgon2id(seed, masterKey, argon2id);
  return formatPassword(raw, metadata);
}
