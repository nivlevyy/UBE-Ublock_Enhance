import { createHash } from "crypto";

const N_FEATURES = 10;
const MISSING = "nan";

/**
 * ממיר טקסט לווקטור של hash md5 עם סימן לפי ה־LSB
 * @param {string[]} parts [finalDomain, sslIssuer, domainRegistrar]
 * @returns {Float32Array} וקטור בגודל 10 עם ערכים מצטברים
 */
export function customMd5HashVector(parts) {
  const vec = new Float32Array(N_FEATURES);

  for (const raw of parts) {
    const str = raw ?? MISSING;
    const hash = createHash("md5").update(str).digest();

    // קח את 4 הבייטים הראשונים והפוך למספר שלם little-endian
    const intHash =
      hash[0] + (hash[1] << 8) + (hash[2] << 16) + (hash[3] << 24) >>> 0;

    const index = intHash % N_FEATURES;
    const sign = (intHash & 1) === 1 ? -1 : 1;

    vec[index] += sign;
  }

  return vec;
}
