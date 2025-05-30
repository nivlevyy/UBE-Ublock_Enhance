import { customMd5HashVector } from "./hashing.js";

const testParts = [
  "www.amazon.com",           // Final Domain
  "GlobalSign nv-sa",         // SSL Issuer
  "Amazon Registrar, Inc."    // Domain Registrar
];

const result = customMd5HashVector(testParts);
console.log(Array.from(result));
