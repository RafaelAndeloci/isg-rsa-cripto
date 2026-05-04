import { encryptNumber, encryptText } from "./encrypt";
import { decryptNumber, decryptText } from "./decrypts";

// ─── Tipos ────────────────────────────────────────────────────────────────────

type PublicKey = {
  e: bigint;
  n: bigint;
};

type PrivateKey = {
  d: bigint;
  n: bigint;
};

type KeyPair = {
  publicKey: PublicKey;
  privateKey: PrivateKey;
};

// ─── Utilitários matemáticos ──────────────────────────────────────────────────

/**
 * Calcula o máximo divisor comum entre a e b (algoritmo de Euclides).
 */
function gcd(a: bigint, b: bigint): bigint {
  let x = a;
  let y = b;

  while (y !== 0n) {
    const temp = y;
    y = x % y;
    x = temp;
  }

  return x;
}

/**
 * Algoritmo de Euclides estendido.
 * Retorna { gcd, x, y } tal que a*x + b*y = gcd.
 */
function extendedGcd(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
  if (b === 0n) {
    return { gcd: a, x: 1n, y: 0n };
  }

  const { gcd, x, y } = extendedGcd(b, a % b);

  return {
    gcd,
    x: y,
    y: x - (a / b) * y,
  };
}

/**
 * Calcula o inverso modular de e em relação a phi (e^-1 mod phi).
 * Lança erro se o inverso não existir (quando gcd(e, phi) != 1).
 */
function modInverse(e: bigint, phi: bigint): bigint {
  const result = extendedGcd(e, phi);

  if (result.gcd !== 1n) {
    throw new Error("O inverso modular não existe (gcd(e, phi) != 1).");
  }

  return ((result.x % phi) + phi) % phi;
}

/**
 * Verifica se um número é primo por divisão por tentativa.
 * Adequado para primos de tamanho acadêmico.
 */
function isPrime(num: bigint): boolean {
  if (num < 2n) return false;
  if (num === 2n) return true;
  if (num % 2n === 0n) return false;

  for (let i = 3n; i * i <= num; i += 2n) {
    if (num % i === 0n) {
      return false;
    }
  }

  return true;
}

/**
 * Escolhe um expoente público e válido para o phi fornecido.
 * Tenta valores comuns primeiro (65537, 257, 17, 5, 3) e depois
 * busca por força bruta se necessário.
 */
function chooseE(phi: bigint): bigint {
  const commonValues = [65537n, 257n, 17n, 5n, 3n];

  for (const candidate of commonValues) {
    if (candidate < phi && gcd(candidate, phi) === 1n) {
      return candidate;
    }
  }

  for (let e = 3n; e < phi; e += 2n) {
    if (gcd(e, phi) === 1n) {
      return e;
    }
  }

  throw new Error("Não foi possível encontrar um valor válido para e.");
}

/**
 * Gera um par de chaves RSA a partir dos primos p e q.
 *
 * @param p - Número primo
 * @param q - Número primo diferente de p
 */
function generateKeys(p: bigint, q: bigint): KeyPair {
  if (!isPrime(p) || !isPrime(q)) {
    throw new Error("p e q precisam ser números primos.");
  }

  if (p === q) {
    throw new Error("p e q não podem ser iguais.");
  }

  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = chooseE(phi);
  const d = modInverse(e, phi);

  return {
    publicKey: { e, n },
    privateKey: { d, n },
  };
}

// ─── Demonstração ─────────────────────────────────────────────────────────────

// Primos maiores para suportar criptografia de texto com caracteres UTF-8
const p = 3557n;
const q = 2579n;

const { publicKey, privateKey } = generateKeys(p, q);

console.log("=== RSA em TypeScript ===");
console.log("p =", p.toString());
console.log("q =", q.toString());
console.log("Chave pública  (e, n):", { e: publicKey.e.toString(), n: publicKey.n.toString() });
console.log("Chave privada  (d, n):", { d: privateKey.d.toString(), n: privateKey.n.toString() });

// --- Exemplo 1: Criptografia/descriptografia numérica ---
console.log("\n=== Exemplo 1: numérico ===");
const numericMessage = 1234n;
const encryptedNumber = encryptNumber(numericMessage, publicKey.e, publicKey.n);
const decryptedNumber = decryptNumber(encryptedNumber, privateKey.d, privateKey.n);

console.log("Original:        ", numericMessage.toString());
console.log("Criptografado:   ", encryptedNumber.toString());
console.log("Descriptografado:", decryptedNumber.toString());
console.log("Correto?         ", decryptedNumber === numericMessage);

// --- Exemplo 2: Criptografia/descriptografia de texto ---
console.log("\n=== Exemplo 2: texto com caracteres UTF-8 ===");
const textMessage = "Olá, mundo RSA! Café com açúcar.";
const encryptedText = encryptText(textMessage, publicKey.e, publicKey.n);
const decryptedText = decryptText(encryptedText, privateKey.d, privateKey.n);

console.log("Original:        ", textMessage);
console.log("Criptografado:   ", encryptedText);
console.log("Descriptografado:", decryptedText);
console.log("Correto?         ", decryptedText === textMessage);

// --- Exemplo 3: Uso com chaves informadas manualmente ---
console.log("\n=== Exemplo 3: chaves informadas manualmente ===");

// As chaves abaixo podem ser substituídas por quaisquer valores válidos (e, d, n)
const manualPublicKey: PublicKey = {
  e: publicKey.e,   // substitua pelo seu valor de e
  n: publicKey.n,   // substitua pelo seu valor de n
};

const manualPrivateKey: PrivateKey = {
  d: privateKey.d,  // substitua pelo seu valor de d
  n: privateKey.n,  // substitua pelo seu valor de n
};

const manualMessage = "Chave informada manualmente!";
const manualEncrypted = encryptText(manualMessage, manualPublicKey.e, manualPublicKey.n);
const manualDecrypted = decryptText(manualEncrypted, manualPrivateKey.d, manualPrivateKey.n);

console.log("Original:        ", manualMessage);
console.log("Criptografado:   ", manualEncrypted);
console.log("Descriptografado:", manualDecrypted);
console.log("Correto?         ", manualDecrypted === manualMessage);
