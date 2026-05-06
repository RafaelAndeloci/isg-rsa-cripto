"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MIN_TEXT_RSA_MODULUS = exports.MIN_BALANCED_PRIME_BITS_FOR_256_BIT_MODULUS = exports.MIN_BALANCED_PRIME_REFERENCE_FOR_256_BIT_MODULUS = exports.TARGET_RSA_MODULUS_BITS = void 0;
exports.validateTextModulus = validateTextModulus;
exports.generateKeys = generateKeys;
exports.generateRandomKeys = generateRandomKeys;
const crypto_1 = require("crypto");
exports.TARGET_RSA_MODULUS_BITS = 256;
exports.MIN_BALANCED_PRIME_REFERENCE_FOR_256_BIT_MODULUS = 1n << 128n;
exports.MIN_BALANCED_PRIME_BITS_FOR_256_BIT_MODULUS = 129;
exports.MIN_TEXT_RSA_MODULUS = 256n;
const MIN_RANDOM_PRIME_BITS = 5;
const MAX_RANDOM_PRIME_BITS = 16;
function gcd(a, b) {
    let x = a;
    let y = b;
    while (y !== 0n) {
        const temp = y;
        y = x % y;
        x = temp;
    }
    return x;
}
function extendedGcd(a, b) {
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
function modInverse(e, phi) {
    const result = extendedGcd(e, phi);
    if (result.gcd !== 1n) {
        throw new Error("O inverso modular nao existe (gcd(e, phi) != 1).");
    }
    return ((result.x % phi) + phi) % phi;
}
function isPrime(num) {
    if (num < 2n)
        return false;
    if (num === 2n)
        return true;
    if (num % 2n === 0n)
        return false;
    for (let i = 3n; i * i <= num; i += 2n) {
        if (num % i === 0n) {
            return false;
        }
    }
    return true;
}
function chooseE(phi) {
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
    throw new Error("Nao foi possivel encontrar um valor valido para e.");
}
function validateTextModulus(n) {
    if (n < exports.MIN_TEXT_RSA_MODULUS) {
        throw new Error(`O modulo n precisa ser no minimo ${exports.MIN_TEXT_RSA_MODULUS.toString()} para suportar texto UTF-8. Escolha chaves maiores.`);
    }
}
function validateRandomPrimeBits(bits) {
    if (!Number.isInteger(bits)) {
        throw new Error("A quantidade de bits precisa ser um numero inteiro.");
    }
    if (bits < MIN_RANDOM_PRIME_BITS || bits > MAX_RANDOM_PRIME_BITS) {
        throw new Error(`A quantidade de bits por primo deve estar entre ${MIN_RANDOM_PRIME_BITS} e ${MAX_RANDOM_PRIME_BITS}.`);
    }
}
function randomBigInt(bits) {
    const byteLength = Math.ceil(bits / 8);
    const random = (0, crypto_1.randomBytes)(byteLength);
    const excessBits = byteLength * 8 - bits;
    if (excessBits > 0) {
        random[0] &= 255 >> excessBits;
    }
    random[0] |= 1 << (7 - excessBits);
    random[random.length - 1] |= 1;
    return BigInt(`0x${random.toString("hex")}`);
}
function generateRandomPrime(bits) {
    validateRandomPrimeBits(bits);
    while (true) {
        const candidate = randomBigInt(bits);
        if (isPrime(candidate)) {
            return candidate;
        }
    }
}
function generateKeys(p, q) {
    if (!isPrime(p) || !isPrime(q)) {
        throw new Error("p e q precisam ser numeros primos.");
    }
    if (p === q) {
        throw new Error("p e q nao podem ser iguais.");
    }
    const n = p * q;
    validateTextModulus(n);
    const phi = (p - 1n) * (q - 1n);
    const e = chooseE(phi);
    const d = modInverse(e, phi);
    return {
        publicKey: { e, n },
        privateKey: { d, n },
    };
}
function generateRandomKeys(primeBits) {
    validateRandomPrimeBits(primeBits);
    while (true) {
        const p = generateRandomPrime(primeBits);
        const q = generateRandomPrime(primeBits);
        if (p === q) {
            continue;
        }
        return generateKeys(p, q);
    }
}
