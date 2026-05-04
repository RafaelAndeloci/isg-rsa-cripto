import { validateTextModulus } from "./rsa";

/**
 * Realiza a exponenciação modular de forma eficiente.
 * Calcula base^exponent mod modulus usando o método das quadrações sucessivas.
 */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;

  let result = 1n;
  let currentBase = ((base % modulus) + modulus) % modulus;
  let currentExponent = exponent;

  while (currentExponent > 0n) {
    if (currentExponent % 2n === 1n) {
      result = (result * currentBase) % modulus;
    }

    currentExponent /= 2n;
    currentBase = (currentBase * currentBase) % modulus;
  }

  return result;
}

function encryptBlock(message: bigint, e: bigint, n: bigint): bigint {
  if (message < 0n || message >= n) {
    throw new Error(`A mensagem numérica deve estar no intervalo 0 <= m < n. Recebido: ${message}, n: ${n}`);
  }

  return modPow(message, e, n);
}

/**
 * Converte um array de bytes em um bigint (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;

  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }

  return result;
}

/**
 * Calcula o tamanho máximo de bloco em bytes que garante que
 * o valor numérico do bloco seja sempre menor que n.
 *
 * Usa (byteLength(n) - 1) para garantir margem de segurança.
 */
function getMaxBlockSize(n: bigint): number {
  let bytes = 0;
  let value = n - 1n;

  while (value > 0n) {
    bytes++;
    value >>= 8n;
  }

  // Subtrai 1 para garantir que o bloco seja sempre menor que n
  return Math.max(1, bytes - 1);
}

/**
 * Criptografa um texto usando RSA por blocos.
 *
 * O texto é convertido para bytes UTF-8, dividido em blocos de tamanho
 * seguro baseado em n, e cada bloco é criptografado individualmente.
 *
 * Formato de saída: "tamanho:valorCriptografado|tamanho:valorCriptografado|..."
 *
 * @param text - Texto original (suporta UTF-8, incluindo acentos)
 * @param e - Expoente público
 * @param n - Módulo RSA
 */
export function encryptText(text: string, e: bigint, n: bigint): string {
  validateTextModulus(n);

  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const blockSize = getMaxBlockSize(n);

  const encryptedBlocks: string[] = [];

  for (let i = 0; i < data.length; i += blockSize) {
    const block = data.slice(i, i + blockSize);
    const blockNumber = bytesToBigInt(block);

    if (blockNumber >= n) {
      throw new Error(
        `Bloco de índice ${i} gerou um valor (${blockNumber}) maior ou igual a n (${n}). Use chaves maiores.`
      );
    }

    const encrypted = encryptBlock(blockNumber, e, n);

    // Serializa o bloco como "tamanhoOriginal:valorCriptografado"
    encryptedBlocks.push(`${block.length}:${encrypted.toString()}`);
  }

  return encryptedBlocks.join("|");
}
