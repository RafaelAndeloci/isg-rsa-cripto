import { modPow } from "./encrypt";

function decryptBlock(ciphertext: bigint, d: bigint, n: bigint): bigint {
  return modPow(ciphertext, d, n);
}

function normalizeCipherText(cipherText: string): string {
  return cipherText
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\s+/g, "")
    .trim();
}

/**
 * Converte um bigint de volta para um array de bytes com comprimento exato (big-endian).
 */
function bigIntToBytes(value: bigint, expectedLength: number): Uint8Array {
  const bytes = new Uint8Array(expectedLength);
  let temp = value;

  for (let i = expectedLength - 1; i >= 0; i--) {
    bytes[i] = Number(temp & 255n);
    temp >>= 8n;
  }

  return bytes;
}

/**
 * Descriptografa um texto que foi criptografado por blocos com encryptText.
 *
 * Espera o formato: "tamanho:valorCriptografado|tamanho:valorCriptografado|..."
 * Cada bloco é descriptografado individualmente e os bytes são remontados
 * para reconstruir o texto original em UTF-8.
 *
 * @param cipherText - Texto criptografado no formato de blocos
 * @param d - Expoente privado
 * @param n - Módulo RSA
 */
export function decryptText(cipherText: string, d: bigint, n: bigint): string {
  const normalizedCipherText = normalizeCipherText(cipherText);

  if (!normalizedCipherText) {
    return "";
  }

  const parts = normalizedCipherText.split("|");
  const resultBytes: number[] = [];

  for (const part of parts) {
    const separatorIndex = part.indexOf(":");

    if (separatorIndex === -1) {
      throw new Error(`Formato de bloco inválido: "${part}". Esperado "tamanho:valor".`);
    }

    const lengthStr = part.slice(0, separatorIndex).trim();
    const encryptedStr = part.slice(separatorIndex + 1).trim();

    if (!lengthStr || !encryptedStr) {
      throw new Error(`Formato de bloco inválido: "${part}". Esperado "tamanho:valor".`);
    }

    if (!/^\d+$/.test(lengthStr) || !/^\d+$/.test(encryptedStr)) {
      throw new Error(`Bloco inválido: "${part}". Use apenas o formato "tamanho:valor" com números inteiros.`);
    }

    const originalLength = Number(lengthStr);
    const encryptedValue = BigInt(encryptedStr);

    const decryptedBlock = decryptBlock(encryptedValue, d, n);
    const blockBytes = bigIntToBytes(decryptedBlock, originalLength);

    resultBytes.push(...blockBytes);
  }

  const decoder = new TextDecoder();
  return decoder.decode(new Uint8Array(resultBytes));
}
