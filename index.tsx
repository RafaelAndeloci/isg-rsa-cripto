import { Box, render, Text, useApp, useInput } from "ink";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { parse, resolve } from "node:path";
import React, { useState } from "react";

import { decryptText } from "./decrypts";
import { encryptText } from "./encrypt";
import {
  generateKeys,
  generateRandomKeys,
  validateTextModulus,
  type PrivateKey,
  type PublicKey
} from "./rsa";

type CliState = {
  publicKey: PublicKey | null;
  privateKey: PrivateKey | null;
};

type MenuAction =
  | "generateKeys"
  | "generateRandomKeys"
  | "manualKeys"
  | "encryptText"
  | "decryptText"
  | "decryptFile"
  | "exit";

type MenuOption = {
  label: string;
  action: MenuAction;
};

type BigIntField = {
  kind: "bigint";
  name: string;
  label: string;
  optional?: boolean;
};

type TextField = {
  kind: "text";
  name: string;
  label: string;
  optional?: boolean;
};

type FormField = BigIntField | TextField;

type FormScreen = {
  type: "form";
  title: string;
  action: Exclude<MenuAction, "exit">;
  hints: string[];
  fields: FormField[];
  values: Record<string, string>;
  choices: Record<string, string[]>;
  index: number;
};

type ActiveScreen = { type: "menu" } | FormScreen;

const menuOptions: MenuOption[] = [
  { label: "Gerar chaves", action: "generateKeys" },
  { label: "Gerar chaves aleatoriamente", action: "generateRandomKeys" },
  { label: "Informar chaves manualmente", action: "manualKeys" },
  { label: "Criptografar texto", action: "encryptText" },
  { label: "Descriptografar texto", action: "decryptText" },
  { label: "Descriptografar a partir de arquivo .rsa", action: "decryptFile" },
  { label: "Sair", action: "exit" },
];

const OUTPUT_DIRS = {
  encrypt: resolve(process.cwd(), "outputs", "encrypt"),
  decrypt: resolve(process.cwd(), "outputs", "decrypt"),
} as const;

type ExportTarget = keyof typeof OUTPUT_DIRS;

function stringifyKeyPart(value: bigint | undefined): string {
  return value === undefined ? "nao informada" : value.toString();
}

function createInitialValues(fields: FormField[]): Record<string, string> {
  const values: Record<string, string> = {};

  for (const field of fields) {
    values[field.name] = "";
  }

  return values;
}

function applyChoiceDefaults(values: Record<string, string>, choices: Record<string, string[]>): Record<string, string> {
  const nextValues = { ...values };

  for (const [fieldName, options] of Object.entries(choices)) {
    if (options.length > 0 && !nextValues[fieldName]) {
      nextValues[fieldName] = options[0];
    }
  }

  return nextValues;
}

function parseFieldValue(field: FormField, rawValue: string): string | bigint | null {
  const trimmedValue = rawValue.trim();

  if (!trimmedValue) {
    if (field.optional) {
      return null;
    }

    throw new Error(`O campo \"${field.label}\" e obrigatorio.`);
  }

  if (field.kind === "bigint") {
    try {
      return BigInt(trimmedValue);
    } catch {
      throw new Error(`O campo \"${field.label}\" precisa ser um numero inteiro valido.`);
    }
  }

  return trimmedValue;
}

function parseKeyPairInput(rawValue: string, keyName: "e" | "d"): { first: bigint; n: bigint } {
  const normalizedValue = rawValue.trim();

  if (!normalizedValue) {
    throw new Error("A chave informada esta vazia.");
  }

  const match = normalizedValue.match(/^(?:\(?\s*)?(\d+)\s*[,;:]\s*(\d+)(?:\s*\)?)?$/);

  if (!match) {
    throw new Error(
      `Formato invalido para a chave ${keyName === "e" ? "publica" : "privada"}. Use "${keyName},n" ou "${keyName}:n".`
    );
  }

  return {
    first: BigInt(match[1]),
    n: BigInt(match[2]),
  };
}

function normalizeExportFileName(rawValue: string, target: ExportTarget): string {
  const trimmedValue = rawValue.trim();

  if (!trimmedValue) {
    throw new Error("Informe um nome de arquivo valido para exportacao.");
  }

  const parsedPath = parse(trimmedValue);
  const baseName = parsedPath.name.trim();

  if (!baseName) {
    throw new Error("Informe um nome de arquivo valido para exportacao.");
  }

  const outputDir = OUTPUT_DIRS[target];
  mkdirSync(outputDir, { recursive: true });

  return resolve(outputDir, `${baseName}.rsa`);
}

function exportTextToRsaFile(fileName: string, content: string, target: ExportTarget): string {
  const outputPath = normalizeExportFileName(fileName, target);
  writeFileSync(outputPath, content, { encoding: "utf8" });
  return outputPath;
}

function readCipherTextFromRsaFile(rawFilePath: string): string {
  const trimmedPath = rawFilePath.trim();

  if (!trimmedPath) {
    throw new Error("Informe o caminho do arquivo .rsa para descriptografar.");
  }

  const resolvedPath = resolve(process.cwd(), trimmedPath);
  const content = readFileSync(resolvedPath, { encoding: "utf8" }).trim();

  if (!content) {
    throw new Error(`O arquivo ${resolvedPath} esta vazio.`);
  }

  return content;
}

function listRsaFiles(target: ExportTarget): string[] {
  const outputDir = OUTPUT_DIRS[target];

  if (!existsSync(outputDir)) {
    return [];
  }

  return readdirSync(outputDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".rsa"))
    .map((entry) => resolve(outputDir, entry.name))
    .sort((a, b) => a.localeCompare(b));
}

function requirePublicKey(state: CliState): PublicKey {
  if (!state.publicKey) {
    throw new Error("Nenhuma chave publica disponivel. Gere ou informe uma chave primeiro.");
  }

  return state.publicKey;
}

function requirePrivateKey(state: CliState): PrivateKey {
  if (!state.privateKey) {
    throw new Error("Nenhuma chave privada disponivel. Gere ou informe uma chave primeiro.");
  }

  return state.privateKey;
}

function InputLine({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <Box>
      <Text color="cyan">{label}: </Text>
      <Text>{value || "_"}</Text>
    </Box>
  );
}

function MenuView({
  state,
  selectedIndex,
  message,
}: {
  state: CliState;
  selectedIndex: number;
  message: string | null;
}): JSX.Element {
  return (
    <Box flexDirection="column">
      <Text color="green">RSA CLI com Ink</Text>
      <Text>Use as setas para navegar e Enter para confirmar.</Text>
      <Text>Pressione Ctrl+C para sair.</Text>
      <Text> </Text>
      <Text color="yellow">Chave publica atual</Text>
      <Text>
        e = {stringifyKeyPart(state.publicKey?.e)}, n = {stringifyKeyPart(state.publicKey?.n)}
      </Text>
      <Text color="yellow">Chave privada atual</Text>
      <Text>
        d = {stringifyKeyPart(state.privateKey?.d)}, n = {stringifyKeyPart(state.privateKey?.n)}
      </Text>
      <Text> </Text>
      {menuOptions.map((option, index) => (
        <Text
          key={option.action}
          color={index === selectedIndex ? "black" : undefined}
          backgroundColor={index === selectedIndex ? "cyan" : undefined}
        >
          {index === selectedIndex ? "> " : "  "}
          {option.label}
        </Text>
      ))}
      <Text> </Text>
      <Text color={message?.startsWith("Erro:") ? "red" : "green"}>{message ?? "Selecione uma opcao."}</Text>
    </Box>
  );
}

function FormView({
  title,
  hints,
  fields,
  values,
  choices,
  index,
  message,
}: {
  title: string;
  hints: string[];
  fields: FormField[];
  values: Record<string, string>;
  choices: Record<string, string[]>;
  index: number;
  message: string | null;
}): JSX.Element {
  return (
    <Box flexDirection="column">
      <Text color="green">{title}</Text>
      <Text>Digite o valor do campo atual e pressione Enter.</Text>
      <Text>Pressione Escape para cancelar e voltar ao menu.</Text>
      {hints.map((hint) => (
        <Text key={hint} color="blue">
          {hint}
        </Text>
      ))}
      <Text> </Text>
      {fields.map((field, fieldIndex) => {
        const prefix = fieldIndex === index ? ">" : " ";
        const optionalLabel = field.optional ? " (opcional)" : "";
        const fieldChoices = choices[field.name] ?? [];
        const hasChoices = fieldChoices.length > 0;
        const selectedChoice = values[field.name] ?? "";

        return (
          <Box key={field.name} flexDirection="column">
            <InputLine label={`${prefix} ${field.label}${optionalLabel}`} value={values[field.name] ?? ""} />
            {hasChoices && fieldIndex === index
              ? fieldChoices.map((choice) => (
                  <Text key={choice} color={choice === selectedChoice ? "green" : undefined}>
                    {choice === selectedChoice ? "  > " : "    "}
                    {choice}
                  </Text>
                ))
              : null}
          </Box>
        );
      })}
      <Text> </Text>
      <Text color={message?.startsWith("Erro:") ? "red" : "yellow"}>{message ?? ""}</Text>
    </Box>
  );
}

function App(): JSX.Element {
  const { exit } = useApp();
  const [cliState, setCliState] = useState<CliState>({ publicKey: null, privateKey: null });
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [message, setMessage] = useState<string | null>("Selecione uma opcao.");
  const [screen, setScreen] = useState<ActiveScreen>({ type: "menu" });

  function openForm(
    title: string,
    action: Exclude<MenuAction, "exit">,
    fields: FormField[],
    hints: string[] = [],
    choices: Record<string, string[]> = {}
  ): void {
    setMessage(null);
    const initialValues = applyChoiceDefaults(createInitialValues(fields), choices);

    setScreen({
      type: "form",
      title,
      action,
      hints,
      fields,
      values: initialValues,
      choices,
      index: 0,
    });
  }

  function returnToMenu(nextMessage: string): void {
    setScreen({ type: "menu" });
    setMessage(nextMessage);
  }

  function handleMenuSelect(action: MenuAction): void {
    switch (action) {
      case "generateKeys":
        openForm(
          "Gerar chaves",
          action,
          [
            { kind: "bigint", name: "p", label: "p" },
            { kind: "bigint", name: "q", label: "q" },
          ],
          ["Para suportar texto UTF-8, o modulo n (p * q) deve ser no minimo 256."]
        );
        return;
      case "generateRandomKeys":
        openForm("Gerar chaves aleatoriamente", action, [
          { kind: "bigint", name: "primeBits", label: "Bits por primo (entre 5 e 16)" },
        ]);
        return;
      case "manualKeys":
        openForm("Informar chaves manualmente", action, [
          { kind: "text", name: "publicKeyText", label: "Chave publica completa (e:n)", optional: true },
          { kind: "text", name: "privateKeyText", label: "Chave privada completa (d:n)", optional: true },
          { kind: "bigint", name: "publicE", label: "Novo e da chave publica", optional: true },
          { kind: "bigint", name: "publicN", label: "Novo n da chave publica", optional: true },
          { kind: "bigint", name: "privateD", label: "Novo d da chave privada", optional: true },
          { kind: "bigint", name: "privateN", label: "Novo n da chave privada", optional: true },
        ]);
        return;
      case "encryptText":
        openForm(
          "Criptografar texto",
          action,
          [
            { kind: "text", name: "text", label: "Texto UTF-8" },
            { kind: "text", name: "exportFileName", label: "Arquivo de saida (.rsa)", optional: true },
          ],
          ["A entrada do texto e convertida em bytes UTF-8 antes da criptografia."]
        );
        return;
      case "decryptText":
        openForm(
          "Descriptografar texto",
          action,
          [
            { kind: "text", name: "cipherText", label: "Texto criptografado" },
            { kind: "text", name: "exportFileName", label: "Arquivo de saida (.rsa)", optional: true },
          ]
        );
        return;
      case "decryptFile":
        {
          const rsaFiles = listRsaFiles("encrypt");

          if (rsaFiles.length === 0) {
            returnToMenu(`Erro: Nenhum arquivo .rsa encontrado em ${OUTPUT_DIRS.encrypt}.`);
            return;
          }

        openForm(
          "Descriptografar a partir de arquivo .rsa",
          action,
          [
            { kind: "text", name: "cipherFilePath", label: "Arquivo .rsa (selecione com as setas)" },
            { kind: "text", name: "exportFileName", label: "Arquivo de saida (.rsa)", optional: true },
          ],
          ["Use as setas para escolher o arquivo .rsa de entrada na pasta de encrypt."],
          { cipherFilePath: rsaFiles }
        );
        return;
        }
      case "exit":
        exit();
        return;
    }
  }

  function updateActiveField(nextValue: string): void {
    if (screen.type !== "form") {
      return;
    }

    const activeField = screen.fields[screen.index];

    setScreen({
      ...screen,
      values: {
        ...screen.values,
        [activeField.name]: nextValue,
      },
    });
  }

  function submitForm(formScreen: FormScreen): void {
    try {
      const parsedValues: Record<string, string | bigint | null> = {};

      for (const field of formScreen.fields) {
        parsedValues[field.name] = parseFieldValue(field, formScreen.values[field.name] ?? "");
      }

      switch (formScreen.action) {
        case "generateKeys": {
          const keys = generateKeys(parsedValues.p as bigint, parsedValues.q as bigint);

          setCliState({ publicKey: keys.publicKey, privateKey: keys.privateKey });
          returnToMenu(
            `Chaves geradas. Publica: e=${keys.publicKey.e.toString()}, n=${keys.publicKey.n.toString()}. ` +
              `Privada: d=${keys.privateKey.d.toString()}, n=${keys.privateKey.n.toString()}.`
          );
          return;
        }
        case "generateRandomKeys": {
          const primeBits = Number(parsedValues.primeBits as bigint);
          const keys = generateRandomKeys(primeBits);

          setCliState({ publicKey: keys.publicKey, privateKey: keys.privateKey });
          returnToMenu(
            `Chaves aleatorias geradas. Publica: e=${keys.publicKey.e.toString()}, n=${keys.publicKey.n.toString()}. ` +
              `Privada: d=${keys.privateKey.d.toString()}, n=${keys.privateKey.n.toString()}.`
          );
          return;
        }
        case "manualKeys": {
          const publicKeyText = parsedValues.publicKeyText as string | null;
          const privateKeyText = parsedValues.privateKeyText as string | null;
          const parsedPublicKey = publicKeyText ? parseKeyPairInput(publicKeyText, "e") : null;
          const parsedPrivateKey = privateKeyText ? parseKeyPairInput(privateKeyText, "d") : null;

          const publicE = parsedPublicKey?.first ?? (parsedValues.publicE as bigint | null);
          const publicN = parsedPublicKey?.n ?? (parsedValues.publicN as bigint | null);
          const privateD = parsedPrivateKey?.first ?? (parsedValues.privateD as bigint | null);
          const privateN = parsedPrivateKey?.n ?? (parsedValues.privateN as bigint | null);

          const nextState: CliState = {
            publicKey: cliState.publicKey,
            privateKey: cliState.privateKey,
          };

          if (publicE !== null || publicN !== null) {
            const nextPublicE = publicE ?? cliState.publicKey?.e;
            const nextPublicN = publicN ?? cliState.publicKey?.n;

            if (nextPublicE === undefined || nextPublicN === undefined) {
              throw new Error("Para definir a chave publica pela primeira vez, informe e e n.");
            }

            validateTextModulus(nextPublicN);

            nextState.publicKey = { e: nextPublicE, n: nextPublicN };
          }

          if (privateD !== null || privateN !== null) {
            const nextPrivateD = privateD ?? cliState.privateKey?.d;
            const nextPrivateN = privateN ?? cliState.privateKey?.n;

            if (nextPrivateD === undefined || nextPrivateN === undefined) {
              throw new Error("Para definir a chave privada pela primeira vez, informe d e n.");
            }

            validateTextModulus(nextPrivateN);

            nextState.privateKey = { d: nextPrivateD, n: nextPrivateN };
          }

          if (publicE === null && publicN === null && privateD === null && privateN === null) {
            returnToMenu("Nenhuma chave foi alterada.");
            return;
          }

          setCliState(nextState);
          returnToMenu("Chaves atualizadas com sucesso.");
          return;
        }
        case "encryptText": {
          const publicKey = requirePublicKey(cliState);
          const cipherText = encryptText(parsedValues.text as string, publicKey.e, publicKey.n);
          const exportFileName = parsedValues.exportFileName as string | null;

          if (exportFileName) {
            const outputPath = exportTextToRsaFile(exportFileName, cipherText, "encrypt");
            returnToMenu(`Texto criptografado e salvo em ${outputPath}: ${cipherText}`);
            return;
          }

          returnToMenu(`Texto criptografado: ${cipherText}`);
          return;
        }
        case "decryptText": {
          const privateKey = requirePrivateKey(cliState);
          const plainText = decryptText(parsedValues.cipherText as string, privateKey.d, privateKey.n);
          const exportFileName = parsedValues.exportFileName as string | null;

          if (exportFileName) {
            const outputPath = exportTextToRsaFile(exportFileName, plainText, "decrypt");
            returnToMenu(`Texto descriptografado e salvo em ${outputPath}: ${plainText}`);
            return;
          }

          returnToMenu(`Texto descriptografado: ${plainText}`);
          return;
        }
        case "decryptFile": {
          const privateKey = requirePrivateKey(cliState);
          const cipherText = readCipherTextFromRsaFile(parsedValues.cipherFilePath as string);
          const plainText = decryptText(cipherText, privateKey.d, privateKey.n);
          const exportFileName = parsedValues.exportFileName as string | null;

          if (exportFileName) {
            const outputPath = exportTextToRsaFile(exportFileName, plainText, "decrypt");
            returnToMenu(`Arquivo descriptografado e salvo em ${outputPath}: ${plainText}`);
            return;
          }

          returnToMenu(`Texto descriptografado do arquivo: ${plainText}`);
          return;
        }
      }
    } catch (error) {
      setMessage(`Erro: ${error instanceof Error ? error.message : "Erro inesperado."}`);
    }
  }

  useInput((input, key) => {
    if (screen.type === "menu") {
      if (key.upArrow) {
        setSelectedIndex(selectedIndex === 0 ? menuOptions.length - 1 : selectedIndex - 1);
        return;
      }

      if (key.downArrow) {
        setSelectedIndex(selectedIndex === menuOptions.length - 1 ? 0 : selectedIndex + 1);
        return;
      }

      if (key.return) {
        handleMenuSelect(menuOptions[selectedIndex].action);
      }

      return;
    }

    if (key.escape) {
      returnToMenu("Acao cancelada.");
      return;
    }

    const activeField = screen.fields[screen.index];
    const currentValue = screen.values[activeField.name] ?? "";
    const activeChoices = screen.choices[activeField.name] ?? [];

    if (activeChoices.length > 0 && (key.upArrow || key.downArrow)) {
      const currentChoiceIndex = Math.max(0, activeChoices.indexOf(currentValue));
      const nextChoiceIndex = key.upArrow
        ? currentChoiceIndex === 0
          ? activeChoices.length - 1
          : currentChoiceIndex - 1
        : currentChoiceIndex === activeChoices.length - 1
          ? 0
          : currentChoiceIndex + 1;

      updateActiveField(activeChoices[nextChoiceIndex]);
      return;
    }

    if (key.backspace || key.delete) {
      if (activeChoices.length > 0) {
        return;
      }

      updateActiveField(currentValue.slice(0, -1));
      return;
    }

    if (key.return) {
      if (screen.index === screen.fields.length - 1) {
        submitForm(screen);
        return;
      }

      setScreen({
        ...screen,
        index: screen.index + 1,
      });
      return;
    }

    if (!key.ctrl && !key.meta && input) {
      if (activeChoices.length > 0) {
        return;
      }

      updateActiveField(`${currentValue}${input}`);
    }
  });

  if (screen.type === "menu") {
    return <MenuView state={cliState} selectedIndex={selectedIndex} message={message} />;
  }

  return (
    <FormView
      title={screen.title}
      hints={screen.hints}
      fields={screen.fields}
      values={screen.values}
      choices={screen.choices}
      index={screen.index}
      message={message}
    />
  );
}

render(<App />);