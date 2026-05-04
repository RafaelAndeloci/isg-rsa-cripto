import React, { useState } from "react";
import { Box, Text, render, useApp, useInput } from "ink";

import { decryptText } from "./decrypts";
import { encryptText } from "./encrypt";
import { generateKeys, generateRandomKeys, type PrivateKey, type PublicKey, validateTextModulus } from "./rsa";

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
  fields: FormField[];
  values: Record<string, string>;
  index: number;
};

type ActiveScreen = { type: "menu" } | FormScreen;

const menuOptions: MenuOption[] = [
  { label: "Gerar chaves", action: "generateKeys" },
  { label: "Gerar chaves aleatoriamente", action: "generateRandomKeys" },
  { label: "Informar chaves manualmente", action: "manualKeys" },
  { label: "Criptografar texto", action: "encryptText" },
  { label: "Descriptografar texto", action: "decryptText" },
  { label: "Sair", action: "exit" },
];

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
  fields,
  values,
  index,
  message,
}: {
  title: string;
  fields: FormField[];
  values: Record<string, string>;
  index: number;
  message: string | null;
}): JSX.Element {
  return (
    <Box flexDirection="column">
      <Text color="green">{title}</Text>
      <Text>Digite o valor do campo atual e pressione Enter.</Text>
      <Text>Pressione Escape para cancelar e voltar ao menu.</Text>
      <Text> </Text>
      {fields.map((field, fieldIndex) => {
        const prefix = fieldIndex === index ? ">" : " ";
        const optionalLabel = field.optional ? " (opcional)" : "";

        return (
          <InputLine
            key={field.name}
            label={`${prefix} ${field.label}${optionalLabel}`}
            value={values[field.name] ?? ""}
          />
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

  function openForm(title: string, action: Exclude<MenuAction, "exit">, fields: FormField[]): void {
    setMessage(null);
    setScreen({
      type: "form",
      title,
      action,
      fields,
      values: createInitialValues(fields),
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
        openForm("Gerar chaves", action, [
          { kind: "bigint", name: "p", label: "p" },
          { kind: "bigint", name: "q", label: "q" },
        ]);
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
        openForm("Criptografar texto", action, [{ kind: "text", name: "text", label: "Texto" }]);
        return;
      case "decryptText":
        openForm("Descriptografar texto", action, [{ kind: "text", name: "cipherText", label: "Texto criptografado" }]);
        return;
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
          returnToMenu(`Texto criptografado: ${cipherText}`);
          return;
        }
        case "decryptText": {
          const privateKey = requirePrivateKey(cliState);
          const plainText = decryptText(parsedValues.cipherText as string, privateKey.d, privateKey.n);
          returnToMenu(`Texto descriptografado: ${plainText}`);
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

    if (key.backspace || key.delete) {
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
      updateActiveField(`${currentValue}${input}`);
    }
  });

  if (screen.type === "menu") {
    return <MenuView state={cliState} selectedIndex={selectedIndex} message={message} />;
  }

  return <FormView title={screen.title} fields={screen.fields} values={screen.values} index={screen.index} message={message} />;
}

render(<App />);