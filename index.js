"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const ink_1 = require("ink");
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
const react_1 = __importStar(require("react"));
const decrypts_1 = require("./decrypts");
const encrypt_1 = require("./encrypt");
const rsa_1 = require("./rsa");
const menuOptions = [
    { label: "Gerar chaves", action: "generateKeys" },
    { label: "Gerar chaves aleatoriamente", action: "generateRandomKeys" },
    { label: "Informar chaves manualmente", action: "manualKeys" },
    { label: "Criptografar texto", action: "encryptText" },
    { label: "Descriptografar texto", action: "decryptText" },
    { label: "Descriptografar a partir de arquivo .rsa", action: "decryptFile" },
    { label: "Sair", action: "exit" },
];
const OUTPUT_DIRS = {
    encrypt: (0, node_path_1.resolve)(process.cwd(), "outputs", "encrypt"),
    decrypt: (0, node_path_1.resolve)(process.cwd(), "outputs", "decrypt"),
};
function stringifyKeyPart(value) {
    return value === undefined ? "nao informada" : value.toString();
}
function createInitialValues(fields) {
    const values = {};
    for (const field of fields) {
        values[field.name] = "";
    }
    return values;
}
function applyChoiceDefaults(values, choices) {
    const nextValues = { ...values };
    for (const [fieldName, options] of Object.entries(choices)) {
        if (options.length > 0 && !nextValues[fieldName]) {
            nextValues[fieldName] = options[0];
        }
    }
    return nextValues;
}
function parseFieldValue(field, rawValue) {
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
        }
        catch {
            throw new Error(`O campo \"${field.label}\" precisa ser um numero inteiro valido.`);
        }
    }
    return trimmedValue;
}
function parseKeyPairInput(rawValue, keyName) {
    const normalizedValue = rawValue.trim();
    if (!normalizedValue) {
        throw new Error("A chave informada esta vazia.");
    }
    const match = normalizedValue.match(/^(?:\(?\s*)?(\d+)\s*[,;:]\s*(\d+)(?:\s*\)?)?$/);
    if (!match) {
        throw new Error(`Formato invalido para a chave ${keyName === "e" ? "publica" : "privada"}. Use "${keyName},n" ou "${keyName}:n".`);
    }
    return {
        first: BigInt(match[1]),
        n: BigInt(match[2]),
    };
}
function normalizeExportFileName(rawValue, target) {
    const trimmedValue = rawValue.trim();
    if (!trimmedValue) {
        throw new Error("Informe um nome de arquivo valido para exportacao.");
    }
    const parsedPath = (0, node_path_1.parse)(trimmedValue);
    const baseName = parsedPath.name.trim();
    if (!baseName) {
        throw new Error("Informe um nome de arquivo valido para exportacao.");
    }
    const outputDir = OUTPUT_DIRS[target];
    (0, node_fs_1.mkdirSync)(outputDir, { recursive: true });
    return (0, node_path_1.resolve)(outputDir, `${baseName}.rsa`);
}
function exportTextToRsaFile(fileName, content, target) {
    const outputPath = normalizeExportFileName(fileName, target);
    (0, node_fs_1.writeFileSync)(outputPath, content, { encoding: "utf8" });
    return outputPath;
}
function readCipherTextFromRsaFile(rawFilePath) {
    const trimmedPath = rawFilePath.trim();
    if (!trimmedPath) {
        throw new Error("Informe o caminho do arquivo .rsa para descriptografar.");
    }
    const resolvedPath = (0, node_path_1.resolve)(process.cwd(), trimmedPath);
    const content = (0, node_fs_1.readFileSync)(resolvedPath, { encoding: "utf8" }).trim();
    if (!content) {
        throw new Error(`O arquivo ${resolvedPath} esta vazio.`);
    }
    return content;
}
function listRsaFiles(target) {
    const outputDir = OUTPUT_DIRS[target];
    if (!(0, node_fs_1.existsSync)(outputDir)) {
        return [];
    }
    return (0, node_fs_1.readdirSync)(outputDir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".rsa"))
        .map((entry) => (0, node_path_1.resolve)(outputDir, entry.name))
        .sort((a, b) => a.localeCompare(b));
}
function requirePublicKey(state) {
    if (!state.publicKey) {
        throw new Error("Nenhuma chave publica disponivel. Gere ou informe uma chave primeiro.");
    }
    return state.publicKey;
}
function requirePrivateKey(state) {
    if (!state.privateKey) {
        throw new Error("Nenhuma chave privada disponivel. Gere ou informe uma chave primeiro.");
    }
    return state.privateKey;
}
function InputLine({ label, value }) {
    return (react_1.default.createElement(ink_1.Box, null,
        react_1.default.createElement(ink_1.Text, { color: "cyan" },
            label,
            ": "),
        react_1.default.createElement(ink_1.Text, null, value || "_")));
}
function MenuView({ state, selectedIndex, message, }) {
    return (react_1.default.createElement(ink_1.Box, { flexDirection: "column" },
        react_1.default.createElement(ink_1.Text, { color: "green" }, "RSA CLI com Ink"),
        react_1.default.createElement(ink_1.Text, null, "Use as setas para navegar e Enter para confirmar."),
        react_1.default.createElement(ink_1.Text, null, "Pressione Ctrl+C para sair."),
        react_1.default.createElement(ink_1.Text, null, " "),
        react_1.default.createElement(ink_1.Text, { color: "yellow" }, "Chave publica atual"),
        react_1.default.createElement(ink_1.Text, null,
            "e = ",
            stringifyKeyPart(state.publicKey?.e),
            ", n = ",
            stringifyKeyPart(state.publicKey?.n)),
        react_1.default.createElement(ink_1.Text, { color: "yellow" }, "Chave privada atual"),
        react_1.default.createElement(ink_1.Text, null,
            "d = ",
            stringifyKeyPart(state.privateKey?.d),
            ", n = ",
            stringifyKeyPart(state.privateKey?.n)),
        react_1.default.createElement(ink_1.Text, null, " "),
        menuOptions.map((option, index) => (react_1.default.createElement(ink_1.Text, { key: option.action, color: index === selectedIndex ? "black" : undefined, backgroundColor: index === selectedIndex ? "cyan" : undefined },
            index === selectedIndex ? "> " : "  ",
            option.label))),
        react_1.default.createElement(ink_1.Text, null, " "),
        react_1.default.createElement(ink_1.Text, { color: message?.startsWith("Erro:") ? "red" : "green" }, message ?? "Selecione uma opcao.")));
}
function FormView({ title, hints, fields, values, choices, index, message, }) {
    return (react_1.default.createElement(ink_1.Box, { flexDirection: "column" },
        react_1.default.createElement(ink_1.Text, { color: "green" }, title),
        react_1.default.createElement(ink_1.Text, null, "Digite o valor do campo atual e pressione Enter."),
        react_1.default.createElement(ink_1.Text, null, "Pressione Escape para cancelar e voltar ao menu."),
        hints.map((hint) => (react_1.default.createElement(ink_1.Text, { key: hint, color: "blue" }, hint))),
        react_1.default.createElement(ink_1.Text, null, " "),
        fields.map((field, fieldIndex) => {
            const prefix = fieldIndex === index ? ">" : " ";
            const optionalLabel = field.optional ? " (opcional)" : "";
            const fieldChoices = choices[field.name] ?? [];
            const hasChoices = fieldChoices.length > 0;
            const selectedChoice = values[field.name] ?? "";
            return (react_1.default.createElement(ink_1.Box, { key: field.name, flexDirection: "column" },
                react_1.default.createElement(InputLine, { label: `${prefix} ${field.label}${optionalLabel}`, value: values[field.name] ?? "" }),
                hasChoices && fieldIndex === index
                    ? fieldChoices.map((choice) => (react_1.default.createElement(ink_1.Text, { key: choice, color: choice === selectedChoice ? "green" : undefined },
                        choice === selectedChoice ? "  > " : "    ",
                        choice)))
                    : null));
        }),
        react_1.default.createElement(ink_1.Text, null, " "),
        react_1.default.createElement(ink_1.Text, { color: message?.startsWith("Erro:") ? "red" : "yellow" }, message ?? "")));
}
function App() {
    const { exit } = (0, ink_1.useApp)();
    const [cliState, setCliState] = (0, react_1.useState)({ publicKey: null, privateKey: null });
    const [selectedIndex, setSelectedIndex] = (0, react_1.useState)(0);
    const [message, setMessage] = (0, react_1.useState)("Selecione uma opcao.");
    const [screen, setScreen] = (0, react_1.useState)({ type: "menu" });
    function openForm(title, action, fields, hints = [], choices = {}) {
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
    function returnToMenu(nextMessage) {
        setScreen({ type: "menu" });
        setMessage(nextMessage);
    }
    function handleMenuSelect(action) {
        switch (action) {
            case "generateKeys":
                openForm("Gerar chaves", action, [
                    { kind: "bigint", name: "p", label: "p" },
                    { kind: "bigint", name: "q", label: "q" },
                ], ["Para suportar texto UTF-8, o modulo n (p * q) deve ser no minimo 256."]);
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
                openForm("Criptografar texto", action, [
                    { kind: "text", name: "text", label: "Texto UTF-8" },
                    { kind: "text", name: "exportFileName", label: "Arquivo de saida (.rsa)", optional: true },
                ], ["A entrada do texto e convertida em bytes UTF-8 antes da criptografia."]);
                return;
            case "decryptText":
                openForm("Descriptografar texto", action, [
                    { kind: "text", name: "cipherText", label: "Texto criptografado" },
                    { kind: "text", name: "exportFileName", label: "Arquivo de saida (.rsa)", optional: true },
                ]);
                return;
            case "decryptFile":
                {
                    const rsaFiles = listRsaFiles("encrypt");
                    if (rsaFiles.length === 0) {
                        returnToMenu(`Erro: Nenhum arquivo .rsa encontrado em ${OUTPUT_DIRS.encrypt}.`);
                        return;
                    }
                    openForm("Descriptografar a partir de arquivo .rsa", action, [
                        { kind: "text", name: "cipherFilePath", label: "Arquivo .rsa (selecione com as setas)" },
                        { kind: "text", name: "exportFileName", label: "Arquivo de saida (.rsa)", optional: true },
                    ], ["Use as setas para escolher o arquivo .rsa de entrada na pasta de encrypt."], { cipherFilePath: rsaFiles });
                    return;
                }
            case "exit":
                exit();
                return;
        }
    }
    function updateActiveField(nextValue) {
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
    function submitForm(formScreen) {
        try {
            const parsedValues = {};
            for (const field of formScreen.fields) {
                parsedValues[field.name] = parseFieldValue(field, formScreen.values[field.name] ?? "");
            }
            switch (formScreen.action) {
                case "generateKeys": {
                    const keys = (0, rsa_1.generateKeys)(parsedValues.p, parsedValues.q);
                    setCliState({ publicKey: keys.publicKey, privateKey: keys.privateKey });
                    returnToMenu(`Chaves geradas. Publica: e=${keys.publicKey.e.toString()}, n=${keys.publicKey.n.toString()}. ` +
                        `Privada: d=${keys.privateKey.d.toString()}, n=${keys.privateKey.n.toString()}.`);
                    return;
                }
                case "generateRandomKeys": {
                    const primeBits = Number(parsedValues.primeBits);
                    const keys = (0, rsa_1.generateRandomKeys)(primeBits);
                    setCliState({ publicKey: keys.publicKey, privateKey: keys.privateKey });
                    returnToMenu(`Chaves aleatorias geradas. Publica: e=${keys.publicKey.e.toString()}, n=${keys.publicKey.n.toString()}. ` +
                        `Privada: d=${keys.privateKey.d.toString()}, n=${keys.privateKey.n.toString()}.`);
                    return;
                }
                case "manualKeys": {
                    const publicKeyText = parsedValues.publicKeyText;
                    const privateKeyText = parsedValues.privateKeyText;
                    const parsedPublicKey = publicKeyText ? parseKeyPairInput(publicKeyText, "e") : null;
                    const parsedPrivateKey = privateKeyText ? parseKeyPairInput(privateKeyText, "d") : null;
                    const publicE = parsedPublicKey?.first ?? parsedValues.publicE;
                    const publicN = parsedPublicKey?.n ?? parsedValues.publicN;
                    const privateD = parsedPrivateKey?.first ?? parsedValues.privateD;
                    const privateN = parsedPrivateKey?.n ?? parsedValues.privateN;
                    const nextState = {
                        publicKey: cliState.publicKey,
                        privateKey: cliState.privateKey,
                    };
                    if (publicE !== null || publicN !== null) {
                        const nextPublicE = publicE ?? cliState.publicKey?.e;
                        const nextPublicN = publicN ?? cliState.publicKey?.n;
                        if (nextPublicE === undefined || nextPublicN === undefined) {
                            throw new Error("Para definir a chave publica pela primeira vez, informe e e n.");
                        }
                        (0, rsa_1.validateTextModulus)(nextPublicN);
                        nextState.publicKey = { e: nextPublicE, n: nextPublicN };
                    }
                    if (privateD !== null || privateN !== null) {
                        const nextPrivateD = privateD ?? cliState.privateKey?.d;
                        const nextPrivateN = privateN ?? cliState.privateKey?.n;
                        if (nextPrivateD === undefined || nextPrivateN === undefined) {
                            throw new Error("Para definir a chave privada pela primeira vez, informe d e n.");
                        }
                        (0, rsa_1.validateTextModulus)(nextPrivateN);
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
                    const cipherText = (0, encrypt_1.encryptText)(parsedValues.text, publicKey.e, publicKey.n);
                    const exportFileName = parsedValues.exportFileName;
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
                    const plainText = (0, decrypts_1.decryptText)(parsedValues.cipherText, privateKey.d, privateKey.n);
                    const exportFileName = parsedValues.exportFileName;
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
                    const cipherText = readCipherTextFromRsaFile(parsedValues.cipherFilePath);
                    const plainText = (0, decrypts_1.decryptText)(cipherText, privateKey.d, privateKey.n);
                    const exportFileName = parsedValues.exportFileName;
                    if (exportFileName) {
                        const outputPath = exportTextToRsaFile(exportFileName, plainText, "decrypt");
                        returnToMenu(`Arquivo descriptografado e salvo em ${outputPath}: ${plainText}`);
                        return;
                    }
                    returnToMenu(`Texto descriptografado do arquivo: ${plainText}`);
                    return;
                }
            }
        }
        catch (error) {
            setMessage(`Erro: ${error instanceof Error ? error.message : "Erro inesperado."}`);
        }
    }
    (0, ink_1.useInput)((input, key) => {
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
        return react_1.default.createElement(MenuView, { state: cliState, selectedIndex: selectedIndex, message: message });
    }
    return (react_1.default.createElement(FormView, { title: screen.title, hints: screen.hints, fields: screen.fields, values: screen.values, choices: screen.choices, index: screen.index, message: message }));
}
(0, ink_1.render)(react_1.default.createElement(App, null));
