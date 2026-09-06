// Native-messaging host for the box's WebAuthn proxy extension. Chrome spawns
// this per ceremony and speaks native-messaging framing on stdio: a 4-byte
// little-endian length, then that many bytes of UTF-8 JSON.

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";

const HEADER_BYTES = 4;
const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;
const SAND_BOX_PORT_HOST_GATEWAY = "1340";

function readEnv(name, fallback) {
	const value = process.env[name];
	return value === undefined || value === "" ? fallback : value;
}

function credentialFile() {
	const primaryDir = readEnv(
		"SAND_PRIMARY_XDG_RUNTIME_DIR",
		"/tmp/xdg-runtime-box"
	);
	for (const runtimeDir of [readEnv("XDG_RUNTIME_DIR", undefined), primaryDir]) {
		if (runtimeDir === undefined) {
			continue;
		}
		try {
			const [token, port] = readFileSync(
				`${runtimeDir}/sand-gateway-credential`,
				"utf8"
			).split("\n");
			if (token !== undefined && token !== "") {
				return { token, port };
			}
		} catch {}
	}
	return undefined;
}

function gatewayBaseUrl(credential) {
	const port = readEnv("SAND_HOST_PORT", undefined) ?? credential?.port ?? SAND_BOX_PORT_HOST_GATEWAY;
	return `http://127.0.0.1:${port}`;
}

function writeMessage(payload) {
	const body = Buffer.from(JSON.stringify(payload), "utf8");
	const header = Buffer.alloc(HEADER_BYTES);
	header.writeUInt32LE(body.length, 0);
	process.stdout.write(Buffer.concat([header, body]));
}

function failure(name, message) {
	return { ok: false, error: { name, message } };
}

async function readMessage() {
	const chunks = [];
	let total = 0;
	for await (const chunk of process.stdin) {
		chunks.push(chunk);
		total += chunk.length;
		if (total > MAX_MESSAGE_BYTES) {
			throw new Error("native message exceeded the maximum size");
		}
		const buffered = Buffer.concat(chunks, total);
		if (buffered.length < HEADER_BYTES) {
			continue;
		}
		const length = buffered.readUInt32LE(0);
		if (buffered.length >= HEADER_BYTES + length) {
			return JSON.parse(
				buffered.subarray(HEADER_BYTES, HEADER_BYTES + length).toString("utf8")
			);
		}
	}
	return undefined;
}

async function requestCeremony(message) {
	const credential = credentialFile();
	const token = readEnv("SAND_GATEWAY_TOKEN", undefined) ?? credential?.token;
	if (token === undefined) {
		return failure(
			"NotAllowedError",
			"Sand's in-box gateway token is not available to the browser bridge."
		);
	}

	const response = await fetch(
		`${gatewayBaseUrl(credential)}/api/requestWebAuthnCeremony`,
		{
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${token}`,
			},
			body: JSON.stringify({
				kind: message.kind,
				origin: message.origin,
				optionsJson: message.optionsJson,
			}),
		}
	);
	if (!response.ok) {
		return failure(
			"NotAllowedError",
			`Sand's in-box host refused the ceremony (HTTP ${response.status}).`
		);
	}
	return await response.json();
}

async function main() {
	let message;
	try {
		message = await readMessage();
	} catch (error) {
		writeMessage(failure("DataError", `unreadable native message: ${error}`));
		return;
	}
	if (message === undefined) {
		writeMessage(failure("DataError", "no native message was received"));
		return;
	}

	try {
		writeMessage(await requestCeremony(message));
	} catch (error) {
		writeMessage(
			failure(
				"NotAllowedError",
				`could not reach Sand's in-box host: ${error?.message ?? error}`
			)
		);
	}
}

await main();
