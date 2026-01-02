import {base32} from "@scure/base";
import {spawn} from "node:child_process";
import {totp} from "./hotp";

if (process.argv.length < 3) {
    throw new Error(`usage: "${process.argv[1]} <secret>"`);
}

// Authenticator app take a base32 encoded secret
const base32Secret = process.argv[2];
const secret = base32.decode(base32Secret);
const digits = 6;

const result = totp(secret, digits);
spawn("clip").stdin.end(result);
console.log("Done");
