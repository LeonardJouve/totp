import {base32} from "rfc4648";
import {totp} from "./hotp";

const digits = 6;
// Authenticator app take a base32 encoded secret
const secret = base32.parse("I65VU7K5ZQL7WB4E");

const execute = () => {
    const result = totp(secret, digits);
    console.log(result);
};

execute();

setTimeout(() => {
    execute();
    setInterval(execute, 30_000);
}, 30_000 - Date.now() % 30_000);
