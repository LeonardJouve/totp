import {base32} from "@scure/base";
import {print} from "./hotp";

const digits = 6;
// Authenticator app take a base32 encoded secret
const secret = base32.decode("I65VU7K5ZQL7WB4E");

print(secret, digits);
