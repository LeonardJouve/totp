import {base32} from "@scure/base";
import {print} from "./hotp";

// Authenticator app take a base32 encoded secret
const secret = base32.decode("I65VU7K5ZQL7WB4E");
const digits = 6;

print(secret, digits);
