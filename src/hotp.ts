import {BinaryLike, createHmac} from "node:crypto";

export enum HMACAlgorithm {
    SHA1 = "sha1",
    SHA256 = "sha256",
    SHA512 = "sha512",
}

export const hmac = (algorithm: HMACAlgorithm, secret: BinaryLike, value: BinaryLike) =>
    Uint8Array.from(Buffer.from(createHmac(algorithm, secret)
        .update(value)
        .digest("hex"), "hex"));

export const numberToBigEndianArray = (digit: number) => {
    const result = new Uint8Array(8);
    let tmp = digit;
    for (let i = result.length - 1; i >= 0; i--) {
        result[i] = tmp & 0xff;
        tmp >>= 8;
    }

    return result;
};

export const truncate = (hmacResult: Uint8Array, digits: number) => {
    // Take last byte as offset
    const offset = hmacResult[hmacResult.length - 1] & 0xf;

    // Make sure the first bit is a 0 to ensure the result is unsigned
    const result =
        ((hmacResult[offset] & 0x7f) << 24) |
        ((hmacResult[offset + 1] & 0xff) << 16) |
        ((hmacResult[offset + 2] & 0xff) << 8) |
        (hmacResult[offset + 3] & 0xff);


    return result % (10 ** digits);
};

export const format = (result: number, digits: number) =>
    String(result)
        .padStart(digits, "0");

export const hotp = (secret: BinaryLike, digits: number, step: number) => {
    const cipher = hmac(HMACAlgorithm.SHA1, secret, numberToBigEndianArray(step));
    const result = truncate(cipher, digits);

    return format(result, digits);
};

// TODO select algo
export const totp = (secret: BinaryLike, digits: number, time: number = Math.floor(Date.now() / 1_000), timeStep: number = 30, initialTime: number = 0) => {
    const step = Math.floor((time - initialTime) / timeStep);
    return hotp(secret, digits, step);
};

export const print = (secret: BinaryLike, digits: number, time: number = Math.floor(Date.now() / 1_000), timeStep: number = 30, initialTime: number = 0) => {
    const execute = () => {
        const result = totp(secret, digits, time, timeStep, initialTime);
        console.log(result);
    };

    execute();

    setTimeout(() => {
        execute();
        setInterval(execute, 30_000);
    }, 30_000 - Date.now() % 30_000);
};
