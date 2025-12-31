import assert from "node:assert";
import {describe, it} from "node:test";
import {numberToBigEndianArray, hmac, HMACAlgorithm, truncate, format, totp} from "../src/hotp";

describe("hotp", () => {
    it("numberToBigEndianArray", () => {
        [
            {input: 0x1, expected: [0, 0, 0, 0, 0, 0, 0, 0x01]},
            {input: 0x10, expected: [0, 0, 0, 0, 0, 0, 0, 0x10]},
            {input: 0x1000000, expected: [0, 0, 0, 0, 0x01, 0, 0, 0]},
            {input: 0x10000000, expected: [0, 0, 0, 0, 0x10, 0, 0, 0]},
        ].forEach(({input, expected}, i) => {
            const result = numberToBigEndianArray(input);
            assert.deepEqual(result, Uint8Array.from(expected), String(i));
        });
    });
    it("hmac-sha1", () => {
        const secret = "12345678901234567890";
        [
            "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
            "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
            "0bacb7fa082fef30782211938bc1c5e70416ff44",
            "66c28227d03a2d5529262ff016a1e6ef76557ece",
            "a904c900a64b35909874b33e61c5938a8e15ed1c",
            "a37e783d7b7233c083d4f62926c7a25f238d0316",
            "bc9cd28561042c83f219324d3c607256c03272ae",
            "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
            "1b3c89f65e6c9e883012052823443f048b4332db",
            "1637409809a679dc698207310c8c7fc07290d9e5",
        ].forEach((expected, i) => {
            const result = hmac(HMACAlgorithm.SHA1, secret, numberToBigEndianArray(i));
            assert.deepEqual(result, Uint8Array.from(Buffer.from(expected, "hex")));
        });
    });
    it("truncate", () => {
        const digits = 6;
        [
            {input: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", expected: 755224},
            {input: "75a48a19d4cbe100644e8ac1397eea747a2d33ab", expected: 287082},
            {input: "0bacb7fa082fef30782211938bc1c5e70416ff44", expected: 359152},
            {input: "66c28227d03a2d5529262ff016a1e6ef76557ece", expected: 969429},
            {input: "a904c900a64b35909874b33e61c5938a8e15ed1c", expected: 338314},
            {input: "a37e783d7b7233c083d4f62926c7a25f238d0316", expected: 254676},
            {input: "bc9cd28561042c83f219324d3c607256c03272ae", expected: 287922},
            {input: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", expected: 162583},
            {input: "1b3c89f65e6c9e883012052823443f048b4332db", expected: 399871},
            {input: "1637409809a679dc698207310c8c7fc07290d9e5", expected: 520489},
        ].forEach(({input, expected}) => {
            const result = truncate(Uint8Array.from(Buffer.from(input, "hex")), digits);
            assert.deepEqual(result, expected);
        });
    });
    it("format", () => {
        const digits = 6;
        [
            {input: 5, expected: "000005"},
            {input: 123, expected: "000123"},
            {input: 0, expected: "000000"},
            {input: 42, expected: "000042"},
            {input: 9876, expected: "009876"},
        ].forEach(({input, expected}) => {
            const result = format(input, digits);
            assert.deepEqual(result, expected);
        });
    });
    it("totp", () => {
        const secret = "12345678901234567890";
        const timeStep = 30;
        const initialTime = 0;
        const digits = 8;
        [
            {input: 59, expected: "94287082"},
            {input: 1111111109, expected: "07081804"},
            {input: 1111111111, expected: "14050471"},
            {input: 1234567890, expected: "89005924"},
            {input: 2000000000, expected: "69279037"},
            {input: 20000000000, expected: "65353130"},
        ].forEach(({input, expected}) => {
            const result = totp(secret, digits, input, timeStep, initialTime);
            assert.deepEqual(result, expected);
        });
    });
});

