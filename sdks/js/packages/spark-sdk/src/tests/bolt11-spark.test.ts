import { describe, expect, it } from "@jest/globals";
import { decodeInvoice } from "../services/bolt11-spark.js";

// examples taken from BOLT-11 spec § Examples (2025-06-04)
// https://github.com/lightning/bolts/blob/master/11-payment-encoding.md#examples
describe("spark bolt11 invoice decoding", () => {
  it("decodes bolt11 example-1", () => {
    const invoice =
      "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
    const { amountMSats, fallbackAddress, paymentHash } =
      decodeInvoice(invoice);
    expect(amountMSats).toBe(null);
    expect(fallbackAddress).toBe(undefined);
    expect(paymentHash).toBe(
      "0001020304050607080900010203040506070809000102030405060708090102",
    );
  });

  it("decodes bolt11 example-2", () => {
    const invoice =
      "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
    const { amountMSats, fallbackAddress, paymentHash } =
      decodeInvoice(invoice);
    expect(amountMSats).toBe(250_000_000n);
    expect(fallbackAddress).toBe(undefined);
    expect(paymentHash).toBe(
      "0001020304050607080900010203040506070809000102030405060708090102",
    );
  });

  it("decodes bolt11 example-4", () => {
    const invoice =
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44";
    const { amountMSats, fallbackAddress, paymentHash } =
      decodeInvoice(invoice);
    expect(amountMSats).toBe(2_000_000_000n);
    expect(fallbackAddress).toBe(undefined);
    expect(paymentHash).toBe(
      "0001020304050607080900010203040506070809000102030405060708090102",
    );
  });

  it("fails to decode bolt11 invoice with invalid checksum", () => {
    const invoice =
      "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow("Invalid checksum");
  });

  it("fails to decode a bolt11 invoice that is too short", () => {
    const invoice =
      "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh";

    expect(() => {
      decodeInvoice(invoice);
    }).toThrow();
  });

  it("fails to decode malformed Bolt11 invoice - no prefix/data separator", () => {
    const invoice =
      "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow('Letter "1" must be present between prefix and data only');
  });

  it("fails to decode malformed Bolt11 invoice - mixed case", () => {
    const invoice =
      "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow("String must be lowercase or uppercase");
  });

  it("fails to decode bolt11 invoice with invalid signature", () => {
    const invoice =
      "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnarugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow("Invalid BOLT11 signature");
  });

  it("fails to decode bolt11 invoice with invalid multiplier", () => {
    const invoice =
      "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow("Invalid multiplier: x");
  });

  it("fails to decode bolt11 invoice with invalid submillisatoshi precision", () => {
    const invoice =
      "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow("Invalid submillisatoshi precision");
  });

  it("fails to decode bolt11 invoice with invalid payment secret", () => {
    const invoice =
      "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp49qdkj";
    expect(() => {
      decodeInvoice(invoice);
    }).toThrow("Invalid payment secret");
  });

  it("decodes a bolt11 invoice with spark address embedded", () => {
    const invoice =
      "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgqfpml2dgykqjsjj0vxkcz9cuftlfhw5qs9720aqf4y0azyqggx29gz7gt7eadu5h5wqmn7ns8rju0ps0tk8jx70eg8jxek3usgsehql0ztdxmfjj58nqjky6w9wp324ctcnj9vnrgc8j9dpujfqjrc8lv9z4twr2pur2cgqujn2dx";

    const { amountMSats, fallbackAddress, paymentHash } =
      decodeInvoice(invoice);

    expect(amountMSats).toBe(null);
    expect(fallbackAddress).toBe(
      "53504b0250949ec35b022e3895fd37750102f94fe813523fa220108328a81790bf67ade5",
    );
    expect(paymentHash).toBe(
      "0001020304050607080900010203040506070809000102030405060708090102",
    );
  });
});
