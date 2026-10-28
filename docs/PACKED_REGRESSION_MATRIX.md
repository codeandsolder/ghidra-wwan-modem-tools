# Qualcomm packed-segment regression matrix

The packed-segment analyzers are intentionally detected by structure rather than modem model, segment number, or fixed address. The fixtures below are the current cross-generation regression corpus. Large firmware files are not stored in this repository; hashes pin the exact inputs used for validation.

| Fixture | Exact input | q6zip expectation | zlib/debug expectation | CLADE expectation |
| --- | --- | --- | --- | --- |
| Sierra EM7455 / SWI9X30C 02.38.00.00 | `modem.mdt` SHA-256 `94d3d18eaca50c854753dfaeafb4c17cbeacd51483ef6798eef28d8d545c1a5b` | map `d0000000..d0eb3000`; v0; dict 10/12; lookback 9; 3762 full + one terminal short page | old 16-byte pointer-validated record layout; 48,672 records; 369 RF-interest | none |
| Quectel EG25-G / MDM9607 | `modem.mdt` SHA-256 `ea7eccd655405a77d1937bab83d16e30c578de6c7daeeb1d205cb3c418357b00` | map `d0000000..d1179000`; v0x0600; dict 10/14; lookback 8; 4473 full pages | old pointer-validated layout; 5,911 records; 39 RF-interest | none |
| Quectel RM500Q / SDX55 | `modem.mdt` SHA-256 `e372ca9cdab4dfa929521684e7998ec2fe8a85d0c00f4bd07cea982e136c6ffc` | decline | dense diagnostic string-pool layout; 94,644 strings / 77,481 diagnostic / 879 RF-interest | full mapping `cc4c0000..ce891000 -> d4800000..d6bd0000` |
| Telit LN920 | `modem.mdt` SHA-256 `2864ee9b96f5303ba359fb8fb918e51503be657bc4a8510dd51be71b1ac8685e` | map `d0000000..d0e0f000`; v0; dict 10/12; lookback 4; 3286 full + 313 short pages; descriptor permits sub-page packed tail padding; dictionary-order near-tie is resolved by full-page scoring | raw DEFLATE body is complete but RFC1950 Adler-32 is nonstandard/stale; exact raw-body completion yields 898 pointer-validated records | none |
| Telit FN990A28 45.00.105 | `modem.mdt` SHA-256 `fb13eaf44de0712f1d73d7221244e7301c6dce010ba31ce838915ba6dde3262f` | decline | decline: the candidate body does not complete as valid raw DEFLATE | identify self-described `.clade.comp` packed block; do not invent a runtime mapping |

## Package provenance hashes

- Telit `FN990A28_45.00.105.tar.gz`: `967b8e09bbae88a257a5ce80ca2fc96d74ad3bdbd6d924d08fef699e46af79dc`
- Telit `LN920_40.00.002.tar.gz`: `ee44c87cc060b0480f9d363b059469216f0c34fdefc92e1102b3cd7de4f4c467`
- Quectel `EG25GGBR07A08M2G_A0.302.A0.302.tar.gz`: `5c7d2b4ebba2bfc56cebec0fcd55e3ec7e7aef25d5eeb50537abda9bd88aeebd`

## Why these cases matter

The corpus deliberately exercises incompatible-looking generations instead of five copies of one layout:

- q6zip dictionary sizes/order, lookback width, version, page count, packed addresses, and DLPager descriptor shape all vary;
- Qualcomm debug data appears as old pointer records, a modern dense string pool, and an RFC1950 container with a valid raw DEFLATE body but invalid trailer;
- CLADE appears both with a recoverable compressed-to-runtime tuple and with only a self-described packed region;
- negative cases are part of the contract: an analyzer must decline unsupported layouts cleanly rather than create a plausible-looking wrong mapping.

Run `ProbeQualcommPacked.java` with `-noanalysis` against any split `modem.mdt` to print the analyzer decisions and created blocks/bookmarks. Exact per-fixture assertions remain useful for pinned images; the generic probe is intended to expose behavior on new firmware without baking model names into the analyzers.
