# GCT GDM7243 RF archaeology

The WF830/GDM7243 family is ARM BE8: instruction bytes are little-endian while ordinary data words are big-endian. Stock Ghidra 12.2 has no ARMv6 mixed-endian language, but `ARM:LEBE:32:v7LEInstruction` has the correct instruction/data endian split and decodes the observed ARM11/v6 instruction stream because ARMv7 is a superset. For headless raw import use `-processor ARM:LEBE:32:v7LEInstruction -cspec default`. Do not import these modem images as plain `ARM:LE:32:v6` when following data tables or pointers.

For the live Polish P4 WF830 image currently under study, the linked image base is `0xD5100000`. This is independently visible in absolute addresses constructed with `movw`/`movt` and in big-endian command-table pointers. A raw import should therefore use that base rather than rebasing a program after auto-analysis.

`ghidra_scripts/GctRfSurvey.java` is the durable RF archaeology tool for this family. In addition to RF-related string/xref triage it scans initialized memory for the two GCT command-table layouts seen in firmware:

- `name, description, flags, target`
- `target, name, description, flags`

Leaf records carry odd Thumb function pointers. Group records such as top-level `-rfm` carry aligned pointers to another command table; the survey validates those recursively instead of pretending every target is executable code. Words are decoded explicitly as big-endian so table recovery also works on an older incorrectly imported project. Runs are accepted only when adjacent records satisfy command-name, pointer, description, flags, and structurally valid target constraints. Recovered handlers/subtables are bookmarked; handler functions are tagged and default `FUN_*` names are upgraded to `gct_cmd_*` where Ghidra already has a function boundary.

The RF surface recovered on the WF830 includes the `-rfm` command family with direct frequency/bandwidth programming, RFFE access, calibration-path routing, TX tone generation, ADC/DAC test routing, AGC/AFC controls, and a hardware complex correlator. Of particular interest:

- `-txt` drives the calibration/test tone generator.
- `-fft2` reaches a hardware correlator whose result words contain signed 12-bit I and signed 12-bit Q and whose firmware prints `CORR_I`, `CORR_Q`, and `I²+Q²` for 2048 results.
- `-cpen`, `-cpmen`, `-cpden`, `-cpdis` control all/main/div calibration paths.
- `-sfd`, `-sfu`, and `-sf` directly program downlink/uplink/TDD RF frequencies.
- `-cal` exposes the much larger `rfm cal ...` interface including PLL frequency-in-kHz and DAC tone controls.
- `-rffe` exposes raw MIPI RFFE commands.

This makes the calibration path + known TX waveform + complex correlator the primary VNAOLTE path to characterize before investing in raw IQ export.

## Stock host DM transport

The application-side `lted` already provides a raw path into this modem command surface. `x_send_dm_command()` calls `LAPI_SendDMCommand(..., 1, cmd, strlen(cmd) + 1)`, while `cm_send_dm_cmd()` does the same for the normal CLI/file/socket paths. The hidden `x` runner treats a token beginning with `dm ` specially and forwards the remainder verbatim; the normal command paths call `do_cmd()` first and forward text that is not consumed locally. This means a VNA control shim should first reuse the stock DM channel rather than patching a new modem transport.

The recovered command hierarchy is itself useful evidence: the top-level `-rfm` record is a subgroup whose target is the RF command table containing `-fft1`, `-fft2`, `-txt`, calibration-path controls, direct frequency/bandwidth setters, `-cal`, and `-rffe`.
