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

The strongest VNAOLTE path is now the normal external RX path plus the existing complex measurement engines. Internal calpath remains valuable as an on-chip reference/calibration path, but it is not required to obtain complex receive data.


## Complex receive measurement without calpath

The `-rxirr` diagnostic is especially important because it measures the live RX paths without enabling any internal calibration path. Its handler at `0xD5209A3C` parses a test-frequency index, prints `Test Freq = ((%d) * 0.48) MHz`, temporarily reconfigures the RX NCO/IQCAL engine, measures main and diversity, and restores the previous RX state.

The firmware prints the raw complex registers for positive and negative NCO separately:

- main/RX0: I `0xFE002484`, Q `0xFE002488`, control `0xFE002480`
- diversity/RX1: I `0xFE00248C`, Q `0xFE002490`, control `0xFE002480`
- the same helper also supports RX2/RX3 at `0xFE002884/888/88C/890` with control `0xFE002880`

The production magnitude helper shifts the raw I/Q words right by 8, treats the remaining 21-bit value as signed (sign bit 20), and accumulates `I^2 + Q^2`. For reproducing the firmware conversion, `v = (raw >> 8) & 0x1fffff; if (v & 0x100000) v -= 0x200000`. Phase is then directly available as `atan2(Q, I)`. The raw diagnostic strings explicitly print `Main path I/Q positive`, `Div path I/Q positive`, the corresponding negative-NCO values, and their scalar magnitudes.

This is evidence for a stock **external-RX complex receiver** rather than merely an internal-loopback measurement primitive.

## TX test generation and internal calibration path

`-txt` takes one integer mode and calls the TX test generator at `0xD519C0AC`. The firmware documents modes 0 through 3 as single tone, four-tone, multi-tone, and LFSR tone. The four-tone setup reports frequency parameters 20, 240, 380, and 540 with `freq = value * 0.015`, i.e. nominal baseband offsets of 0.30, 3.60, 5.70, and 8.10 MHz. `-fft1` similarly accepts mode 0 (single tone) or 1 (multi tone). `-fft2` triggers the 2048-result complex correlator.

`-tx on|off` controls the TX RF state, while `-txg` passes an integer gain setting into the RF gain helper. These are useful controls for a bench harness, but RF output must be characterized into a cabled/attenuated load before relying on the numeric gain scale.

`Cal_TxCL` (`0xD518E3BC`) is TX carrier-leakage calibration. It enables the **main internal calpath**, runs IQCAL, and hill-climbs two correction fields in `0xFE001050` to minimize measured power. Production RX calibration likewise enables main/div/all calpath around IQCAL without invoking the external RFFE/PA/antenna-switch layer. Together with the fact that calpath modifies integrated RF-device registers 1, `0x20`, and `0x21`, this strongly places the stock calibration loop inside the GDM7243QT RF transceiver rather than through the antenna connector.

## External RF routing and VNA topology

The firmware independently exposes board-level routing. `rfm cal rtxsw [0~2]` controls `TR_SW/B` (manual states 0/1, state 2 returns control to the modem), and `rfm cal asdsw [0~1]` controls `ANT_SW/B`. These paths manipulate front-end control registers such as `0xFC000514`, `0xFC002094`, and `0xFC0020D4`; PAM and MIPI-RFFE controls are separate again. A recovered BOLT PL100/GDM7243Q reference RF diagram shows the expected architecture: two TX-capable RF paths and four RX paths with external baluns, filters, PAs and T/R/antenna switching. No directional coupler is obvious in that reference design.

That makes a practical VNA architecture straightforward in principle:

1. Tune TX and RX RF paths to the desired region. The `rfm cal rfpll [tx|rx] [freq_kHz] [port] [band]` interface accepts frequency as integer kHz and bypasses the 100 kHz EARFCN quantization of `-sfd/-sfu`; actual PLL resolution and out-of-band range still require hardware measurement.
2. Generate a known TX tone/multitone and route it to a physical RF port.
3. Feed a reference arm to one RX chain and the DUT response to another RX chain.
4. Read both complex channels in one `-rxirr` acquisition and use their complex ratio. Simultaneous main/div reception should cancel most source/retune phase drift.
5. For S21, use an external splitter/reference arm and feed DUT output to the second RX. For S11, add an external directional bridge/coupler and feed incident/reference and reflected samples to the two RX chains.
6. Calibrate the fixed TX/RX/front-end/bridge response in the usual VNA way.

A full two-port instrument needs source-direction switching (a second usable TX path or an external RF switch) and appropriate attenuation/isolation. The exact PL100/WF830 band-filter and connector routing still needs physical-board confirmation. No live RF transmit experiment has been performed as part of this archaeology.

## Live P4 RF-NV and PAM profiles

The live WF830/P4 `BD_CFG` object selects five FDD band pairs and a MIPI-programmable SKY77645-11 PAM profile family. Main VPorts select PAM IDs 14, 15, and 16, which the firmware names `SKY77645_11_MULTI_PORT1/2/3`; all use wanted USID `0x0f`. The firmware's six-byte PAM identity table at `0xD56AC6E8` independently identifies PAM IDs 14–17 as default USID `0x0f`, product `0x0a`, manufacturer `0xa5`. By contrast, RF5426 PAM IDs 28–32 use product/manufacturer `0xfd/0x34`.

That distinction resolves `rffe_ctrl_type=23`: type 23 probes MIPI registers `0x1d`/`0x1e` and promotes runtime control to type 29 only if a device answers `0xfd/0x34`. The promotion is compatibility logic for an RF5426-class hardware variant; it is not evidence that this P4 unit actually promotes. Its configured SKY77645 profiles expect `0x0a/0xa5`.

`DumpGctPamProfiles.java` makes the compiled PAM programming directly inspectable. The firmware constructors produce a fixed 0x22-byte record: six MIPI register addresses, four banks of six values, then four per-bank send counts. For SKY77645-11 the address vector is `00 01 02 03 00 00`, the send counts are `4,4,4,2`, and the shutdown bank writes register 0 and register 1 to zero. At representative live uplink frequencies, the active bank is:

| LTE band | live PAM ID | kHz | active MIPI writes |
|---|---:|---:|---|
| B8 | 14 / port 1 | 897500 | `R0=0x0c R1=0x5b R2=0x00 R3=0x8a` |
| B20 | 15 / port 2 | 847000 | `R0=0x1c R1=0x5b R2=0x00 R3=0x8a` |
| B3 | 16 / port 3 | 1747500 | `R0=0x44 R1=0x5f R2=0x00 R3=0xcb` |
| B1 | 15 / port 2 | 1950000 | `R0=0x3c R1=0x4e R2=0x00 R3=0xcb` |
| B7 | 14 / port 1 | 2535000 | `R0=0x6c R1=0xca R2=0x00 R3=0x89` |

The profile constructor therefore gives an exact software-side front-end control table even before the PCB traces are mapped. The next physical-routing question is how the SKY77645 output/T-R ports feed the WF830 duplexers, filters, and antenna switching, and whether its receive-switch state can expose a convenient same-frequency measurement path.

## Stock host DM transport

The application-side `lted` already provides a raw path into this modem command surface. `x_send_dm_command()` calls `LAPI_SendDMCommand(..., 1, cmd, strlen(cmd) + 1)`, while `cm_send_dm_cmd()` does the same for the normal CLI/file/socket paths. The hidden `x` runner treats a token beginning with `dm ` specially and forwards the remainder verbatim; the normal command paths call `do_cmd()` first and forward text that is not consumed locally. This means a VNA control shim should first reuse the stock DM channel rather than patching a new modem transport.

The recovered command hierarchy is itself useful evidence: the top-level `-rfm` record is a subgroup whose target is the RF command table containing `-fft1`, `-fft2`, `-txt`, calibration-path controls, direct frequency/bandwidth setters, `-cal`, and `-rffe`.

## DMA and sample-path findings

The firmware has multiple genuine hardware-to-RAM result paths. They are useful for instrumentation, but the paths recovered so far are processed measurement data rather than raw ADC IQ.

### CSI DMA

`csi_process_dma_intr` is the function at `0xD5230620`; the identity is confirmed by the embedded `__func__` string at `0xD54FC754`. The CSI interrupt/event path monitors the CQI/CSI register bank rooted at `0xFE006040` and hands completed slots to this routine. A CSI setup routine performs cache maintenance over `[buffer, buffer + 0x850)` before arming the hardware, proving that the approximately `0x850`-byte record is a DMA-visible RAM buffer rather than a later software copy.

The record contains packed RI/PMI/ppCINR/subband/channel-state data. `csi_process_dma_intr` walks the packed words, derives CSI metrics, emits the `[CSI][DMA]` diagnostics found in the image, and clears the record back to `0xffffffff` after consumption. `CQI_CONFIG0` at `0xFE006040 + 0x40*n` exposes fields including `INTR_EN`, `DONE_FLAG`, `REPORT_METRIC`, `TARGET_M`, and explicit RI/PMI/ppCINR enables. This is therefore a real DSP-result DMA path, but not a raw-IQ stream.

The hidden CSI `-dma` command only toggles the DMA diagnostic state; it does not itself start a generic DMA engine.

### Measurement-engine output buffers

The hidden `-dma_addr` command exposes a second, independent result path. It prints the runtime ME UE/PE output-buffer table. Consumers perform cache maintenance over `0x958` bytes per output buffer and over associated `0x340`-byte side/result blocks. These buffers feed measurement processing such as RSSI/RSRP/CINR rather than raw IQ, but they are further evidence that the baseband routinely writes substantial DSP results directly into software-visible RAM.

### ADC routing and FIBC

`set_rx_adc_ant_mux_sel` is the function at `0xD51782A4`. It programs the per-RX mux fields in `0xFE002004`; its callers switch additional `0xFE0024xx`, `0xFE0028xx`, and RF-control state. The calibration/test interface also advertises RX ATE selections for `ADC output`, `RXBB to ADC`, and `RXBB output`, plus an `adc_copy_mode` control. These are real pre-DSP routing surfaces and are the best bridge candidates into an earlier capture path.

The PP diagnostic namespace contains `-fibc`, expanded by the firmware itself as **FFT Input Buffer Control**. Detailed branch tracing shows that its special paths manipulate PP timing/alignment/window-control state (`tau_0`, `MaxDIFF`, `ONE-STEP`, gear-shift and related controls) plus normal FFT/PP configuration. They do **not** copy a sample payload to RAM. FIBC is therefore not currently a raw-capture lead. No explicit `ADC DMA`, `IQ DMA`, or `FFT DMA` command/string has been recovered yet, so raw-IQ DMA remains unproven.

For VNAOLTE this means DMA is an enhancement rather than a prerequisite: the hardware correlator already provides complex I/Q results for vector measurements. If an ATE/ADC or other pre-DSP path can be steered into a RAM-visible buffer, the same hardware could additionally provide spectrum/time-domain or SDR-like capture without making the correlator path depend on that work.
