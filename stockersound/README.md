# StockerSound

Export The Sims 2, The Urbz or Spyro: Shadow Legacy DS music bank to editable Impulse Tracker files, or render
it through the game's original ARM9 sequencer and mixer running in Unicorn.
Based on Eggrens's SoundData research and the sounddata-spec investigation.
No module-specific fixes are applied. Each region executes its own original
instructions using a verified address map.

Requires Python 3.11 or newer and your USA, Europe or Japan Sims 2 or Urbz
cartridge dump, or USA/Europe Spyro: Shadow Legacy dump.
Other games/revisions are not supported. Setup installs pinned dependencies
in a local `.venv` and verifies both extracted inputs before saving them.

From this folder, run:

```sh
python3 setup.py "/path/to/The Sims 2.nds"

# Export all modules (45 Sims 2 / 61 Urbz / 39 Spyro), or just one
.venv/bin/python stockersound.py export
.venv/bin/python stockersound.py export --module 14

# Render one module with the original DS runtime
.venv/bin/python stockersound.py render --module 14 --seconds 120
```

On Windows, use `python setup.py ...` and `.venv\Scripts\python.exe` for the
main commands.

Setup creates `data/arm9.bin` and `data/SoundData.rom`. Export creates
`output/it/module00.it` through `module44.it` (Sims 2) or `module60.it`
(Urbz), or `module38.it` (Spyro), with JSON diagnostics alongside.
Rendering creates `output/moduleNN.wav`: 16-bit stereo PCM at 32768 Hz for
Sims 2 and Spyro, or the original timer-derived rate (32728 Hz) for Urbz.
Module numbers are zero-based bank indices, not OST track numbers.

Optional output paths and native tracing:

```sh
.venv/bin/python stockersound.py export --output-dir /path/to/modules
.venv/bin/python stockersound.py render --module 14 --seconds 120 \
  --output /path/to/music.wav --trace /path/to/ticks.json
```

The IT files are editable reconstructions; standard tracker playback can
differ from the DS engine. Native rendering retains the original sample tails,
loops, timing and voice behavior, including Sims 2 module 14's observed tail. This
is a focused audio runtime, not a full DS emulator; hardware/game integration
has not been fully validated. Some source sample-map warnings are deliberately
preserved in the export reports. A fixed-duration render can continue with the
native mixer noise floor after a song stops. Long renders/traces take time
and can produce large files.

Urbz uses its own older original loader, integrated packet/tick decoder and
ITCM mixer. Native rendering sets master output volume to 127 through the
original setters, since saved-game volume preferences are absent. Its PCM
can vary slightly with scheduler batch boundaries; the renderer defaults to
2048-frame batches. This does not change musical events or voice state.

Spyro uses its cartridge ARM player and ITCM mixer with three documented,
general runtime repairs. Both supplied regions share the same bank. All 1,106
patterns decode with the original reader/seeker, and all 39 modules export
and complete the bounded native playback checks.

The repairs run as ARM instructions inside Unicorn:

- Expand the original sample-loader stack frame to fit all 255 possible sample
  slots. This allows module 22's 119 slots without replacing asset decoding.
- Keep source filter envelopes out of pitch calculations. The DS runtime has
  no corresponding filter implementation, so rendering ignores that filter;
  the editable IT retains it and reports the possible timbre difference.
- Apply semitone pitch envelopes through the cartridge's linear-slide helper,
  independently of the song's ordinary Amiga/linear slide mode. This avoids
  extreme frequencies and out-of-buffer reads on modules 6, 24 and 29.

No module numbers are special-cased and no notes, envelopes or sample bytes
are edited. The input ARM9 file is preserved; only the emulated copy is
patched. Export reports and optional render traces list the runtime changes.
These repaired renders are not claims of bit-identical in-game audio.

To investigate the unmodified player, disable repairs explicitly:

```sh
.venv/bin/python stockersound.py render --module 6 --seconds 2 --unmodified-runtime
```

That mode reproduces the original software-mixer failure; it also refuses
sample counts above the unsafe original 100-slot loader limit. Failed renders
do not overwrite a previous WAV or publish partial audio.
