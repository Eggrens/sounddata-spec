# StockerSound (SoundData.rom) File Format Specification

This project aims to document the StockerSound (SoundData.rom) format and provides tools to export Impulse Tracker modules and raw samples from the file.
This format is found in Nintendo DS games developed by Amaze Entertainment, such as **The Sims 2**, **The Urbz: Sims in the City**, and **Spyro: Shadow Legacy**.


See the [rough specification](./sounddata-format.txt) for more details.

## Tools

### StockerSound Parser

The StockerSound Parser can be found in the `stockersound` directory. See its [README](./stockersound/README.md) for how to use it.

The parser can export modules from the module bank in SoundData.rom to editable Impulse Tracker module (.it) files. It can also render modules as WAV by emulating the ROM's ARM9 sequencer and mixer.

Many thanks to [@EshayDev](https://github.com/EshayDev) for writing this parser!!

### StockerSound Sample Exporter

Exports samples from SoundData.rom as WAV files. This converts any signed 8-bit PCM or 4-bit IMA-ADPCM data into signed 16-bit PCM. You can find it in the `audio-exporter` directory ([link to script](./audio-exporter/audio-exporter.py)).

See the help dialog below on how to use it:
```
usage: audio-exporter.py [-h] [-s SAMPLE] sounddata

positional arguments:
  sounddata             path to SoundData.rom file

options:
  -h, --help            show this help message and exit
  -s SAMPLE, --sample SAMPLE
                        extract a specific sample by index number
```

Examples:
```sh
# export all samples
$ python3 audio-exporter.py /path/to/SoundData.rom
# export a sample by index
$ python3 audio-exporter.py /path/to/SoundData.rom --sample 25
```

If you're on Windows, replace `python3` with `python`.

## Games Analyzed so Far

- The Sims 2 (DS)
- The Urbz: Sims in the City (DS)
- Spyro: Shadow Legacy

## Special Thanks

Special thanks to:
- FAST6191 and RyanPenfold from the GBATemp Forums, for providing helpful information and inspiring me to start this project in the first place.
- EshayDev, for additional research and writing the StockerSound parser.