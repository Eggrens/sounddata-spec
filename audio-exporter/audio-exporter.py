import struct
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "out"

class Sample:
    def __init__(self, header: bytes):
        self.raw_index = struct.unpack("<I", header[:4])[0]
        flag_byte = struct.unpack("B", header[5:6])[0]
        self.is_adpcm = bool(flag_byte & 8)
        self.channels = 2 if flag_byte & 4 else 1

        if flag_byte & 2:
            self.bps = 16
        else:
            if self.is_adpcm:
                self.bps = 4
            else:
                self.bps = 8

        self.length = struct.unpack("<I", header[8:12])[0]
        self.sample_rate = struct.unpack("<I", header[20:24])[0]

    def __str__(self):
        return f"[ index = {self.raw_index}, {self.bps}-bit {'stereo' if self.channels == 2 else 'mono'}" \
               f"{'IMA-ADPCM' if self.is_adpcm else 'PCM'}, length = {self.length} samples, sample rate = {self.sample_rate} Hz ]"


def get_sample_list(data, sample_ptrs: tuple):
    samples = []
    for ptr in sample_ptrs:
        data.seek(ptr)
        samples.append(Sample(data.read(32)))
    return samples

def get_audio_list(data, audio_ptrs: tuple):
    audios = []
    for i, ptr in enumerate(audio_ptrs):
        data.seek(ptr)
        if i < len(audio_ptrs) - 1:
            data_length = audio_ptrs[i+1] - ptr
            audios.append(data.read(data_length))
        else:
            audios.append(data.read())
    return audios

def clamp(value, min, max):
    if value < min: return min
    if value > max: return max
    return value

IMA_INDEX_TABLE = [
    -1, -1, -1, -1, 2, 4, 6, 8,
    -1, -1, -1, -1, 2, 4, 6, 8
]

IMA_STEP_TABLE = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
    19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
    130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
    876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
    5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767
]


def decode_adpcm(data: bytes, num_samples: int):
    """
    Based on:
        https://wiki.multimedia.cx/index.php/IMA_ADPCM
        https://gist.github.com/aquagoose/526a2d6bc829f39a01d29dc2de0b8146
        https://github.com/eurotools/es-ima-adpcm-encoder-decoder/blob/main/ImaAdpcm-Encoder-Decoder/AudioCodec/ImaAdpcm.cs

    This decoding algorithm only handles mono for now.
    """
    converted_data = bytearray(num_samples * 2)     # IMA-ADPCM: 2 samples per byte -> PCM16: 1 sample per 2 bytes

    # NDS IMA-ADPCM has a 4-byte header before data starts:
    #   Bits 0-15:  Initial PCM16 predictor value (between -32767 to 32767)
    #   Bits 16-22: Inital step table index value (between 0-88)
    #   Bits 23-31: Not used (zero)
    # See: https://problemkaputt.de/gbatek-ds-sound-notes.htm
    predictor = struct.unpack_from("<h", data, 0)[0]
    step_index = struct.unpack_from("B", data, 2)[0]
    step = IMA_STEP_TABLE[step_index]

    adpcm_data = data[4:]

    conv_data_index = 0
    for byte in adpcm_data:
        for n in range(2):
            if n == 0:
                # get top nibble
                nibble = (byte >> 4) & 0xf
            else:
                # get bottom nibble
                nibble = byte & 0xf

            sign = nibble & 8
            delta = nibble & 7
            diff = step >> 3

            if delta & 4: diff += step
            if delta & 2: diff += (step >> 1)
            if delta & 1: diff += (step >> 2)

            if sign != 0:
                predictor -= diff
            else:
                predictor += diff

            # PCM16 values on the DS are clamped between -32767 to 32767, NOT -32768 to 32767 like it usually would be
            predictor = clamp(predictor, -32767, 32767)
            step_index += IMA_INDEX_TABLE[nibble]
            step_index = clamp(step_index, 0, 88)
            step = IMA_STEP_TABLE[step_index]

            converted_data[conv_data_index:conv_data_index+2] = struct.pack("<h", predictor)
            conv_data_index += 2

    return converted_data

def make_pcm16_wav(sample: Sample, audio: bytes, sample_num: int):
    if not sample.is_adpcm and sample.bps == 8:
        # first convert signed 8-bit PCM into signed 16-bit PCM. WAV does not support signed 8-bit PCM
        audio_data = bytearray()
        signed_bytes = struct.unpack(f"{len(audio)}b", audio)
        for b in signed_bytes:
            signed16 = b << 8
            audio_data += struct.pack("<h", signed16)
    else:
        # audio data here should already be signed 16-bit PCM
        audio_data = audio

    riff_chunk = bytearray(12)
    format_chunk = bytearray(24)
    data_chunk = bytearray(8)

    riff_chunk[:4] = b'RIFF'
    # overall length of the file, minus 8 bytes
    riff_chunk[4:8] = struct.pack("<I", len(riff_chunk) + len(format_chunk) + len(data_chunk) + len(audio_data) - 8)
    riff_chunk[8:] = b'WAVE'

    format_chunk[:4] = b'fmt '
    format_chunk[4:8] = struct.pack("<I", 16)   # chunk size, not including first 8 bytes -> 24 - 8 = 16
    format_chunk[8:10] = struct.pack("<H", 1)   # format tag, PCM = 1
    format_chunk[10:12] = struct.pack("<H", sample.channels)
    block_align = sample.channels * 2           # = channels * bps / 8,  bps is 16 no matter what
    format_chunk[12:16] = struct.pack("<I", sample.sample_rate)
    format_chunk[16:20] = struct.pack("<I", sample.sample_rate * block_align)
    format_chunk[20:22] = struct.pack("<H", block_align)
    format_chunk[22:] = struct.pack("<H", 16)   # bps

    data_chunk[:4] = b'data'
    data_chunk[4:] = struct.pack("<I", len(audio_data))
    wav_header = riff_chunk + format_chunk + data_chunk

    output_path = (OUTPUT_DIR / f"sample{sample_num}.wav").resolve()
    with open(output_path, "wb") as wav:
        wav.write(wav_header)
        wav.write(audio_data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sounddata", type=Path, help="path to SoundData.rom file")
    parser.add_argument("-s", "--sample", type=int, help="extract a specific sample by index number")
    args = parser.parse_args()

    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir()

    sounddata_path = args.sounddata.resolve()
    with open(sounddata_path, "rb") as sounddata:
        header = struct.unpack("<10I", sounddata.read(40))
        sample_bank = header[2]
        num_sample_ptrs = (header[3] - sample_bank) // 4
        audio_bank = header[4]
        num_audio_ptrs = (header[5] - audio_bank) // 4

        sounddata.seek(sample_bank)
        sample_ptrs = struct.unpack(f"<{num_sample_ptrs}I", sounddata.read(num_sample_ptrs * 4))
        sounddata.seek(audio_bank)
        audio_ptrs = struct.unpack(f"<{num_audio_ptrs}I", sounddata.read(num_audio_ptrs * 4))

        samples = get_sample_list(sounddata, sample_ptrs)
        audios = get_audio_list(sounddata, audio_ptrs)

        if args.sample is not None:
            if args.sample < 0 or args.sample >= len(samples):
                print(f"ERROR: Sample number ({args.sample}) is not a valid index. Valid indices: (0-{len(samples)-1})")
                sys.exit(1)

            samp = samples[args.sample]
            if samp.is_adpcm:
                audio = decode_adpcm(audios[samp.raw_index], samp.length)
            else:
                audio = audios[samp.raw_index]

            make_pcm16_wav(samp, audio, args.sample)
            output_path = OUTPUT_DIR / f"sample{args.sample}.wav"
            print(f"Finished export. File written to {output_path}")
        else:
            print("Exporting all samples. This might take a bit.")

            for i, samp in enumerate(samples):
                if samp.is_adpcm:
                    audio = decode_adpcm(audios[samp.raw_index], samp.length)
                else:
                    audio = audios[samp.raw_index]
                make_pcm16_wav(samp, audio, i)

            print(f"Finished export. {len(samples)} wav files written to {OUTPUT_DIR}")



if __name__ == "__main__":
    main()