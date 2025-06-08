from stegano import lsb
import wave

def hide_message(input_image_path, output_image_path, message):
    secret = lsb.hide(input_image_path, message)
    secret.save(output_image_path)

def reveal_message(image_path):
    return lsb.reveal(image_path)

def encode_lsb(audio_path, message, output_path):
    with wave.open(audio_path, 'rb') as song:
        frames = bytearray(list(song.readframes(song.getnframes())))

        message += '###'  # znacznik końca wiadomości
        bits = ''.join([format(ord(c), '08b') for c in message])

        if len(bits) > len(frames):
            raise ValueError("Wiadomość za długa dla tego pliku audio!")

        for i, bit in enumerate(bits):
            frames[i] = (frames[i] & 254) | int(bit)

        with wave.open(output_path, 'wb') as modified:
            modified.setparams(song.getparams())
            modified.writeframes(bytes(frames))

def decode_lsb(audio_path):
    with wave.open(audio_path, 'rb') as song:
        frames = bytearray(list(song.readframes(song.getnframes())))

        bits = [str(frames[i] & 1) for i in range(len(frames))]
        chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]

        message = ''.join(chars)
        return message.split('###')[0]  # ucinamy po znaczniku końca