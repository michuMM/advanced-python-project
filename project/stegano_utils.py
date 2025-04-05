from stegano import lsb

def hide_message(input_image_path, output_image_path, message):
    secret = lsb.hide(input_image_path, message)
    secret.save(output_image_path)

def reveal_message(image_path):
    return lsb.reveal(image_path)