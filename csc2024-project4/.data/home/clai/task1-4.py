from PIL import Image
import pytesseract
import subprocess

image   = "source/doll/Matryoshka\ dolls.jpg"
command = "xxd " + image + " | grep \"PNG\""

result = subprocess.run(command, shell=True, capture_output=True, text=True)
offset = int(result.stdout[0:8], 16)

command = "dd if=\"source/doll/Matryoshka dolls.jpg\" of=\"task1-4_flag.png\" bs=1 skip=" + str(offset)
result = subprocess.run(command, shell=True, capture_output=True, text=True)

image = Image.open("task1-4_flag.png")
flag  = pytesseract.image_to_string(image)
print(flag)