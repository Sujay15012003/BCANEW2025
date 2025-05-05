from tkinter import *
import time

root = Tk()
root.geometry("1200x600")
root.title("Message Encryption and Decryption")

Tops = Frame(root, width=1600, relief=SUNKEN)
Tops.pack(side=TOP)

f1 = Frame(root, width=800, height=700, relief=SUNKEN)
f1.pack(side=LEFT)

# Display Time
localtime = time.asctime(time.localtime(time.time()))

lblTitle = Label(Tops, font=('helvetica', 50, 'bold'),
                 text="SECRET MESSAGING \nClassic Vigenère Cipher",
                 fg="Black", bd=10, anchor='w')
lblTitle.grid(row=0, column=0)

lblTime = Label(Tops, font=('arial', 20, 'bold'),
                text=localtime, fg="Steel Blue",
                bd=10, anchor='w')
lblTime.grid(row=1, column=0)

# Variables
rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()

# Functions
def qExit():
    root.destroy()

def Reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")

# Classic Vigenère Cipher Functions
def vigenere_encrypt(plaintext, key):
    plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
    key = key.upper()
    cipher = ''

    for i in range(len(plaintext)):
        shift = (ord(plaintext[i]) - ord('A') + ord(key[i % len(key)]) - ord('A')) % 26
        cipher += chr(shift + ord('A'))

    return cipher

def vigenere_decrypt(ciphertext, key):
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
    key = key.upper()
    plain = ''

    for i in range(len(ciphertext)):
        shift = (ord(ciphertext[i]) - ord(key[i % len(key)]) + 26) % 26
        plain += chr(shift + ord('A'))

    return plain

def Ref():
    clear = Msg.get()
    k = key.get()
    m = mode.get().lower()

    if not clear or not k:
        Result.set("Input Error")
        return

    if m == 'e':
        Result.set(vigenere_encrypt(clear, k))
    elif m == 'd':
        Result.set(vigenere_decrypt(clear, k))
    else:
        Result.set("Invalid mode")

# GUI Layout
Label(f1, font=('arial', 16, 'bold'), text="Name:", bd=16, anchor="w").grid(row=0, column=0)
Entry(f1, font=('arial', 16, 'bold'), textvariable=rand, bd=10, insertwidth=4,
      bg="powder blue", justify='right').grid(row=0, column=1)

Label(f1, font=('arial', 16, 'bold'), text="MESSAGE", bd=16, anchor="w").grid(row=1, column=0)
Entry(f1, font=('arial', 16, 'bold'), textvariable=Msg, bd=10, insertwidth=4,
      bg="powder blue", justify='right').grid(row=1, column=1)

Label(f1, font=('arial', 16, 'bold'), text="KEY", bd=16, anchor="w").grid(row=2, column=0)
Entry(f1, font=('arial', 16, 'bold'), textvariable=key, bd=10, insertwidth=4,
      bg="powder blue", justify='right').grid(row=2, column=1)

Label(f1, font=('arial', 16, 'bold'),
      text="MODE (e for encrypt, d for decrypt)", bd=16, anchor="w").grid(row=3, column=0)
Entry(f1, font=('arial', 16, 'bold'), textvariable=mode, bd=10, insertwidth=4,
      bg="powder blue", justify='right').grid(row=3, column=1)

Label(f1, font=('arial', 16, 'bold'), text="The Result-", bd=16, anchor="w").grid(row=2, column=2)
Entry(f1, font=('arial', 16, 'bold'), textvariable=Result, bd=10, insertwidth=4,
      bg="powder blue", justify='right').grid(row=2, column=3)

# Buttons
Button(f1, padx=16, pady=8, bd=16, fg="black", font=('arial', 16, 'bold'),
       width=10, text="Show Message", bg="powder blue", command=Ref).grid(row=7, column=1)

Button(f1, padx=16, pady=8, bd=16, fg="black", font=('arial', 16, 'bold'),
       width=10, text="Reset", bg="green", command=Reset).grid(row=7, column=2)

Button(f1, padx=16, pady=8, bd=16, fg="black", font=('arial', 16, 'bold'),
       width=10, text="Exit", bg="red", command=qExit).grid(row=7, column=3)

root.mainloop()
