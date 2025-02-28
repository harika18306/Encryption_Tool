import os
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256

# AES encryption/decryption functions
def encrypt_file(file_path, password):
    key = sha256(password.encode('utf-8')).digest()  # Derive 32-byte key using SHA-256
    cipher = AES.new(key, AES.MODE_CBC)  # CBC mode
    output_file = file_path + ".enc"
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))  # Pad the data to the block size
        with open(output_file, 'wb') as f_enc:
            f_enc.write(cipher.iv)  # Write the IV at the start of the encrypted file
            f_enc.write(encrypted_data)
        
        messagebox.showinfo("Success", f"File encrypted successfully: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def decrypt_file(file_path, password):
    key = sha256(password.encode('utf-8')).digest()  # Derive 32-byte key using SHA-256
    try:
        with open(file_path, 'rb') as f:
            iv = f.read(16)  # Extract the 16-byte IV
            encrypted_data = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)  # CBC mode with the extracted IV
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)  # Unpad the decrypted data
        
        output_file = file_path.replace(".enc", ".dec")
        with open(output_file, 'wb') as f_dec:
            f_dec.write(decrypted_data)
        
        messagebox.showinfo("Success", f"File decrypted successfully: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# GUI Setup
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool")
        self.root.geometry("400x300")

        self.password_label = Label(root, text="Enter Password (32 characters for AES-256):")
        self.password_label.pack(pady=5)

        self.password_entry = Entry(root, show='*', width=32)
        self.password_entry.pack(pady=5)

        self.encrypt_button = Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)

        self.quit_button = Button(root, text="Quit", command=root.quit)
        self.quit_button.pack(pady=10)

    def encrypt_file(self):
        password = self.password_entry.get()
        if len(password) < 8:  # You can define a minimum length for the password
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return
        
        file_path = filedialog.askopenfilename(title="Select a File to Encrypt")
        if file_path:
            encrypt_file(file_path, password)

    def decrypt_file(self):
        password = self.password_entry.get()
        if len(password) < 8:  # You can define a minimum length for the password
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return
        
        file_path = filedialog.askopenfilename(title="Select a File to Decrypt")
        if file_path:
            decrypt_file(file_path, password)

# Main
if __name__ == "__main__":
    root = Tk()
    app = EncryptionApp(root)
    root.mainloop()
