from tkinter import *
import sqlite3
import hashlib 
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import codecs


backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 32,
    salt = salt,
    iterations = 100000,
    backend= backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


### Database setup
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
Website TEXT NOT NULL,
Username TEXT NOT NULL,
Password TEXT NOT NULL);
""")


### Creating popUp boxes for input data
def popUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer

### Intiating GUI window ###
window = Tk()
window.title("Password Vault")


### Hashing password
def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

#### First Screen ####
def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")
    lbl = Label(window, text = "Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt_input = Entry(window, width=20, show="*")
    txt_input.pack()
    txt_input.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.pack()

    txt_input1 = Entry(window, width=20, show="*")
    txt_input1.pack()

### Function to Save Password
    def savePassword():
        if txt_input.get() == txt_input1.get():
            query = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(query)

            hashedPassword = hashPassword(txt_input.get().encode('utf-8'))
            key = str(uuid.uuid4())  
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt_input.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?)"""
            cursor.execute(insert_password, [(hashedPassword), (recoveryKey)])
            db.commit()

            recoveryScreen(key)
        else:
            lbl2 = Label(window, text="Passwords do not match")
            lbl2.config(anchor=CENTER)
            lbl2.pack()

### Save Password Button
    btn = Button(window, text= "Save", command=savePassword)
    btn.pack()

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")
    lbl = Label(window, text = "Save This Key To Recover Account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

### Button to copy key to clipboard
    btn = Button(window, text= "Copy Key", command=copyKey)
    btn.pack(pady=5)

    def done():
        passwordVault()

    btn = Button(window, text= "Done", command=done)
    btn.pack(pady=5)

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")
    lbl = Label(window, text = "Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt_input = Entry(window, width=20)
    txt_input.pack()
    txt_input.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(txt_input.get().encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            firstScreen()
        else:
            txt_input.delete(0, 'end')
            lbl1.config(text="Wrong Key")

### Button to Check Recovery Key
    btn = Button(window, text= "Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)


#### Login Screen ####
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("500x250")
    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    
    txt_input = Entry(window, width=20, show="*")
    txt_input.pack()
    txt_input.focus()

    lbl1 = Label(window)
    lbl1.pack()

### Retrieving Master Password From Database
    def getMasterPAssword():
        checkHashedpassword = hashPassword(txt_input.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt_input.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedpassword)])
        return cursor.fetchall()

### Checking Master Password
    def checkPassword():
        match = getMasterPAssword()
        if match:
            passwordVault()
        else:
            txt_input.delete(0, "end")
            lbl1.config(text="Wrong Password")

    def resetPassword():
        resetScreen()

### Check Password Button    
    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=10)


#### Password Vault Screen ####
def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

### Adding Entry to Database
    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website,username,password)
                            VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        passwordVault()

### Deleting Entry from Database
    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordVault()

    window.geometry("700x550")

    def copyPass():
        pyperclip.copy(lbl1.cget("text"))

    lbl = Label(window, text="Password Vault")
    lbl.config(anchor=CENTER)    
    lbl.grid(column=1)

### Button to create new Password Entry
    btn = Button(window, text= " + ", command=addEntry)
    btn.grid(column=1, pady=10)

### Grid Structure of Password Vault
    lbl = Label(window, text="website")
    lbl.grid(row=2, column=0, padx=50)

    lbl = Label(window, text="username")
    lbl.grid(row=2, column=1, padx=50)

    lbl = Label(window, text="password")
    lbl.grid(row=2, column=2, padx=50)

### Retrieving Database values to Display
    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while(True):
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row= i+3)

            lbl1 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=1, row= i+3)

            pw = decrypt(array[i][3], encryptionKey)

            ret_pass = ["*" for i in pw]
            ret_pass = "".join(ret_pass)

            lbl1 = Label(window, text=ret_pass, font=("Helvetica", 12))
            lbl1.grid(column=2, row= i+3)

            def showPass(start, i):
                # if start == 0:
                lbl1 = Label(window, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
                lbl1.grid(column=2, row= i+3)
              
            btn = Button(window, text='Show', command=partial(showPass, 0, i))
            btn.grid(column=3, row=i+3, padx= 10, pady=10)

            def copyPass(pw):
                pyperclip.copy(pw)

            btn1 = Button(window, text="Copy Password", command= partial(copyPass, codecs.decode((decrypt(array[i][3], encryptionKey)))))
            btn1.grid(column=4, row=i+3, padx=10, pady=10)

            btn = Button(window, text="Delete", command= partial(removeEntry, array[i][0]))
            btn.grid(column=5, row=i+3, pady=10)

            i += 1
            
            cursor.execute("SELECT * FROM vault")
            if(len(cursor.fetchall()) <= i):
                break

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()


