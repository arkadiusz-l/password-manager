import tkinter as tk

root = tk.Tk()
root.title("Password Manager")
root.resizable(False, False)
root_width = 450
root_height = 355
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x_offset = int(screen_width / 2 - root_width / 2)
y_offset = int(screen_height / 2 - root_height / 2)
root.geometry(f"{root_width}x{root_height}+{x_offset}+{y_offset}")

root.mainloop()
