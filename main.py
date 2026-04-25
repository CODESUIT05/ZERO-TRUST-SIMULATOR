import tkinter as tk 
from dashboard import ZTDashboard

def main():
    root=tk.Tk()
    app=ZTDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()
    