import os
import json
import base64
import hashlib
import secrets
import ctypes
import ctypes.wintypes as wintypes
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

APP_DIR = os.path.join(os.environ["APPDATA"], "MyVault")
DATA_FILE = os.path.join(APP_DIR, "vault.dat")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")

os.makedirs(APP_DIR, exist_ok=True)


# ---------------- WINDOWS DPAPI ----------------

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte))
    ]


def protect(data: bytes) -> bytes:
    blob_in = DATA_BLOB(
        len(data),
        ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte))
    )
    blob_out = DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out)
    ):
        raise ctypes.WinError()

    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    kernel32.LocalFree(blob_out.pbData)
    return result


def unprotect(data: bytes) -> bytes:
    blob_in = DATA_BLOB(
        len(data),
        ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte))
    )
    blob_out = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out)
    ):
        raise ctypes.WinError()

    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    kernel32.LocalFree(blob_out.pbData)
    return result


# ---------------- MASTER PASSWORD ----------------

def make_password_hash(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )


def setup_master():
    password = simpledialog.askstring(
        "Create Vault",
        "Create your Master Password:",
        show="•"
    )

    if not password or len(password) < 8:
        messagebox.showwarning(
            "Master Password",
            "Use at least 8 characters."
        )
        return False

    confirm = simpledialog.askstring(
        "Create Vault",
        "Repeat your Master Password:",
        show="•"
    )

    if password != confirm:
        messagebox.showerror(
            "Error",
            "Passwords do not match."
        )
        return False

    salt = secrets.token_bytes(32)
    password_hash = make_password_hash(password, salt)

    config = {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(password_hash).decode()
    }

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f)

    save_vault({"categories": []})
    return True


def check_master():
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)

    salt = base64.b64decode(config["salt"])
    saved_hash = base64.b64decode(config["hash"])

    password = simpledialog.askstring(
        "Unlock Vault",
        "Master Password:",
        show="•"
    )

    if password is None:
        return False

    current_hash = make_password_hash(password, salt)

    if secrets.compare_digest(current_hash, saved_hash):
        return True

    messagebox.showerror(
        "Wrong Password",
        "Incorrect Master Password."
    )
    return False


# ---------------- VAULT ----------------

def save_vault(vault):
    raw = json.dumps(
        vault,
        ensure_ascii=False
    ).encode("utf-8")

    encrypted = protect(raw)

    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)


def load_vault():
    if not os.path.exists(DATA_FILE):
        return {"categories": []}

    with open(DATA_FILE, "rb") as f:
        encrypted = f.read()

    raw = unprotect(encrypted)
    return json.loads(raw.decode("utf-8"))


# ---------------- APP ----------------

class VaultApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("MyVault")
        self.geometry("1050x650")
        self.minsize(850, 520)
        self.configure(bg="#111318")

        self.vault = load_vault()
        self.current_category = None

        self.setup_style()
        self.build_ui()

    def setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "TFrame",
            background="#111318"
        )

        style.configure(
            "Panel.TFrame",
            background="#191c22"
        )

        style.configure(
            "TLabel",
            background="#111318",
            foreground="#e7e9ed",
            font=("Segoe UI", 10)
        )

        style.configure(
            "Title.TLabel",
            background="#111318",
            foreground="#ffffff",
            font=("Segoe UI", 23, "bold")
        )

        style.configure(
            "TButton",
            background="#292e38",
            foreground="#ffffff",
            borderwidth=0,
            padding=(12, 8)
        )

        style.map(
            "TButton",
            background=[("active", "#363c48")]
        )

        style.configure(
            "Accent.TButton",
            background="#5b5cf0",
            foreground="#ffffff"
        )

        style.map(
            "Accent.TButton",
            background=[("active", "#7071ff")]
        )

        style.configure(
            "Danger.TButton",
            background="#642c34",
            foreground="#ffffff"
        )

        style.configure(
            "TEntry",
            fieldbackground="#22262e",
            foreground="#ffffff",
            insertcolor="#ffffff",
            borderwidth=0,
            padding=9
        )

        style.configure(
            "Treeview",
            background="#191c22",
            fieldbackground="#191c22",
            foreground="#e7e9ed",
            rowheight=40,
            borderwidth=0
        )

        style.configure(
            "Treeview.Heading",
            background="#22262e",
            foreground="#aeb5c2",
            borderwidth=0
        )

        style.map(
            "Treeview",
            background=[("selected", "#383d61")]
        )

    def build_ui(self):

        top = ttk.Frame(self, padding=(22, 18))
        top.pack(fill="x")

        ttk.Label(
            top,
            text="MyVault",
            style="Title.TLabel"
        ).pack(side="left")

        ttk.Label(
            top,
            text="Local password manager"
        ).pack(side="left", padx=15, pady=(9, 0))

        ttk.Button(
            top,
            text="🔒 Lock",
            command=self.lock
        ).pack(side="right")

        body = ttk.Frame(self)
        body.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=(0, 18)
        )

        # SIDEBAR

        sidebar = ttk.Frame(
            body,
            style="Panel.TFrame",
            padding=14
        )

        sidebar.pack(
            side="left",
            fill="y"
        )

        sidebar.configure(width=230)
        sidebar.pack_propagate(False)

        label = tk.Label(
            sidebar,
            text="CATEGORIES",
            bg="#191c22",
            fg="#8d94a1",
            font=("Segoe UI", 9, "bold")
        )
        label.pack(anchor="w", pady=(4, 12))

        self.category_list = tk.Listbox(
            sidebar,
            bg="#191c22",
            fg="#e7e9ed",
            selectbackground="#383d61",
            selectforeground="#ffffff",
            borderwidth=0,
            highlightthickness=0,
            font=("Segoe UI", 10)
        )

        self.category_list.pack(
            fill="both",
            expand=True
        )

        self.category_list.bind(
            "<<ListboxSelect>>",
            self.category_selected
        )

        buttons = ttk.Frame(
            sidebar,
            style="Panel.TFrame"
        )

        buttons.pack(
            fill="x",
            pady=(12, 0)
        )

        ttk.Button(
            buttons,
            text="+ Category",
            command=self.add_category
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        ttk.Button(
            buttons,
            text="Delete",
            style="Danger.TButton",
            command=self.delete_category
        ).pack(
            side="left",
            fill="x",
            expand=True,
            padx=(7, 0)
        )

        # CONTENT

        content = ttk.Frame(body)
        content.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(18, 0)
        )

        header = ttk.Frame(content)
        header.pack(fill="x", pady=(0, 14))

        self.category_title = ttk.Label(
            header,
            text="Select category",
            font=("Segoe UI", 18, "bold")
        )

        self.category_title.pack(side="left")

        ttk.Button(
            header,
            text="+ Add platform",
            style="Accent.TButton",
            command=self.add_entry
        ).pack(side="right")

        columns = (
            "platform",
            "username",
            "password"
        )

        self.tree = ttk.Treeview(
            content,
            columns=columns,
            show="headings"
        )

        self.tree.heading(
            "platform",
            text="Platform"
        )

        self.tree.heading(
            "username",
            text="Username / Email"
        )

        self.tree.heading(
            "password",
            text="Password"
        )

        self.tree.column(
            "platform",
            width=220
        )

        self.tree.column(
            "username",
            width=280
        )

        self.tree.column(
            "password",
            width=220
        )

        self.tree.pack(
            fill="both",
            expand=True
        )

        self.tree.bind(
            "<Double-1>",
            lambda e: self.edit_entry()
        )

        bottom = ttk.Frame(content)
        bottom.pack(
            fill="x",
            pady=(12, 0)
        )

        ttk.Button(
            bottom,
            text="Edit",
            command=self.edit_entry
        ).pack(side="left")

        ttk.Button(
            bottom,
            text="Delete",
            style="Danger.TButton",
            command=self.delete_entry
        ).pack(
            side="left",
            padx=8
        )

        self.refresh_categories()

    # ---------- CATEGORIES ----------

    def refresh_categories(self):

        self.category_list.delete(
            0,
            tk.END
        )

        for category in self.vault["categories"]:
            self.category_list.insert(
                tk.END,
                category["name"]
            )

        if self.vault["categories"]:
            self.category_list.selection_set(0)
            self.category_selected()

    def category_selected(self, event=None):

        selection = self.category_list.curselection()

        if not selection:
            return

        self.current_category = self.vault[
            "categories"
        ][selection[0]]

        self.category_title.config(
            text=self.current_category["name"]
        )

        self.refresh_entries()

    def add_category(self):

        name = simpledialog.askstring(
            "New Category",
            "Category name:"
        )

        if not name:
            return

        name = name.strip()

        if any(
            c["name"].lower() == name.lower()
            for c in self.vault["categories"]
        ):
            messagebox.showwarning(
                "Category",
                "This category already exists."
            )
            return

        self.vault["categories"].append({
            "name": name,
            "entries": []
        })

        save_vault(self.vault)
        self.refresh_categories()

    def delete_category(self):

        if not self.current_category:
            return

        if not messagebox.askyesno(
            "Delete category",
            f'Delete "{self.current_category["name"]}" and all its entries?'
        ):
            return

        self.vault["categories"].remove(
            self.current_category
        )

        self.current_category = None

        save_vault(self.vault)
        self.refresh_categories()

    # ---------- ENTRIES ----------

    def refresh_entries(self):

        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.current_category:
            return

        for i, entry in enumerate(
            self.current_category["entries"]
        ):

            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    entry["platform"],
                    entry["username"],
                    "••••••••"
                )
            )

    def selected_index(self):

        selection = self.tree.selection()

        if not selection:
            return None

        return int(selection[0])

    def add_entry(self):

        if not self.current_category:
            messagebox.showinfo(
                "Category",
                "Create or select a category first."
            )
            return

        self.entry_window()

    def edit_entry(self):

        index = self.selected_index()

        if index is None:
            return

        entry = self.current_category[
            "entries"
        ][index]

        self.entry_window(
            entry,
            index
        )

    def entry_window(
        self,
        entry=None,
        index=None
    ):

        win = tk.Toplevel(self)

        win.title(
            "Edit platform"
            if entry
            else
            "Add platform"
        )

        win.geometry("480x430")
        win.configure(bg="#191c22")

        win.transient(self)
        win.grab_set()

        frame = ttk.Frame(
            win,
            style="Panel.TFrame",
            padding=28
        )

        frame.pack(
            fill="both",
            expand=True
        )

        ttk.Label(
            frame,
            text="Platform details",
            font=("Segoe UI", 18, "bold"),
            background="#191c22"
        ).pack(
            anchor="w",
            pady=(0, 22)
        )

        # PLATFORM

        ttk.Label(
            frame,
            text="Platform",
            background="#191c22"
        ).pack(anchor="w")

        platform = ttk.Entry(frame)
        platform.pack(
            fill="x",
            pady=(5, 14)
        )

        # USERNAME

        ttk.Label(
            frame,
            text="Username / Email",
            background="#191c22"
        ).pack(anchor="w")

        username = ttk.Entry(frame)
        username.pack(
            fill="x",
            pady=(5, 14)
        )

        # PASSWORD

        ttk.Label(
            frame,
            text="Password",
            background="#191c22"
        ).pack(anchor="w")

        password_frame = ttk.Frame(
            frame,
            style="Panel.TFrame"
        )

        password_frame.pack(
            fill="x",
            pady=(5, 14)
        )

        password = ttk.Entry(
            password_frame,
            show="•"
        )

        password.pack(
            side="left",
            fill="x",
            expand=True
        )

        visible = False

        def toggle_password():

            nonlocal visible

            visible = not visible

            password.config(
                show="" if visible else "•"
            )

            eye.config(
                text="🙈" if visible else "👁"
            )

        eye = ttk.Button(
            password_frame,
            text="👁",
            width=4,
            command=toggle_password
        )

        eye.pack(
            side="left",
            padx=(7, 0)
        )

        def copy_password():

            self.clipboard_clear()
            self.clipboard_append(
                password.get()
            )

            messagebox.showinfo(
                "Copied",
                "Password copied to clipboard.",
                parent=win
            )

        ttk.Button(
            password_frame,
            text="📋",
            width=4,
            command=copy_password
        ).pack(
            side="left",
            padx=(7, 0)
        )

        if entry:

            platform.insert(
                0,
                entry["platform"]
            )

            username.insert(
                0,
                entry["username"]
            )

            password.insert(
                0,
                entry["password"]
            )

        buttons = ttk.Frame(
            frame,
            style="Panel.TFrame"
        )

        buttons.pack(
            fill="x",
            pady=(10, 0)
        )

        def save():

            p = platform.get().strip()
            u = username.get().strip()
            pw = password.get()

            if not p or not u or not pw:
                messagebox.showwarning(
                    "Missing data",
                    "Fill in all fields.",
                    parent=win
                )
                return

            new_entry = {
                "platform": p,
                "username": u,
                "password": pw
            }

            if index is None:
                self.current_category[
                    "entries"
                ].append(new_entry)
            else:
                self.current_category[
                    "entries"
                ][index] = new_entry

            save_vault(self.vault)
            self.refresh_entries()

            win.destroy()

        ttk.Button(
            buttons,
            text="Cancel",
            command=win.destroy
        ).pack(side="right")

        ttk.Button(
            buttons,
            text="Save",
            style="Accent.TButton",
            command=save
        ).pack(
            side="right",
            padx=(0, 8)
        )

        platform.focus()

    def delete_entry(self):

        index = self.selected_index()

        if index is None:
            return

        entry = self.current_category[
            "entries"
        ][index]

        if not messagebox.askyesno(
            "Delete",
            f'Delete "{entry["platform"]}"?'
        ):
            return

        self.current_category[
            "entries"
        ].pop(index)

        save_vault(self.vault)
        self.refresh_entries()

    def lock(self):

        self.destroy()


# ---------------- START ----------------

def main():

    root = tk.Tk()
    root.withdraw()

    if not os.path.exists(CONFIG_FILE):

        if not setup_master():
            root.destroy()
            return

    else:

        if not check_master():
            root.destroy()
            return

    root.destroy()

    app = VaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
