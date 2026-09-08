import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import json, os, re, base64, secrets, string, math, shutil
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ══════════════════════════════════════════════════════════════
#  by: Nean
# ══════════════════════════════════════════════════════════════
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DATA_FILE = os.path.join(os.path.expanduser("~"), ".gmailv4_data.enc")
SALT_FILE = os.path.join(os.path.expanduser("~"), ".gmailv4.salt")
BAK_FILE  = DATA_FILE + ".bak"
AUTO_LOCK_MS = 5 * 60 * 1000  # 5 دقائق

C = {
    "bg":      "#080B14",
    "panel":   "#0E1220",
    "card":    "#141828",
    "card2":   "#1A2035",
    "border":  "#252D45",
    "border2": "#2D3855",
    "accent":  "#4F8BFF",
    "green":   "#22D3A4",
    "orange":  "#F5A623",
    "red":     "#FF4D6A",
    "purple":  "#B78FFF",
    "cyan":    "#00D4FF",
    "yellow":  "#FFD700",
    "t1":      "#E8F0FF",
    "t2":      "#7A8DB5",
    "t3":      "#3A4560",
    # badge backgrounds
    "acc_bg":  "#0A1535",
    "grn_bg":  "#0A2520",
    "red_bg":  "#2A0A15",
    "org_bg":  "#2A1A05",
    "pur_bg":  "#15082A",
    "cyn_bg":  "#002535",
}

F = {
    "title":  ("Segoe UI", 20, "bold"),
    "head":   ("Segoe UI", 15, "bold"),
    "sub":    ("Segoe UI", 13, "bold"),
    "body":   ("Segoe UI", 13),
    "small":  ("Segoe UI", 11),
    "tiny":   ("Segoe UI", 10),
    "mono":   ("Consolas", 13),
    "monol":  ("Consolas", 15),
    "monom":  ("Consolas", 12),
}

TAGS_PRESET = ["شخصي", "عمل", "مصرفي", "تسوق", "ترفيه", "تعليم", "أخرى"]

# ══════════════════════════════════════════════════════════════
#  CRYPTO + BACKUP
# ══════════════════════════════════════════════════════════════
def _get_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f: return f.read()
    s = os.urandom(32)
    with open(SALT_FILE, "wb") as f: f.write(s)
    return s

def _make_key(pw: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=_get_salt(), iterations=480_000)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def vault_load(pw: str):
    if not os.path.exists(DATA_FILE): return {}
    try:
        with open(DATA_FILE, "rb") as f: raw = f.read()
        return json.loads(Fernet(_make_key(pw)).decrypt(raw).decode())
    except Exception: return None

def vault_save(data: dict, pw: str):
    enc = Fernet(_make_key(pw)).encrypt(
        json.dumps(data, ensure_ascii=False).encode())
    # نسخة احتياطية تلقائية
    if os.path.exists(DATA_FILE):
        shutil.copy2(DATA_FILE, BAK_FILE)
    with open(DATA_FILE, "wb") as f: f.write(enc)

def vault_export(data: dict, pw: str, path: str):
    """تصدير مشفر بنفس المفتاح"""
    enc = Fernet(_make_key(pw)).encrypt(
        json.dumps(data, ensure_ascii=False, indent=2).encode())
    with open(path, "wb") as f: f.write(enc)

def vault_import(pw: str, path: str):
    """استيراد ملف مُصدَّر"""
    try:
        with open(path, "rb") as f: raw = f.read()
        return json.loads(Fernet(_make_key(pw)).decrypt(raw).decode())
    except Exception: return None

# ══════════════════════════════════════════════════════════════
#  PASSWORD ENGINE
# ══════════════════════════════════════════════════════════════
def gen_pw(length=28, upper=True, lower=True, digits=True,
           symbols=True, no_ambig=False):
    AMB = set("0O1lI|`'\"")
    U = ''.join(c for c in string.ascii_uppercase if not (no_ambig and c in AMB))
    L = ''.join(c for c in string.ascii_lowercase if not (no_ambig and c in AMB))
    D = ''.join(c for c in string.digits          if not (no_ambig and c in AMB))
    S = ''.join(c for c in "!@#$%^&*()_+-=[]{}:;,.<>?" if not (no_ambig and c in AMB))
    pool, required = "", []
    if upper   and U: pool += U; required.append(secrets.choice(U))
    if lower   and L: pool += L; required.append(secrets.choice(L))
    if digits  and D: pool += D; required.append(secrets.choice(D))
    if symbols and S: pool += S; required.append(secrets.choice(S))
    if not pool: pool = string.ascii_letters + string.digits
    need = max(0, length - len(required))
    chars = required + [secrets.choice(pool) for _ in range(need)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

def pw_strength(pw: str):
    if not pw: return 0, "—", C["t3"]
    s = min(len(pw) * 2, 30)
    if re.search(r"[A-Z]", pw): s += 15
    if re.search(r"[a-z]", pw): s += 15
    if re.search(r"\d",    pw): s += 15
    if re.search(r"[^A-Za-z0-9]", pw): s += 20
    if len(pw) >= 20: s += 5
    s = min(s, 100)
    if s < 35: return s, "ضعيفة",      C["red"]
    if s < 60: return s, "متوسطة",     C["orange"]
    if s < 80: return s, "جيدة",       C["green"]
    return s,         "قوية جداً ✦",   C["accent"]

def pw_entropy(pw, pool_size):
    if pool_size <= 1 or not pw: return 0
    return int(len(pw) * math.log2(pool_size))

def strength_bg(col):
    return {C["red"]: C["red_bg"], C["orange"]: C["org_bg"],
            C["green"]: C["grn_bg"], C["accent"]: C["acc_bg"]}.get(col, C["card2"])

def pw_analysis(pw: str) -> dict:
    """تحليل مفصّل لكلمة المرور"""
    has_upper   = bool(re.search(r"[A-Z]", pw))
    has_lower   = bool(re.search(r"[a-z]", pw))
    has_digit   = bool(re.search(r"\d", pw))
    has_sym     = bool(re.search(r"[^A-Za-z0-9]", pw))
    pool = (26 if has_upper else 0) + (26 if has_lower else 0) + \
           (10 if has_digit else 0) + (32 if has_sym else 0)
    bits = pw_entropy(pw, pool or 62)
    sc, sl, col = pw_strength(pw)
    issues = []
    if len(pw) < 12:   issues.append("قصيرة جداً (أقل من 12 حرفاً)")
    if not has_upper:  issues.append("لا تحتوي على أحرف كبيرة")
    if not has_lower:  issues.append("لا تحتوي على أحرف صغيرة")
    if not has_digit:  issues.append("لا تحتوي على أرقام")
    if not has_sym:    issues.append("لا تحتوي على رموز خاصة")
    return {"score": sc, "label": sl, "color": col, "bits": bits,
            "length": len(pw), "pool": pool, "issues": issues,
            "has_upper": has_upper, "has_lower": has_lower,
            "has_digit": has_digit, "has_sym": has_sym}

def is_old(date_str: str, days=90) -> bool:
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        return (datetime.now() - d) > timedelta(days=days)
    except Exception: return False

# ══════════════════════════════════════════════════════════════
#  CLIPBOARD
# ══════════════════════════════════════════════════════════════
def clip_copy(widget, text: str):
    root = widget
    while root.master:
        root = root.master
    root.clipboard_clear()
    root.clipboard_append(str(text))

# ══════════════════════════════════════════════════════════════
#  CONTEXT MENU
# ══════════════════════════════════════════════════════════════
def _get_tk_entry(ctk_entry):
    if hasattr(ctk_entry, "_entry"):
        return ctk_entry._entry
    for child in ctk_entry.winfo_children():
        if isinstance(child, tk.Entry):
            return child
    return None

def attach_menu(ctk_entry):
    inner = _get_tk_entry(ctk_entry)
    if inner is None: return
    menu = tk.Menu(inner, tearoff=0,
                   bg=C["card2"], fg=C["t1"],
                   activebackground=C["accent"], activeforeground="#FFFFFF",
                   relief="flat", bd=1)
    menu.add_command(label="✂  قص",      command=lambda: inner.event_generate("<<Cut>>"))
    menu.add_command(label="⎘  نسخ",     command=lambda: inner.event_generate("<<Copy>>"))
    menu.add_command(label="📋  لصق",    command=lambda: inner.event_generate("<<Paste>>"))
    menu.add_separator()
    menu.add_command(label="تحديد الكل", command=lambda: (inner.select_range(0,"end"), inner.icursor("end")))
    menu.add_command(label="نسخ الكل",   command=lambda: clip_copy(inner, inner.get()))
    def show(e):
        try: menu.tk_popup(e.x_root, e.y_root)
        finally: menu.grab_release()
    inner.bind("<Button-3>", show)
    inner.bind("<Button-2>", show)

# ══════════════════════════════════════════════════════════════
#  TOAST
# ══════════════════════════════════════════════════════════════
class Toast:
    def __init__(self, root):
        self.root = root
        self._w = None

    def show(self, msg: str, color: str = None, ms: int = 2500):
        color = color or C["green"]
        if self._w:
            try: self._w.destroy()
            except: pass
        w = tk.Toplevel(self.root)
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.configure(bg=color)
        tk.Frame(w, bg=color, padx=2, pady=2).pack(fill="both", expand=True)
        inner = tk.Frame(w, bg=C["card2"], padx=22, pady=12)
        inner.place(x=2, y=2)
        tk.Label(inner, text=msg, font=F["body"], bg=C["card2"], fg=color).pack()
        self._w = w
        w.after(10, lambda: self._pos(w))
        w.after(ms, self._close)

    def _pos(self, w):
        try:
            rx, ry = self.root.winfo_x(), self.root.winfo_y()
            rw, rh = self.root.winfo_width(), self.root.winfo_height()
            w.update_idletasks()
            tw, th = w.winfo_reqwidth(), w.winfo_reqheight()
            w.geometry(f"{tw}x{th}+{rx+(rw-tw)//2}+{ry+rh-th-50}")
        except: pass

    def _close(self):
        try:
            if self._w: self._w.destroy()
        except: pass
        self._w = None

# ══════════════════════════════════════════════════════════════
#  REUSABLE WIDGETS
# ══════════════════════════════════════════════════════════════
def mk_entry(parent, placeholder="", mono=False, show="", **kw):
    e = ctk.CTkEntry(parent,
                     placeholder_text=placeholder,
                     font=F["mono"] if mono else F["body"],
                     fg_color=C["bg"], border_color=C["border"],
                     text_color=C["t1"], corner_radius=8, height=42,
                     show=show, **kw)
    attach_menu(e)
    return e

class StrBar(ctk.CTkFrame):
    def __init__(self, parent, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self.columnconfigure(0, weight=1)
        self._bar = ctk.CTkProgressBar(self, height=5, corner_radius=3,
                                        fg_color=C["border"], progress_color=C["green"])
        self._bar.set(0)
        self._bar.grid(row=0, column=0, sticky="ew")
        self._lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 11, "bold"),
                                  text_color=C["green"], width=90, anchor="e")
        self._lbl.grid(row=0, column=1, padx=(8, 0))

    def update(self, pw: str = ""):
        sc, sl, col = pw_strength(pw)
        self._bar.set(sc / 100)
        self._bar.configure(progress_color=col)
        self._lbl.configure(text=sl, text_color=col)

# ══════════════════════════════════════════════════════════════
#  BUTTON CLASSES
# ══════════════════════════════════════════════════════════════
class PrimaryBtn(ctk.CTkButton):
    def __init__(self, m, **kw):
        kw.setdefault("fg_color",     C["accent"])
        kw.setdefault("hover_color",  "#3A75F5")
        kw.setdefault("corner_radius", 8)
        kw.setdefault("font",         ("Segoe UI", 13, "bold"))
        kw.setdefault("height",       40)
        super().__init__(m, **kw)

class GhostBtn(ctk.CTkButton):
    def __init__(self, m, **kw):
        kw.setdefault("fg_color",     "transparent")
        kw.setdefault("hover_color",  C["card2"])
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", C["border"])
        kw.setdefault("text_color",   C["t2"])
        kw.setdefault("corner_radius", 8)
        kw.setdefault("font",         F["body"])
        kw.setdefault("height",       38)
        super().__init__(m, **kw)

class GreenBtn(ctk.CTkButton):
    def __init__(self, m, **kw):
        kw.setdefault("fg_color",     "#0A2520")
        kw.setdefault("hover_color",  "#0F3530")
        kw.setdefault("text_color",   C["green"])
        kw.setdefault("corner_radius", 8)
        kw.setdefault("font",         ("Segoe UI", 13, "bold"))
        kw.setdefault("height",       40)
        super().__init__(m, **kw)

class DangerBtn(ctk.CTkButton):
    def __init__(self, m, **kw):
        kw.setdefault("fg_color",     "#2A0A15")
        kw.setdefault("hover_color",  "#4A1525")
        kw.setdefault("text_color",   C["red"])
        kw.setdefault("corner_radius", 8)
        kw.setdefault("font",         ("Segoe UI", 13, "bold"))
        kw.setdefault("height",       40)
        super().__init__(m, **kw)

class OrangeBtn(ctk.CTkButton):
    def __init__(self, m, **kw):
        kw.setdefault("fg_color",     "#2A1A05")
        kw.setdefault("hover_color",  "#3A2A10")
        kw.setdefault("text_color",   C["orange"])
        kw.setdefault("corner_radius", 8)
        kw.setdefault("font",         ("Segoe UI", 13, "bold"))
        kw.setdefault("height",       40)
        super().__init__(m, **kw)

class Card(ctk.CTkFrame):
    def __init__(self, m, **kw):
        kw.setdefault("fg_color",      C["card"])
        kw.setdefault("corner_radius", 14)
        kw.setdefault("border_width",  1)
        kw.setdefault("border_color",  C["border"])
        super().__init__(m, **kw)

# ══════════════════════════════════════════════════════════════
#  LOCK SCREEN
# ══════════════════════════════════════════════════════════════
class LockScreen(ctk.CTkFrame):
    def __init__(self, master, on_unlock):
        super().__init__(master, fg_color=C["bg"])
        self.on_unlock = on_unlock
        self.is_new = not os.path.exists(DATA_FILE)
        self._build()

    def _build(self):
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        box = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=20,
                           border_width=1, border_color=C["border2"], width=460)
        box.grid(row=0, column=0)
        box.columnconfigure(0, weight=1)

        ic = ctk.CTkFrame(box, fg_color=C["card"], corner_radius=20,
                          width=80, height=80)
        ic.grid(row=0, pady=(48, 12))
        ic.grid_propagate(False)
        ic.rowconfigure(0, weight=1); ic.columnconfigure(0, weight=1)
        ctk.CTkLabel(ic, text="🔐", font=("Segoe UI", 38)).grid()

        ctk.CTkLabel(box, text="MKL_z7z_Gmail",
                     font=("Segoe UI", 30, "bold"), text_color=C["t1"]).grid(row=1)
        ctk.CTkLabel(box, text="مدير كلمات المرور الآمن والمشفر",
                     font=F["body"], text_color=C["t2"]).grid(row=2, pady=(6, 6))
        ctk.CTkLabel(box, text="AES-256 · PBKDF2 · 480,000 iterations",
                     font=F["tiny"], text_color=C["t3"]).grid(row=3, pady=(0, 22))

        hint = "✦  إنشاء خزنة جديدة" if self.is_new else "أدخل كلمة المرور الرئيسية"
        ctk.CTkLabel(box, text=hint, font=F["small"],
                     text_color=C["accent"] if self.is_new else C["t2"]).grid(row=4, pady=(0, 8))

        self._pw = ctk.CTkEntry(box, width=340, height=48, show="●",
                                placeholder_text="●●●●●●●●●●●●",
                                font=F["body"], corner_radius=10,
                                fg_color=C["card"], border_color=C["border"],
                                text_color=C["t1"])
        self._pw.grid(row=5, padx=56, pady=4)
        self._pw.bind("<Return>", lambda _: self._try_unlock())
        attach_menu(self._pw)

        self._pw2 = None
        if self.is_new:
            self._pw2 = ctk.CTkEntry(box, width=340, height=48, show="●",
                                     placeholder_text="تأكيد كلمة المرور",
                                     font=F["body"], corner_radius=10,
                                     fg_color=C["card"], border_color=C["border"],
                                     text_color=C["t1"])
            self._pw2.grid(row=6, padx=56, pady=4)
            self._pw2.bind("<Return>", lambda _: self._try_unlock())
            attach_menu(self._pw2)

        self._err = ctk.CTkLabel(box, text="", font=F["small"], text_color=C["red"])
        self._err.grid(row=7, pady=(4, 2))

        btn_txt = "✦  إنشاء الخزنة" if self.is_new else "▶  دخول"
        PrimaryBtn(box, text=btn_txt, command=self._try_unlock,
                   width=340, height=48).grid(row=8, padx=56, pady=(4, 6))

        if not self.is_new:
            GhostBtn(box, text="♻  استعادة النسخة الاحتياطية",
                     command=self._restore_bak, width=260, height=36).grid(row=9, pady=(0, 30))
        else:
            ctk.CTkLabel(box, text="", font=F["tiny"]).grid(row=9, pady=(0, 30))

        self._pw.focus()

    def _err_msg(self, msg):
        self._err.configure(text=f"⚠  {msg}")

    def _try_unlock(self):
        pw = self._pw.get().strip()
        if not pw:
            self._err_msg("أدخل كلمة المرور"); return
        if self.is_new:
            if len(pw) < 6:
                self._err_msg("6 أحرف على الأقل"); return
            if self._pw2 and self._pw2.get() != pw:
                self._err_msg("كلمتا المرور غير متطابقتين"); return
            vault_save({}, pw)
            self.on_unlock(pw, {})
        else:
            data = vault_load(pw)
            if data is None:
                self._err_msg("كلمة المرور خاطئة")
                self._pw.delete(0, "end"); self._pw.focus(); return
            self.on_unlock(pw, data)

    def _restore_bak(self):
        if not os.path.exists(BAK_FILE):
            self._err_msg("لا توجد نسخة احتياطية"); return
        pw = self._pw.get().strip()
        if not pw:
            self._err_msg("أدخل كلمة المرور أولاً"); return
        try:
            with open(BAK_FILE, "rb") as f: raw = f.read()
            data = json.loads(Fernet(_make_key(pw)).decrypt(raw).decode())
            shutil.copy2(BAK_FILE, DATA_FILE)
            self.on_unlock(pw, data)
        except Exception:
            self._err_msg("فشل استعادة النسخة الاحتياطية")

# ══════════════════════════════════════════════════════════════
#  SECURITY DASHBOARD PAGE  (جديد كلياً)
# ══════════════════════════════════════════════════════════════
class SecurityPage(ctk.CTkFrame):
    def __init__(self, parent, vault: dict, on_fix):
        super().__init__(parent, fg_color="transparent")
        self.vault = vault
        self.on_fix = on_fix
        self._build()

    def _build(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=26, pady=22)
        scroll.columnconfigure(0, weight=1)

        # ── Header ──
        ctk.CTkLabel(scroll, text="🛡  لوحة الأمان",
                     font=F["title"], text_color=C["t1"]).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(scroll, text="تحليل شامل لأمان خزنتك",
                     font=F["small"], text_color=C["t2"]).pack(anchor="w", pady=(0, 18))

        accs = list(self.vault.values())
        total  = len(accs)
        strong = sum(1 for a in accs if pw_strength(a.get("password",""))[0] >= 80)
        medium = sum(1 for a in accs if 55 <= pw_strength(a.get("password",""))[0] < 80)
        weak   = sum(1 for a in accs if pw_strength(a.get("password",""))[0] < 55)
        old    = sum(1 for a in accs if is_old(a.get("date", "")))

        # كشف التكرار
        pws = [a.get("password","") for a in accs if a.get("password","")]
        pw_counts = {}
        for p in pws: pw_counts[p] = pw_counts.get(p, 0) + 1
        reused = sum(1 for p, c in pw_counts.items() if c > 1)

        # درجة الأمان
        if total > 0:
            base = (strong * 3 + medium * 1) / (total * 3) * 100
            penalty = reused * 5 + old * 2
            score = max(0, min(100, int(base - penalty)))
        else:
            score = 0

        score_col = C["green"] if score >= 75 else C["orange"] if score >= 50 else C["red"]

        # ── Score Card ──
        sc = Card(scroll)
        sc.pack(fill="x", pady=(0, 12))
        sc_inner = ctk.CTkFrame(sc, fg_color="transparent")
        sc_inner.pack(fill="x", padx=22, pady=18)
        sc_inner.columnconfigure(1, weight=1)

        # الدرجة الدائرية (Canvas)
        cv = tk.Canvas(sc_inner, width=90, height=90,
                       bg=C["card"], bd=0, highlightthickness=0)
        cv.grid(row=0, column=0, rowspan=3, padx=(0, 20))
        arc_angle = int(score * 3.6)
        cv.create_oval(8, 8, 82, 82, outline=C["border2"], width=8)
        if arc_angle > 0:
            cv.create_arc(8, 8, 82, 82, start=90, extent=-arc_angle,
                          outline=score_col, width=8, style="arc")
        cv.create_text(45, 40, text=str(score), fill=score_col,
                       font=("Consolas", 20, "bold"))
        cv.create_text(45, 62, text="/ 100", fill=C["t3"],
                       font=("Segoe UI", 9))

        ctk.CTkLabel(sc_inner, text="درجة الأمان الإجمالية",
                     font=F["sub"], text_color=C["t1"]).grid(row=0, column=1, sticky="w")
        msg = ("خزنتك محمية جيداً — استمر!" if score >= 75
               else "هناك مجال للتحسين — عزّز كلماتك الضعيفة."
               if score >= 50 else
               "⚠  تحتاج خزنتك تحديثات عاجلة!")
        ctk.CTkLabel(sc_inner, text=msg, font=F["small"],
                     text_color=C["t2"], wraplength=350, anchor="w").grid(row=1, column=1, sticky="w")

        # ── Stats Grid ──
        gf = ctk.CTkFrame(scroll, fg_color="transparent")
        gf.pack(fill="x", pady=(0, 12))
        for i in range(3): gf.columnconfigure(i, weight=1)

        stats = [
            ("📋", "إجمالي", total,  C["accent"], C["acc_bg"]),
            ("🛡", "قوية",   strong, C["green"],  C["grn_bg"]),
            ("⚡", "متوسطة", medium, C["orange"], C["org_bg"]),
            ("⚠", "ضعيفة",  weak,   C["red"],    C["red_bg"]),
            ("🔄", "مكررة",  reused, C["purple"], C["pur_bg"]),
            ("📅", "قديمة",  old,    C["cyan"],   C["cyn_bg"]),
        ]
        for i, (icon, lbl, val, col, bg) in enumerate(stats):
            fr = ctk.CTkFrame(gf, fg_color=bg, corner_radius=12,
                              border_width=1, border_color=C["border"])
            fr.grid(row=i//3, column=i%3, padx=4, pady=4, sticky="nsew")
            ctk.CTkLabel(fr, text=icon, font=("Segoe UI", 22)).pack(pady=(14,0))
            ctk.CTkLabel(fr, text=str(val),
                         font=("Consolas", 22, "bold"), text_color=col).pack()
            ctk.CTkLabel(fr, text=lbl, font=F["tiny"],
                         text_color=C["t3"]).pack(pady=(0, 14))

        # ── توزيع شريط ──
        if total > 0:
            dc = Card(scroll)
            dc.pack(fill="x", pady=(0, 12))
            ctk.CTkLabel(dc, text="توزيع قوة كلمات المرور",
                         font=F["sub"], text_color=C["t2"]).pack(anchor="w", padx=20, pady=(14, 6))
            bar_fr = ctk.CTkFrame(dc, fg_color="transparent")
            bar_fr.pack(fill="x", padx=20, pady=(0, 6))
            bar_fr.columnconfigure(0, weight=strong)
            bar_fr.columnconfigure(1, weight=max(medium, 0))
            bar_fr.columnconfigure(2, weight=max(weak, 1))
            for col_idx, (col, w) in enumerate([(C["green"], strong), (C["orange"], medium), (C["red"], weak)]):
                if w > 0:
                    ctk.CTkFrame(bar_fr, fg_color=col, height=8, corner_radius=4).grid(
                        row=0, column=col_idx, sticky="ew", padx=1)
            legend = ctk.CTkFrame(dc, fg_color="transparent")
            legend.pack(anchor="w", padx=20, pady=(0, 14))
            for lbl, col, val in [("قوية", C["green"], strong),
                                   ("متوسطة", C["orange"], medium),
                                   ("ضعيفة", C["red"], weak)]:
                ctk.CTkFrame(legend, fg_color=col, width=10, height=10,
                             corner_radius=2).pack(side="left", padx=(0, 4))
                ctk.CTkLabel(legend, text=f"{lbl}: {val}",
                             font=F["tiny"], text_color=C["t2"]).pack(side="left", padx=(0, 14))

        # ── قائمة المشاكل ──
        problems = []
        for key, a in self.vault.items():
            issues = pw_analysis(a.get("password",""))["issues"]
            if pw_counts.get(a.get("password",""), 0) > 1:
                issues.append("مكررة في الخزنة")
            if is_old(a.get("date", "")):
                issues.append("لم تُحدَّث منذ 90+ يوم")
            if issues:
                problems.append((key, a.get("name","?"), issues))

        if problems:
            pc = Card(scroll)
            pc.pack(fill="x", pady=(0, 12))
            ctk.CTkLabel(pc, text="⚠  حسابات تحتاج تحسين",
                         font=F["sub"], text_color=C["orange"]).pack(anchor="w", padx=20, pady=(14, 8))
            for key, name, issues in problems[:10]:
                row = ctk.CTkFrame(pc, fg_color=C["card2"], corner_radius=10,
                                   border_width=1, border_color=C["border"])
                row.pack(fill="x", padx=14, pady=3)
                row.columnconfigure(1, weight=1)
                ctk.CTkLabel(row, text=name, font=F["small"],
                             text_color=C["t1"]).grid(row=0, column=0, padx=12, pady=8, sticky="w")
                ctk.CTkLabel(row, text=" · ".join(issues[:2]),
                             font=F["tiny"], text_color=C["orange"]).grid(row=0, column=1, sticky="w")
                GhostBtn(row, text="✎ تعديل", width=80, height=28, font=F["tiny"],
                         command=lambda k=key: self.on_fix(k)).grid(row=0, column=2, padx=8)
            if len(problems) > 10:
                ctk.CTkLabel(pc, text=f"... و{len(problems)-10} آخرين",
                             font=F["tiny"], text_color=C["t3"]).pack(pady=(0, 8))

        ctk.CTkLabel(scroll, text="", height=10).pack()

# ══════════════════════════════════════════════════════════════
#  ACCOUNT DETAIL WINDOW  (جديد)
# ══════════════════════════════════════════════════════════════
class DetailWindow(ctk.CTkToplevel):
    def __init__(self, master, acc: dict, key: str, app):
        super().__init__(master)
        self.acc = acc
        self.key = key
        self.app = app
        self._reveal_after = None
        self.title(f"تفاصيل — {acc.get('name','')}")
        self.geometry("520x620")
        self.configure(fg_color=C["bg"])
        self.grab_set()
        self.resizable(False, False)
        self._build()

    def _build(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(scroll, text=f"📋  {self.acc.get('name','')}",
                     font=F["title"], text_color=C["t1"]).pack(anchor="w", pady=(0,16))

        an = pw_analysis(self.acc.get("password",""))

        # معلومات أساسية
        info_card = Card(scroll)
        info_card.pack(fill="x", pady=(0,10))
        for icon, lbl, val, is_mono in [
            ("📧", "البريد الإلكتروني",  self.acc.get("email","—"),  False),
            ("🏷", "التصنيف",            self.acc.get("tag","—"),    False),
            ("📅", "تاريخ الإضافة",      self.acc.get("date","—"),   False),
            ("✏️", "آخر تعديل",          self.acc.get("modified","—"), False),
            ("📝", "ملاحظات",            self.acc.get("notes","—") or "—", False),
        ]:
            fr = ctk.CTkFrame(info_card, fg_color="transparent")
            fr.pack(fill="x", padx=16, pady=4)
            fr.columnconfigure(1, weight=1)
            ctk.CTkLabel(fr, text=f"{icon}  {lbl}", font=F["small"],
                         text_color=C["t2"], width=130, anchor="w").grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(fr, text=val, font=F["mono"] if is_mono else F["small"],
                         text_color=C["t1"], anchor="w", wraplength=280).grid(row=0, column=1, sticky="w")
            GhostBtn(fr, text="⎘", width=30, height=28, font=F["small"],
                     command=lambda v=val: (clip_copy(self, v), self.app.toast.show("✓  تم النسخ", C["green"]))
                     ).grid(row=0, column=2, padx=6)

        # كلمة المرور
        pw_card = Card(scroll)
        pw_card.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(pw_card, text="🔑  كلمة المرور",
                     font=F["sub"], text_color=C["t2"]).pack(anchor="w", padx=16, pady=(14,6))

        pw_fr = ctk.CTkFrame(pw_card, fg_color=C["bg"], corner_radius=8,
                             border_width=1, border_color=C["border"])
        pw_fr.pack(fill="x", padx=16, pady=(0,4))

        self._pw_lbl = ctk.CTkLabel(pw_fr, text="●" * min(len(self.acc.get("password","")),24),
                                    font=F["monol"], text_color=C["green"],
                                    anchor="w", wraplength=340)
        self._pw_lbl.pack(side="left", padx=12, pady=12, fill="x", expand=True)

        btn_row = ctk.CTkFrame(pw_card, fg_color="transparent")
        btn_row.pack(padx=16, pady=(0,14))
        PrimaryBtn(btn_row, text="👁  عرض (10ث)", command=self._reveal,
                   width=140, height=34).pack(side="left", padx=4)
        GhostBtn(btn_row, text="⎘  نسخ", command=self._copy_pw,
                 width=100, height=34).pack(side="left", padx=4)
        OrangeBtn(btn_row, text="⚡  استبدال", command=self._replace_pw,
                  width=110, height=34).pack(side="left", padx=4)

        # تحليل القوة
        an_card = Card(scroll)
        an_card.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(an_card, text="📊  تحليل القوة",
                     font=F["sub"], text_color=C["t2"]).pack(anchor="w", padx=16, pady=(14,6))

        StrBar(an_card).pack(fill="x", padx=16, pady=(0,6))
        # نفّذ تحديث بعد packing
        bar = StrBar(an_card)
        bar.pack(fill="x", padx=16, pady=(0,6))
        bar.update(self.acc.get("password",""))

        meta_fr = ctk.CTkFrame(an_card, fg_color="transparent")
        meta_fr.pack(fill="x", padx=16, pady=(0,10))
        for lbl, val, col in [
            ("الطول",    f"{an['length']} حرف",  C["t1"]),
            ("الانتروبيا", f"~{an['bits']} بت",  C["cyan"]),
            ("المجموعة",  f"{an['pool']} محرف",   C["t2"]),
        ]:
            ctk.CTkLabel(meta_fr, text=f"{lbl}: ", font=F["tiny"],
                         text_color=C["t3"]).pack(side="left")
            ctk.CTkLabel(meta_fr, text=f"{val}  ", font=("Consolas", 11),
                         text_color=col).pack(side="left")

        if an["issues"]:
            ctk.CTkLabel(an_card, text="نقاط ضعف:", font=F["tiny"],
                         text_color=C["orange"]).pack(anchor="w", padx=16, pady=(0,4))
            for iss in an["issues"]:
                ctk.CTkLabel(an_card, text=f"  ⚡ {iss}", font=F["tiny"],
                             text_color=C["orange"]).pack(anchor="w", padx=20)
            ctk.CTkLabel(an_card, text="", height=6).pack()

        # أزرار الإجراءات
        act = ctk.CTkFrame(scroll, fg_color="transparent")
        act.pack(pady=10)
        PrimaryBtn(act, text="✎  تعديل",  command=lambda: (self.destroy(), self.app._open_edit(self.key)), width=120).pack(side="left", padx=4)
        DangerBtn (act, text="✕  حذف",    command=lambda: (self.destroy(), self.app._confirm_delete(self.key)), width=100).pack(side="left", padx=4)
        GhostBtn  (act, text="إغلاق",     command=self.destroy, width=90).pack(side="left", padx=4)

    def _reveal(self):
        if self._reveal_after:
            try: self.after_cancel(self._reveal_after)
            except: pass
        self._pw_lbl.configure(text=self.acc.get("password",""))
        self._reveal_after = self.after(10_000, self._hide_pw)

    def _hide_pw(self):
        pw = self.acc.get("password","")
        self._pw_lbl.configure(text="●" * min(len(pw), 24))

    def _copy_pw(self):
        clip_copy(self, self.acc.get("password",""))
        self.app.toast.show("✓  تم نسخ كلمة المرور", C["green"])

    def _replace_pw(self):
        new_pw = gen_pw(28)
        if messagebox.askyesno("استبدال كلمة المرور",
                               f"هل تريد استبدال كلمة المرور الحالية بـ:\n{new_pw}",
                               parent=self):
            self.acc["password"] = new_pw
            self.acc["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            self.app.vault[self.key] = self.acc
            vault_save(self.app.vault, self.app.master_pw)
            self.app.toast.show("✓  تم استبدال كلمة المرور", C["green"])
            self.app._refresh_stats()
            self.destroy()
            self.app._nav("accounts")

# ══════════════════════════════════════════════════════════════
#  ACCOUNT CARD ROW
# ══════════════════════════════════════════════════════════════
class AccCard(ctk.CTkFrame):
    def __init__(self, parent, acc: dict, key: str, app, **kw):
        super().__init__(parent, fg_color=C["card"], corner_radius=14,
                         border_width=1, border_color=C["border"], **kw)
        self.acc = acc
        self.key = key
        self.app = app
        self._expanded = False
        self._detail_built = False
        self._build_header()
        self._detail = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=8)

    def _build_header(self):
        self.columnconfigure(1, weight=1)
        name = self.acc.get("name", "?")
        initials = "".join(p[0].upper() for p in name.split()[:2]) or "?"

        av = ctk.CTkFrame(self, width=48, height=48, corner_radius=12,
                          fg_color=C["acc_bg"])
        av.grid(row=0, column=0, padx=(14,10), pady=13, sticky="ns")
        av.grid_propagate(False)
        av.rowconfigure(0, weight=1); av.columnconfigure(0, weight=1)
        ctk.CTkLabel(av, text=initials, font=("Segoe UI", 14, "bold"),
                     text_color=C["accent"]).grid()

        info = ctk.CTkFrame(self, fg_color="transparent")
        info.grid(row=0, column=1, sticky="w", pady=10)
        name_row = ctk.CTkFrame(info, fg_color="transparent")
        name_row.pack(anchor="w")
        ctk.CTkLabel(name_row, text=name, font=F["sub"],
                     text_color=C["t1"], anchor="w").pack(side="left")
        # وسم التصنيف
        tag = self.acc.get("tag","")
        if tag:
            ctk.CTkLabel(name_row, text=f"  {tag}  ", font=F["tiny"],
                         text_color=C["purple"], fg_color=C["pur_bg"],
                         corner_radius=4).pack(side="left", padx=6)
        # تحذير قديم
        if is_old(self.acc.get("date","")):
            ctk.CTkLabel(name_row, text="  قديمة  ", font=F["tiny"],
                         text_color=C["cyan"], fg_color=C["cyn_bg"],
                         corner_radius=4).pack(side="left", padx=2)

        ctk.CTkLabel(info, text=self.acc.get("email","—"),
                     font=F["small"], text_color=C["t2"], anchor="w").pack(anchor="w")

        sc, sl, col = pw_strength(self.acc.get("password",""))
        bg = strength_bg(col)
        ctk.CTkLabel(self, text=f"  {sl}  ", font=("Segoe UI", 11, "bold"),
                     text_color=col, fg_color=bg, corner_radius=6).grid(row=0, column=2, padx=6)

        bf = ctk.CTkFrame(self, fg_color="transparent")
        bf.grid(row=0, column=3, padx=(0, 12))

        def ib(txt, cmd, c):
            b = ctk.CTkButton(bf, text=txt, width=34, height=34,
                              fg_color="transparent", hover_color=C["card2"],
                              border_width=1, border_color=C["border"],
                              text_color=c, corner_radius=8,
                              font=("Segoe UI", 13), command=cmd)
            b.pack(side="left", padx=2)

        ib("⊕", self._toggle,                                              C["t2"])
        ib("🔍", lambda: DetailWindow(self.app, self.acc, self.key, self.app), C["cyan"])
        ib("⎘", self._copy_pw,                                             C["accent"])
        ib("✎", lambda: self.app._open_edit(self.key),                     C["orange"])
        ib("✕", lambda: self.app._confirm_delete(self.key),                C["red"])

    def _build_detail(self):
        self._detail.columnconfigure(1, weight=1)
        pw = self.acc.get("password","—")
        rows = [
            ("📧", "البريد",        self.acc.get("email","—"),    False),
            ("🔑", "كلمة المرور",   pw,                           True),
            ("🏷", "التصنيف",       self.acc.get("tag","—"),      False),
            ("📝", "ملاحظات",       self.acc.get("notes","") or "—", False),
            ("📅", "التاريخ",       self.acc.get("date","—"),     False),
        ]
        for i, (icon, label, val, is_pw) in enumerate(rows):
            ctk.CTkLabel(self._detail, text=f"{icon}  {label}",
                         font=F["small"], text_color=C["t2"],
                         anchor="w").grid(row=i, column=0, padx=(14,6), pady=5, sticky="w")
            ctk.CTkLabel(self._detail, text=val,
                         font=F["mono"] if is_pw else F["small"],
                         text_color=C["accent"] if is_pw else C["t1"],
                         anchor="w", wraplength=300).grid(
                row=i, column=1, pady=5, sticky="w", padx=(0,8))
            def _copy(v=val, lbl=label):
                clip_copy(self.app, v)
                self.app.toast.show(f"✓  تم نسخ {lbl}", C["green"])
            ctk.CTkButton(self._detail, text="⎘", width=28, height=28,
                          fg_color="transparent", hover_color=C["card2"],
                          border_width=1, border_color=C["border"],
                          text_color=C["t2"], corner_radius=6,
                          font=("Segoe UI", 11), command=_copy
                          ).grid(row=i, column=2, padx=(0,10), pady=5)

        sep = ctk.CTkFrame(self._detail, fg_color=C["border"], height=1)
        sep.grid(row=5, column=0, columnspan=3, sticky="ew", padx=12, pady=(4,6))
        bfr = ctk.CTkFrame(self._detail, fg_color="transparent")
        bfr.grid(row=6, column=0, columnspan=3, sticky="ew", padx=14, pady=(0,12))
        bfr.columnconfigure(0, weight=1)
        sc, sl, col = pw_strength(self.acc.get("password",""))
        pb = ctk.CTkProgressBar(bfr, height=6, corner_radius=3,
                                 fg_color=C["border"], progress_color=col)
        pb.set(sc/100)
        pb.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(bfr, text=f"  {sl}", font=("Segoe UI",11,"bold"),
                     text_color=col).grid(row=0, column=1)
        self._detail_built = True

    def _toggle(self):
        self._expanded = not self._expanded
        if self._expanded:
            if not self._detail_built: self._build_detail()
            self._detail.grid(row=1, column=0, columnspan=4,
                              padx=12, pady=(0,12), sticky="ew")
        else:
            self._detail.grid_forget()

    def _copy_pw(self):
        clip_copy(self.app, self.acc.get("password",""))
        self.app.toast.show("✓  تم نسخ كلمة المرور", C["green"])

# ══════════════════════════════════════════════════════════════
#  MAIN APP
# ══════════════════════════════════════════════════════════════
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Gmail Vault v4  —  مدير كلمات المرور")
        self.geometry("1060x720")
        self.minsize(880, 600)
        self.configure(fg_color=C["bg"])
        self.master_pw: str = ""
        self.vault: dict = {}
        self.toast = Toast(self)
        self._pending_pw = ""
        self._gen_history: list[str] = []
        self._last_gen = ""
        self._sort_by = "name"
        self._auto_lock_id = None
        self._show_lock()
        self.bind_all("<Key>", self._reset_lock_timer)
        self.bind_all("<Motion>", self._reset_lock_timer)

    def _reset_lock_timer(self, event=None):
        if not self.master_pw: return
        if self._auto_lock_id:
            try: self.after_cancel(self._auto_lock_id)
            except: pass
        self._auto_lock_id = self.after(AUTO_LOCK_MS, self._auto_lock)

    def _auto_lock(self):
        if self.master_pw:
            self.toast.show("🔒  تم القفل تلقائياً بعد عدم النشاط", C["cyan"], 3000)
            self.after(800, self._lock)

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    def _show_lock(self):
        self._clear()
        LockScreen(self, self._after_unlock).pack(fill="both", expand=True)

    def _after_unlock(self, pw: str, vault: dict):
        self.master_pw = pw
        self.vault = vault
        self._build_main()
        self._reset_lock_timer()

    # ── Main Layout ──────────────────────────────────────────
    def _build_main(self):
        self._clear()
        self.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        # ── Sidebar ──────────────────────────────────────────
        sb = ctk.CTkFrame(self, fg_color=C["panel"], width=240, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.rowconfigure(7, weight=1)
        sb.columnconfigure(0, weight=1)

        logo = ctk.CTkFrame(sb, fg_color=C["card"], corner_radius=12,
                            border_width=1, border_color=C["border"])
        logo.grid(sticky="ew", padx=14, pady=(18,14))
        logo.columnconfigure(0, weight=1)
        ctk.CTkLabel(logo, text="🔐  Gmail Vault",
                     font=("Segoe UI", 15, "bold"),
                     text_color=C["t1"]).grid(padx=14, pady=(12,2), sticky="w")
        ctk.CTkLabel(logo, text="v4 · مشفر ومحمي",
                     font=F["tiny"], text_color=C["t3"]).grid(padx=14, pady=(0,12), sticky="w")

        self._nav_btns: dict[str, ctk.CTkButton] = {}
        nav_items = [
            ("accounts",  "📋   الحسابات"),
            ("security",  "🛡   لوحة الأمان"),
            ("generator", "⚡   مولّد كلمات المرور"),
            ("add",       "➕   إضافة حساب"),
        ]
        for i, (key, label) in enumerate(nav_items):
            b = ctk.CTkButton(sb, text=label, font=F["body"], anchor="w",
                              fg_color="transparent", hover_color=C["card2"],
                              text_color=C["t2"], corner_radius=8, height=42,
                              command=lambda k=key: self._nav(k))
            b.grid(row=1+i, padx=10, pady=2, sticky="ew")
            self._nav_btns[key] = b

        ctk.CTkFrame(sb, fg_color=C["border"], height=1).grid(
            row=5, sticky="ew", padx=14, pady=10)

        self._stat_fr = ctk.CTkFrame(sb, fg_color="transparent")
        self._stat_fr.grid(row=6, sticky="ew", padx=14)
        self._stat_fr.columnconfigure(0, weight=1)
        self._refresh_stats()

        # أزرار استيراد/تصدير
        io_fr = ctk.CTkFrame(sb, fg_color="transparent")
        io_fr.grid(row=7, sticky="ew", padx=14, pady=(8,4))
        io_fr.columnconfigure(0, weight=1); io_fr.columnconfigure(1, weight=1)
        GhostBtn(io_fr, text="📤 تصدير", command=self._export,
                 height=34, font=F["tiny"]).grid(row=0, column=0, padx=(0,4), sticky="ew")
        GhostBtn(io_fr, text="📥 استيراد", command=self._import,
                 height=34, font=F["tiny"]).grid(row=0, column=1, sticky="ew")

        DangerBtn(sb, text="🔒  قفل التطبيق", command=self._lock,
                  width=210, height=38).grid(row=8, padx=14, pady=(4,18), sticky="s")

        # ── Content ──────────────────────────────────────────
        self.content = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)

        self._nav("accounts")

    def _refresh_stats(self):
        for w in self._stat_fr.winfo_children(): w.destroy()
        total  = len(self.vault)
        strong = sum(1 for a in self.vault.values() if pw_strength(a.get("password",""))[0] >= 80)
        weak   = sum(1 for a in self.vault.values() if pw_strength(a.get("password",""))[0] < 55)
        pws    = [a.get("password","") for a in self.vault.values() if a.get("password","")]
        pw_counts = {}
        for p in pws: pw_counts[p] = pw_counts.get(p,0)+1
        reused = sum(1 for c in pw_counts.values() if c > 1)

        for lbl, val, col, bg in [
            ("إجمالي", total,  C["accent"], C["acc_bg"]),
            ("قوية",   strong, C["green"],  C["grn_bg"]),
            ("ضعيفة",  weak,   C["red"],    C["red_bg"]),
            ("مكررة",  reused, C["purple"], C["pur_bg"]),
        ]:
            fr = ctk.CTkFrame(self._stat_fr, fg_color=bg, corner_radius=8,
                              border_width=1, border_color=C["border"])
            fr.grid(sticky="ew", pady=3)
            fr.columnconfigure(0, weight=1)
            ctk.CTkLabel(fr, text=str(val), font=("Consolas", 18, "bold"),
                         text_color=col).grid(sticky="w", padx=14, pady=(8,0))
            ctk.CTkLabel(fr, text=lbl, font=F["tiny"],
                         text_color=C["t3"]).grid(sticky="w", padx=14, pady=(0,8))

    def _nav(self, page: str):
        for k, b in self._nav_btns.items():
            b.configure(fg_color=C["card2"] if k==page else "transparent",
                        text_color=C["accent"] if k==page else C["t2"])
        for w in self.content.winfo_children(): w.destroy()
        getattr(self, f"_pg_{page}")()

    def _lock(self):
        self.vault = {}; self.master_pw = ""
        if self._auto_lock_id:
            try: self.after_cancel(self._auto_lock_id)
            except: pass
        self._show_lock()

    # ══════════════════════════════════════════════════════════
    #  PAGE: ACCOUNTS
    # ══════════════════════════════════════════════════════════
    def _pg_accounts(self):
        root = ctk.CTkFrame(self.content, fg_color="transparent")
        root.pack(fill="both", expand=True, padx=26, pady=22)
        root.rowconfigure(3, weight=1)
        root.columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(root, fg_color="transparent")
        hdr.grid(row=0, sticky="ew", pady=(0,12))
        hdr.columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="الحسابات المحفوظة",
                     font=F["title"], text_color=C["t1"]).grid(row=0, column=0, sticky="w")
        self._acc_badge = ctk.CTkLabel(hdr, text=f"  {len(self.vault)} حساب  ",
                                        font=F["small"], text_color=C["accent"],
                                        fg_color=C["acc_bg"], corner_radius=8)
        self._acc_badge.grid(row=0, column=1, padx=8)

        # بحث
        sf = ctk.CTkFrame(root, fg_color=C["panel"], corner_radius=10,
                          border_width=1, border_color=C["border"])
        sf.grid(row=1, sticky="ew", pady=(0,6))
        sf.columnconfigure(1, weight=1)
        ctk.CTkLabel(sf, text="🔍", font=("Segoe UI",16),
                     text_color=C["t2"]).grid(row=0, column=0, padx=(12,4))
        self._search_sv = tk.StringVar()
        s_entry = ctk.CTkEntry(sf, textvariable=self._search_sv,
                               placeholder_text="ابحث باسم أو بريد أو ملاحظات...",
                               font=F["body"], fg_color="transparent",
                               border_width=0, text_color=C["t1"], height=46)
        s_entry.grid(row=0, column=1, sticky="ew", padx=(0,4), pady=4)
        attach_menu(s_entry)
        GhostBtn(sf, text="✕", width=34, height=34,
                 command=lambda: self._search_sv.set("")).grid(row=0, column=2, padx=(0,8))

        # ترتيب + تصفية تصنيف
        sort_fr = ctk.CTkFrame(root, fg_color="transparent")
        sort_fr.grid(row=2, sticky="ew", pady=(0,8))
        ctk.CTkLabel(sort_fr, text="ترتيب:", font=F["small"],
                     text_color=C["t3"]).pack(side="left", padx=(0,6))
        for lbl, key in [("الاسم","name"),("البريد","email"),("التاريخ","date"),("القوة","strength")]:
            def _mk_sort(k=key):
                self._sort_by = k
                self._draw_accounts()
            b = ctk.CTkButton(sort_fr, text=lbl, font=F["tiny"], height=28, width=60,
                              fg_color=C["accent"] if self._sort_by==key else C["card2"],
                              hover_color=C["card2"], text_color=C["t1"],
                              corner_radius=6, command=_mk_sort)
            b.pack(side="left", padx=2)

        # قائمة
        self._accs_scroll = ctk.CTkScrollableFrame(root, fg_color="transparent",
                                                    scrollbar_button_color=C["border"],
                                                    scrollbar_button_hover_color=C["t3"])
        self._accs_scroll.grid(row=3, sticky="nsew")
        self._accs_scroll.columnconfigure(0, weight=1)

        self._search_after_id = None
        def _debounced(*_):
            if self._search_after_id:
                try: self.after_cancel(self._search_after_id)
                except: pass
            self._search_after_id = self.after(120, self._draw_accounts)
        self._search_sv.trace_add("write", _debounced)
        self._draw_accounts()

    def _draw_accounts(self):
        scroll = self._accs_scroll
        for w in scroll.winfo_children(): w.destroy()
        q = self._search_sv.get().lower() if hasattr(self,"_search_sv") else ""
        items = [(k,v) for k,v in self.vault.items()
                 if q in v.get("name","").lower()
                 or q in v.get("email","").lower()
                 or q in v.get("notes","").lower()
                 or q in v.get("tag","").lower()]

        def sort_key(item):
            k, v = item
            if self._sort_by == "name":     return v.get("name","").lower()
            if self._sort_by == "email":    return v.get("email","").lower()
            if self._sort_by == "date":     return v.get("date","")
            if self._sort_by == "strength": return -pw_strength(v.get("password",""))[0]
            return v.get("name","").lower()

        items = sorted(items, key=sort_key)
        n = len(items) if q else len(self.vault)
        if hasattr(self,"_acc_badge"):
            self._acc_badge.configure(text=f"  {n} حساب  ")
        if not items:
            ef = Card(scroll)
            ef.pack(fill="x", padx=4, pady=40)
            ctk.CTkLabel(ef, text="🗂", font=("Segoe UI",44)).pack(pady=(28,6))
            ctk.CTkLabel(ef, text="لا توجد حسابات" if not q else f"لا نتائج لـ «{q}»",
                         font=F["sub"], text_color=C["t2"]).pack(pady=(0,28))
            return
        for key, acc in items:
            AccCard(scroll, acc, key, self).pack(fill="x", padx=4, pady=4)

    # ══════════════════════════════════════════════════════════
    #  PAGE: SECURITY
    # ══════════════════════════════════════════════════════════
    def _pg_security(self):
        def on_fix(key):
            self._nav("accounts")
            self._open_edit(key)
        SecurityPage(self.content, self.vault, on_fix).pack(fill="both", expand=True)

    # ══════════════════════════════════════════════════════════
    #  PAGE: GENERATOR
    # ══════════════════════════════════════════════════════════
    def _pg_generator(self):
        scroll = ctk.CTkScrollableFrame(self.content, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=26, pady=22)

        ctk.CTkLabel(scroll, text="⚡  مولّد كلمات المرور القوية",
                     font=F["title"], text_color=C["t1"]).pack(anchor="w", pady=(0,18))

        # ── الإعدادات ──
        sc = Card(scroll)
        sc.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(sc, text="إعدادات التوليد", font=F["sub"],
                     text_color=C["t2"]).pack(anchor="w", padx=20, pady=(16,10))

        lf = ctk.CTkFrame(sc, fg_color="transparent")
        lf.pack(fill="x", padx=20, pady=(0,12))
        lf.columnconfigure(1, weight=1)
        ctk.CTkLabel(lf, text="الطول:", font=F["body"],
                     text_color=C["t1"], width=55).grid(row=0, column=0, sticky="w")
        self._len_v = ctk.IntVar(value=28)
        self._len_lbl = ctk.CTkLabel(lf, text="28", font=("Consolas",16,"bold"),
                                      text_color=C["accent"], width=38)
        self._len_lbl.grid(row=0, column=2, padx=(8,0))
        self._slider_after = None
        def _on_slider(v):
            self._len_lbl.configure(text=str(int(v)))
            if self._slider_after:
                try: self.after_cancel(self._slider_after)
                except: pass
            self._slider_after = self.after(80, self._do_gen)
        ctk.CTkSlider(lf, from_=8, to=64, variable=self._len_v,
                      number_of_steps=56,
                      button_color=C["accent"], button_hover_color="#3A75F5",
                      progress_color=C["accent"],
                      command=_on_slider).grid(row=0, column=1, sticky="ew")

        ctk.CTkFrame(sc, fg_color=C["border"], height=1).pack(fill="x", padx=20, pady=(0,10))
        ctk.CTkLabel(sc, text="المحارف المستخدمة", font=F["sub"],
                     text_color=C["t2"]).pack(anchor="w", padx=20)

        self._o_upper  = ctk.BooleanVar(value=True)
        self._o_lower  = ctk.BooleanVar(value=True)
        self._o_digits = ctk.BooleanVar(value=True)
        self._o_syms   = ctk.BooleanVar(value=True)
        self._o_noamb  = ctk.BooleanVar(value=False)
        opts = [(self._o_upper,  "أحرف كبيرة  (A–Z)"),
                (self._o_lower,  "أحرف صغيرة  (a–z)"),
                (self._o_digits, "أرقام  (0–9)"),
                (self._o_syms,   "رموز خاصة  (!@#$…)"),
                (self._o_noamb,  "تجنب المتشابهة  (0 O 1 l I)")]
        ofr = ctk.CTkFrame(sc, fg_color="transparent")
        ofr.pack(fill="x", padx=20, pady=(8,20))
        for i, (var, lbl) in enumerate(opts):
            ctk.CTkCheckBox(ofr, text=lbl, variable=var,
                            font=F["body"], text_color=C["t1"],
                            checkmark_color=C["bg"], fg_color=C["accent"],
                            hover_color="#3A75F5", border_color=C["border"],
                            command=self._do_gen).grid(
                row=i//2, column=i%2, sticky="w", padx=12, pady=5)

        # ── الناتج ──
        oc = Card(scroll)
        oc.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(oc, text="كلمة المرور المولّدة",
                     font=F["sub"], text_color=C["t2"]).pack(anchor="w", padx=20, pady=(16,8))

        self._gen_out = ctk.CTkEntry(oc, height=56, font=F["monol"],
                                      fg_color=C["bg"], border_color=C["border"],
                                      text_color=C["green"], corner_radius=8)
        self._gen_out.pack(fill="x", padx=20, pady=(0,10))
        attach_menu(self._gen_out)

        self._gen_str = StrBar(oc)
        self._gen_str.pack(fill="x", padx=20, pady=(0,6))

        self._entropy_lbl = ctk.CTkLabel(oc, text="", font=F["small"], text_color=C["t3"])
        self._entropy_lbl.pack(anchor="w", padx=20, pady=(0,10))

        bf = ctk.CTkFrame(oc, fg_color="transparent")
        bf.pack(padx=20, pady=(0,18))
        PrimaryBtn(bf, text="⟳  توليد جديد",  command=self._do_gen,   width=150).pack(side="left", padx=4)
        GhostBtn  (bf, text="⎘  نسخ",          command=self._copy_gen, width=100).pack(side="left", padx=4)
        GreenBtn  (bf, text="➕  أضف لحساب",   command=self._use_gen,  width=150).pack(side="left", padx=4)

        # ── السجل ──
        hc = Card(scroll)
        hc.pack(fill="x")
        ctk.CTkLabel(hc, text="آخر كلمات المرور المولّدة",
                     font=F["sub"], text_color=C["t2"]).pack(anchor="w", padx=20, pady=(14,8))
        self._hist_fr = ctk.CTkFrame(hc, fg_color="transparent")
        self._hist_fr.pack(fill="x", padx=20, pady=(0,14))
        self._hist_fr.columnconfigure(0, weight=1)
        self._hist_rows = []
        self._rebuild_hist()
        self._do_gen()

    def _do_gen(self):
        pw = gen_pw(
            length=int(self._len_v.get()),
            upper=self._o_upper.get(),
            lower=self._o_lower.get(),
            digits=self._o_digits.get(),
            symbols=self._o_syms.get(),
            no_ambig=self._o_noamb.get(),
        )
        self._last_gen = pw
        self._gen_out.delete(0, "end")
        self._gen_out.insert(0, pw)
        self._gen_str.update(pw)

        pool = (26 if self._o_upper.get() else 0) + \
               (26 if self._o_lower.get() else 0) + \
               (10 if self._o_digits.get() else 0) + \
               (24 if self._o_syms.get() else 0)
        bits = pw_entropy(pw, pool or 62)
        sc, _, _ = pw_strength(pw)
        self._entropy_lbl.configure(
            text=f"انتروبيا: ~{bits} بت  ·  طول: {len(pw)} حرف  ·  مجموعة: {pool or 62} محرف")

        if pw not in self._gen_history:
            self._gen_history.insert(0, pw)
            if len(self._gen_history) > 8: self._gen_history.pop()
            self._rebuild_hist()
        else:
            self._update_hist_colors(pw)

    def _rebuild_hist(self):
        for w in self._hist_fr.winfo_children(): w.destroy()
        self._hist_rows = []
        if not self._gen_history:
            ctk.CTkLabel(self._hist_fr, text="لم يتم التوليد بعد",
                         font=F["small"], text_color=C["t3"]).pack(anchor="w")
            return
        for i, p in enumerate(self._gen_history):
            sc, sl, col = pw_strength(p)
            rw = ctk.CTkFrame(self._hist_fr, fg_color=C["card2"],
                              corner_radius=8, border_width=1, border_color=C["border"])
            rw.pack(fill="x", pady=3)
            rw.columnconfigure(0, weight=1)
            lbl = ctk.CTkLabel(rw, text=p, font=F["monom"],
                               text_color=C["t1"] if i==0 else C["t2"], anchor="w")
            lbl.grid(row=0, column=0, padx=12, pady=7, sticky="w")
            ctk.CTkLabel(rw, text=f"  {sl}  ", font=F["tiny"],
                         text_color=col, fg_color=strength_bg(col),
                         corner_radius=4).grid(row=0, column=1, padx=4)
            ctk.CTkButton(rw, text="⎘", width=28, height=28,
                          fg_color="transparent", hover_color=C["card"],
                          border_width=1, border_color=C["border"],
                          text_color=C["t2"], corner_radius=6,
                          font=("Segoe UI",11),
                          command=lambda cp=p: (
                              clip_copy(self, cp),
                              self.toast.show("✓  تم النسخ", C["green"])
                          )).grid(row=0, column=2, padx=(0,8), pady=4)
            self._hist_rows.append((rw, lbl, p))

    def _update_hist_colors(self, active):
        for _, lbl, p in self._hist_rows:
            lbl.configure(text_color=C["t1"] if p==active else C["t2"])

    def _copy_gen(self):
        pw = self._gen_out.get()
        if pw:
            clip_copy(self, pw)
            self.toast.show("✓  تم نسخ كلمة المرور", C["green"])

    def _use_gen(self):
        self._pending_pw = self._last_gen or self._gen_out.get()
        self._nav("add")

    # ══════════════════════════════════════════════════════════
    #  PAGE: ADD ACCOUNT
    # ══════════════════════════════════════════════════════════
    def _pg_add(self):
        scroll = ctk.CTkScrollableFrame(self.content, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=26, pady=22)

        ctk.CTkLabel(scroll, text="➕  إضافة حساب جديد",
                     font=F["title"], text_color=C["t1"]).pack(anchor="w", pady=(0,18))

        fc = Card(scroll)
        fc.pack(fill="x")

        def lbl(text):
            ctk.CTkLabel(fc, text=text, font=F["body"],
                         text_color=C["t2"]).pack(anchor="w", padx=20, pady=(14,4))

        lbl("📛  اسم الحساب")
        self._a_name = mk_entry(fc, "مثال: حساب العمل، Gmail الشخصي...")
        self._a_name.pack(fill="x", padx=20, pady=(0,4))

        lbl("📧  بريد Gmail")
        self._a_email = mk_entry(fc, "example@gmail.com")
        self._a_email.pack(fill="x", padx=20, pady=(0,4))

        lbl("🔑  كلمة المرور")
        pw_row = ctk.CTkFrame(fc, fg_color="transparent")
        pw_row.pack(fill="x", padx=20, pady=(0,4))
        pw_row.columnconfigure(0, weight=1)
        self._a_pw = mk_entry(pw_row, "أدخل أو اضغط ⚡ لتوليد كلمة قوية", mono=True)
        self._a_pw.grid(row=0, column=0, sticky="ew", padx=(0,6))
        GhostBtn(pw_row, text="⚡", width=46, height=42,
                 command=self._fill_a_pw).grid(row=0, column=1)

        self._a_str = StrBar(fc)
        self._a_str.pack(fill="x", padx=20, pady=(0,4))
        inner = _get_tk_entry(self._a_pw)
        if inner:
            inner.bind("<KeyRelease>", lambda _: self._a_str.update(self._a_pw.get()))

        lbl("🏷  التصنيف")
        tag_fr = ctk.CTkFrame(fc, fg_color="transparent")
        tag_fr.pack(fill="x", padx=20, pady=(0,4))
        self._a_tag = mk_entry(tag_fr, "مثال: شخصي، عمل...")
        self._a_tag.pack(side="left", fill="x", expand=True, padx=(0,8))
        self._a_tag_var = ctk.StringVar(value=TAGS_PRESET[0])
        ctk.CTkOptionMenu(tag_fr, values=TAGS_PRESET,
                          variable=self._a_tag_var,
                          command=lambda v: (self._a_tag.delete(0,"end"), self._a_tag.insert(0,v)),
                          width=110, height=42,
                          fg_color=C["card2"], button_color=C["border"],
                          button_hover_color=C["card"],
                          dropdown_fg_color=C["panel"],
                          text_color=C["t1"]).pack(side="left")

        lbl("📝  ملاحظات  (اختياري)")
        self._a_notes = mk_entry(fc, "مثال: حساب الشركة — لا تشاركه...")
        self._a_notes.pack(fill="x", padx=20, pady=(0,4))

        ctk.CTkFrame(fc, fg_color=C["border"], height=1).pack(fill="x", padx=20, pady=14)
        PrimaryBtn(fc, text="💾  حفظ الحساب",
                   command=self._save_account, width=230, height=46).pack(pady=(0,22))

        if self._pending_pw:
            self._a_pw.delete(0, "end")
            self._a_pw.insert(0, self._pending_pw)
            self._a_str.update(self._pending_pw)
            self._pending_pw = ""

    def _fill_a_pw(self):
        pw = gen_pw(28)
        self._a_pw.delete(0, "end")
        self._a_pw.insert(0, pw)
        self._a_str.update(pw)

    def _save_account(self):
        name  = self._a_name.get().strip()
        email = self._a_email.get().strip()
        pw    = self._a_pw.get().strip()
        notes = self._a_notes.get().strip()
        tag   = self._a_tag.get().strip()
        if not name:
            self.toast.show("⚠  أدخل اسم الحساب", C["red"]); return
        if not email or "@" not in email:
            self.toast.show("⚠  أدخل بريداً صحيحاً", C["red"]); return
        if not pw:
            self.toast.show("⚠  أدخل كلمة المرور", C["red"]); return
        key = str(int(datetime.now().timestamp() * 1000))
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.vault[key] = {"name": name, "email": email, "password": pw,
                           "notes": notes, "tag": tag,
                           "date": now, "modified": now}
        vault_save(self.vault, self.master_pw)
        self._refresh_stats()
        self.toast.show(f"✓  تم حفظ «{name}»", C["green"])
        self._nav("accounts")

    # ══════════════════════════════════════════════════════════
    #  EDIT MODAL
    # ══════════════════════════════════════════════════════════
    def _open_edit(self, key: str):
        acc = self.vault.get(key)
        if not acc: return

        m = ctk.CTkToplevel(self)
        m.title("تعديل الحساب")
        m.geometry("520x620")
        m.configure(fg_color=C["bg"])
        m.grab_set(); m.resizable(False, False)

        scroll = ctk.CTkScrollableFrame(m, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(scroll, text="✎  تعديل الحساب",
                     font=F["title"], text_color=C["t1"]).pack(anchor="w", pady=(0,14))

        mc = Card(scroll)
        mc.pack(fill="x", pady=(0,14))

        entries: dict = {}
        fields = [("📛  اسم الحساب", "name",     False),
                  ("📧  البريد",      "email",    False),
                  ("🔑  كلمة المرور", "password", True),
                  ("🏷  التصنيف",     "tag",      False),
                  ("📝  ملاحظات",     "notes",    False)]

        e_str = None
        for lbl_txt, fld, mono in fields:
            ctk.CTkLabel(mc, text=lbl_txt, font=F["small"],
                         text_color=C["t2"]).pack(anchor="w", padx=16, pady=(12,3))
            if mono:
                row = ctk.CTkFrame(mc, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=(0,4))
                row.columnconfigure(0, weight=1)
                e = mk_entry(row, mono=True)
                e.insert(0, acc.get(fld,""))
                e.grid(row=0, column=0, sticky="ew", padx=(0,6))
                def _gen_into(entry=e):
                    p = gen_pw(28)
                    entry.delete(0,"end"); entry.insert(0,p)
                    if e_str: e_str.update(p)
                GhostBtn(row, text="⚡", width=46, height=42,
                         command=_gen_into).grid(row=0, column=1)
            else:
                e = mk_entry(mc)
                e.insert(0, acc.get(fld,""))
                e.pack(fill="x", padx=16, pady=(0,4))
            entries[fld] = e

        e_str = StrBar(mc)
        e_str.pack(fill="x", padx=16, pady=(0,14))
        e_str.update(acc.get("password",""))
        inner_pw = _get_tk_entry(entries["password"])
        if inner_pw:
            inner_pw.bind("<KeyRelease>",
                          lambda _: e_str.update(entries["password"].get()))

        def do_save():
            for fld, e in entries.items():
                self.vault[key][fld] = e.get().strip()
            self.vault[key]["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            vault_save(self.vault, self.master_pw)
            self._refresh_stats()
            m.destroy()
            self.toast.show("✓  تم حفظ التعديلات", C["green"])
            self._nav("accounts")

        bf = ctk.CTkFrame(scroll, fg_color="transparent")
        bf.pack(pady=6)
        PrimaryBtn(bf, text="💾  حفظ",  command=do_save,    width=140).pack(side="left", padx=6)
        GhostBtn  (bf, text="إلغاء",   command=m.destroy,  width=110).pack(side="left", padx=6)

    # ══════════════════════════════════════════════════════════
    #  DELETE CONFIRM
    # ══════════════════════════════════════════════════════════
    def _confirm_delete(self, key: str):
        acc  = self.vault.get(key, {})
        name = acc.get("name","هذا الحساب")
        d = ctk.CTkToplevel(self)
        d.title("تأكيد الحذف")
        d.geometry("420x220")
        d.configure(fg_color=C["bg"])
        d.grab_set(); d.resizable(False, False)

        ctk.CTkLabel(d, text="⚠  حذف الحساب",
                     font=F["head"], text_color=C["red"]).pack(anchor="w", padx=26, pady=(26,8))
        ctk.CTkLabel(d,
            text=f"هل تريد حذف «{name}» نهائياً؟\nلا يمكن التراجع عن هذا الإجراء.",
            font=F["body"], text_color=C["t1"],
            wraplength=360, justify="right").pack(padx=26)

        def do_del():
            self.vault.pop(key, None)
            vault_save(self.vault, self.master_pw)
            self._refresh_stats()
            d.destroy()
            self.toast.show(f"تم حذف «{name}»", C["red"])
            self._nav("accounts")

        bf = ctk.CTkFrame(d, fg_color="transparent")
        bf.pack(pady=18)
        DangerBtn(bf, text="✕  حذف نهائياً", command=do_del,    width=160).pack(side="left", padx=6)
        GhostBtn (bf, text="إلغاء",           command=d.destroy, width=110).pack(side="left", padx=6)

    # ══════════════════════════════════════════════════════════
    #  IMPORT / EXPORT
    # ══════════════════════════════════════════════════════════
    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".vault",
            filetypes=[("Vault File","*.vault"),("All","*.*")],
            title="تصدير الخزنة")
        if not path: return
        vault_export(self.vault, self.master_pw, path)
        self.toast.show("✓  تم التصدير بنجاح", C["green"])

    def _import(self):
        path = filedialog.askopenfilename(
            filetypes=[("Vault File","*.vault"),("All","*.*")],
            title="استيراد خزنة")
        if not path: return
        imported = vault_import(self.master_pw, path)
        if imported is None:
            self.toast.show("⚠  فشل الاستيراد — كلمة المرور لا تتطابق", C["red"])
            return
        count = len(imported)
        self.vault.update(imported)
        vault_save(self.vault, self.master_pw)
        self._refresh_stats()
        self.toast.show(f"✓  تم استيراد {count} حساب", C["green"])
        self._nav("accounts")

# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = App()
    app.mainloop()