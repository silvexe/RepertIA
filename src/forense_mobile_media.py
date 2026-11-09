# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.1) - foto, video e audio degli smartphone e delle memorie di massa: tutti, riconosciuti dal contenuto, con
l'app, il programma o la cartella a cui appartengono.

Perché: le app salvano molte immagini e video nelle cache con nomi senza estensione o con estensioni proprie (Glide «.0»,
Fresco «.cnt», ExoPlayer «.exo», …). Cercandoli per estensione restavano fuori dalla sezione Foto/Video/Audio
(estrazione pubblica Android 14 di Hickman: 8.717 file per estensione, 21.751 per contenuto).

Metodo
- Si leggono i primi 32 byte di ogni file dell'estrazione (sola lettura) e si riconosce il formato dalla firma: JPEG, PNG,
  GIF, WebP, HEIC/AVIF, TIFF, MP4/MOV/3GP, Matroska/WebM, AVI, M4A, WAV, Ogg/Opus, AMR, MP3 (ID3), FLAC. Un file con
  l'estensione di una foto, di un video o di un audio ma senza una firma riconosciuta entra lo stesso, «per estensione».
- Ogni file ha la sua app: Android dal nome del pacchetto nel percorso (data/data/<pacchetto>, data/user/<n>/…,
  Android/data|media/<pacchetto>), le cartelle della memoria condivisa (DCIM, Pictures, Download, …) a parte; iOS dal
  file di metadati del contenitore (identificativo dell'app o del gruppo di app), il Rullino (Media/DCIM) a parte.
  «cache» se il percorso passa da una cartella di cache.
- I file senza i metadati dell'indicizzazione (riconosciuti solo dal contenuto) si passano a exiftool con una copia
  temporanea con l'estensione giusta; se exiftool non trova nulla resta una riga con il solo formato.
- Memorie di massa (dischi, pendrive, copie forensi): stesso riconoscimento sui file del file system, letti con pytsk3 (o
  icat) come fa il controllo delle anomalie. Un file cancellato entra dal solo contenuto solo se il contenuto è ancora il
  suo (record non riassegnato, primo cluster non sovrascritto); con l'estensione di una foto, di un video o di un audio
  entra comunque, come prima. Ogni file ha il programma o la cartella: browser e programmi dalle cartelle AppData,
  Library o .cache dell'utente (Chrome, Edge, Firefox, Safari, …), cartelle dell'utente (Immagini, Scrivania, Download,
  …), Temp, Cestino, Programmi, Sistema.
- Cache dei browser basati su Chromium (Chrome, Samsung Internet, Edge, Opera, Brave, WebView delle app), telefoni e
  memorie di massa: ogni voce «<hash>_0» della Simple Cache ha intestazione, indirizzo web e poi il contenuto scaricato.
  Se il contenuto è una foto o un video si estrae (solo quei byte, con gli hash) tra i file estratti, tipo «cache_web»,
  con il nome preso dall'indirizzo web e nella nota l'indirizzo e l'offset nel file d'origine; in media_file con
  part = -1 e inode = id dell'estratto.
- Tabella `media_file` del caso; si rifà con l'indicizzazione (analisi aggiuntiva «Testo e media»).
"""
import json
import re
import shutil
import struct
import time
from urllib.parse import unquote, urlsplit
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

HEIF = (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis")
AUDIO_FTYP = (b"M4A ", b"M4B ", b"F4A ", b"M4P ")
FORMATI = {"jpg": "JPEG", "png": "PNG", "gif": "GIF", "webp": "WebP", "heic": "HEIC/HEIF", "avif": "AVIF", "tif": "TIFF",
           "mp4": "MP4", "mov": "QuickTime", "3gp": "3GP", "mkv": "Matroska/WebM", "avi": "AVI", "m4a": "M4A",
           "wav": "WAV", "ogg": "Ogg/Opus", "amr": "AMR", "mp3": "MP3", "flac": "FLAC"}
# le stesse estensioni delle sezioni Foto, Video e Audio dell'interfaccia (IMG_ALL, VIDEO_EXT, AUDIO_EXT di forense_gui)
EXT_TIPO = {**{e: "foto" for e in (".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".webp", ".bmp", ".ico", ".avif", ".heic",
                                   ".heif", ".tif", ".tiff", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".orf", ".raf", ".psd", ".tga")},
            **{e: "video" for e in (".mp4", ".m4v", ".mov", ".webm", ".3gp", ".avi", ".mkv", ".wmv", ".mpg", ".mpeg", ".flv",
                                    ".mts", ".m2ts")},
            **{e: "audio" for e in (".mp3", ".m4a", ".aac", ".wav", ".ogg", ".oga", ".opus", ".flac", ".amr", ".caf", ".aif",
                                    ".aiff", ".wma", ".3ga", ".m4r", ".awb")}}
MIN_BYTE = 16
# valori di media_file mostrati all'agente (tipo, metodo, area)
VALORI = {"foto": N_("foto"), "video": N_("video"), "audio": N_("audio"), "contenuto": N_("contenuto"),
          "estensione": N_("estensione"), "app": N_("app"), "cache": N_("cache"), "condivisa": N_("condivisa")}
SCHEMA = """
CREATE TABLE IF NOT EXISTS media_file(part INTEGER, inode TEXT, path TEXT, tipo TEXT, formato TEXT, metodo TEXT,
    app TEXT, area TEXT, size INTEGER);
CREATE INDEX IF NOT EXISTS idx_media_pi ON media_file(part, inode);
CREATE INDEX IF NOT EXISTS idx_media_ta ON media_file(tipo, app);
"""
CACHE_DIR = {"cache", "caches", "code_cache", "tmp", ".thumbnails", "thumbnails", "image_manager_disk_cache",
             "exo", "exoplayer", "http-cache", "webviewcache", "fresco", "glide", "picasso-cache", "cache4",
             # memorie di massa: cache dei browser e file temporanei
             "cache_data", "cache2", "temp", "temporary internet files", "inetcache", "webcache", ".cache"}
# cartelle della memoria condivisa di Android e di iOS che non sono di un'app sola
CONDIVISE = {"dcim": N_("Fotocamera (DCIM)"), "pictures": N_("Immagini (Pictures)"), "movies": N_("Video (Movies)"),
             "music": N_("Musica (Music)"), "download": N_("Download"), "documents": N_("Documenti (Documents)"),
             "recordings": N_("Registrazioni (Recordings)"), "ringtones": N_("Suonerie"), "notifications": N_("Suoni di notifica"),
             "alarms": N_("Suoni delle sveglie"), "podcasts": "Podcasts", "audiobooks": "Audiobooks", "screenshots": N_("Schermate"),
             "photodata": N_("Foto di iOS: miniature e dati (PhotoData)"), "itunes": N_("Musica e iTunes (copertine)"),
             "icloud": N_("iCloud (CloudKit e iCloud Drive)"), "notifiche": N_("Notifiche"),
             "sistema": N_("Sistema"), "altro": N_("Altre cartelle"),
             # memorie di massa
             "desktop": N_("Scrivania (Desktop)"), "temp": N_("File temporanei (Temp)"), "cestino": N_("Cestino"),
             "programmi": N_("Programmi"), "utente": N_("Altre cartelle dell'utente"), "onedrive": "OneDrive",
             "dropbox": "Dropbox", "google drive": "Google Drive", "carving": N_("Recuperati dal carving")}
# cartelle della memoria condivisa che sono di un'app (versioni vecchie di WhatsApp e Telegram)
CARTELLE_APP = {"whatsapp": "com.whatsapp", "whatsapp business": "com.whatsapp.w4b", "telegram": "org.telegram.messenger"}
NOMI = {
    "com.whatsapp": "WhatsApp", "com.whatsapp.w4b": "WhatsApp Business", "org.telegram.messenger": "Telegram",
    "org.thoughtcrime.securesms": "Signal", "com.facebook.orca": "Messenger", "com.facebook.katana": "Facebook",
    "com.facebook.lite": "Facebook Lite", "com.instagram.android": "Instagram", "com.snapchat.android": "Snapchat",
    "com.zhiliaoapp.musically": "TikTok", "com.ss.android.ugc.trill": "TikTok", "com.viber.voip": "Viber",
    "jp.naver.line.android": "LINE", "com.skype.raider": "Skype", "us.zoom.videomeetings": "Zoom",
    "com.microsoft.teams": "Microsoft Teams", "com.discord": "Discord", "com.twitter.android": "X (Twitter)",
    "com.reddit.frontpage": "Reddit", "com.imgur.mobile": "Imgur", "com.pinterest": "Pinterest", "com.tinder": "Tinder",
    "com.google.android.apps.photos": N_("Google Foto"), "com.google.android.apps.messaging": N_("Google Messaggi"),
    "com.google.android.gm": "Gmail", "com.google.android.youtube": "YouTube", "com.google.android.apps.maps": "Google Maps",
    "com.google.android.googlequicksearchbox": "Google", "com.google.android.gms": "Google Play Services",
    "com.google.android.inputmethod.latin": "Gboard", "com.google.android.apps.docs": "Google Drive",
    "com.google.android.apps.dynamite": "Google Chat", "com.google.android.dialer": N_("Telefono (Google)"),
    "com.google.android.GoogleCamera": N_("Fotocamera (Google)"), "com.android.chrome": "Chrome", "org.mozilla.firefox": "Firefox",
    "com.android.providers.telephony": "SMS/MMS (Android)", "com.android.providers.media.module": N_("Archivio multimediale (Android)"),
    "com.google.android.providers.media.module": N_("Archivio multimediale (Android)"), "com.sec.android.gallery3d": N_("Galleria Samsung"),
    "com.samsung.android.messaging": N_("Messaggi Samsung"), "com.waze": "Waze", "com.spotify.music": "Spotify",
    "com.life360.android.safetymapd": "Life360", "kik.android": "Kik", "com.kakao.talk": "KakaoTalk", "com.tencent.mm": "WeChat",
    "ch.threema.app": "Threema", "com.wire": "Wire", "com.Slack": "Slack", "com.gettr.gettr": "GETTR", "com.mewe": "MeWe",
    "com.imo.android.imous": "imo", "ch.swisscows.messenger.teleguardapp": "TeleGuard", "com.burner.app": "Burner",
    "com.groupme.android": "GroupMe", "com.google.android.apps.nbu.files": N_("Files di Google"), "com.google.android.apps.tips": N_("Suggerimenti (Pixel)"),
    "com.google.android.apps.tachyon": "Google Meet (Duo)", "com.bereal.ft": "BeReal", "com.google.android.apps.youtube.music": "YouTube Music",
    "com.google.android.apps.googlevoice": "Google Voice", "com.google.android.calendar": "Google Calendar",
    "com.google.android.apps.nexuslauncher": "Pixel Launcher", "com.google.android.apps.wallpaper": N_("Sfondi (Pixel)"),
    "com.google.android.contacts": N_("Contatti (Google)"), "com.google.android.keep": "Google Keep", "com.amazon.mShop.android.shopping": "Amazon",
    "com.ubercab": "Uber", "com.airbnb.android": "Airbnb", "com.netflix.mediaclient": "Netflix", "com.linkedin.android": "LinkedIn",
    "com.microsoft.office.outlook": "Outlook", "org.signal": "Signal", "com.protonmail.android": "Proton Mail", "ch.protonmail.android": "Proton Mail", "com.wickr.pro": "Wickr",
    "com.sec.android.app.sbrowser": "Samsung Internet", "com.microsoft.emmx": "Edge", "com.opera.browser": "Opera",
    "com.brave.browser": "Brave", "com.duckduckgo.mobile.android": "DuckDuckGo", "com.kiwibrowser.browser": "Kiwi Browser",
    "com.vivaldi.browser": "Vivaldi", "com.yandex.browser": "Yandex Browser", "com.android.webview": "Android WebView",
    "com.google.android.webview": "Android WebView",
    "org.chromium.chrome": "Chromium", "org.bromite.bromite": "Bromite", "org.cromite.cromite": "Cromite",
    "com.chrome.beta": "Chrome Beta", "com.chrome.dev": "Chrome Dev", "com.chrome.canary": "Chrome Canary",
    "org.chromium.Chromium": "Chromium", "Chromium": "Chromium",
    "com.textnow.android": "TextNow", "com.tumblr": "Tumblr", "tv.twitch.android.app": "Twitch",
    # iOS (identificativo dell'app o del gruppo di app)
    "net.whatsapp.WhatsApp": "WhatsApp", "group.net.whatsapp.WhatsApp.shared": "WhatsApp",
    "net.whatsapp.WhatsAppSMB": "WhatsApp Business", "group.net.whatsapp.WhatsAppSMB.shared": "WhatsApp Business",
    "ph.telegra.Telegraph": "Telegram", "group.ph.telegra.Telegraph": "Telegram", "org.whispersystems.signal": "Signal",
    "group.org.whispersystems.signal.group": "Signal", "com.burbn.instagram": "Instagram", "com.toyopagroup.picaboo": "Snapchat",
    "com.zhiliaoapp.musically": "TikTok", "com.facebook.Messenger": "Messenger", "com.facebook.Facebook": "Facebook",
    "com.apple.MobileSMS": N_("Messaggi (iMessage/SMS)"), "com.apple.mobileslideshow": N_("Foto (Apple)"),
    "com.apple.camera": N_("Fotocamera (Apple)"), "com.apple.VoiceMemos": N_("Memo vocali"), "com.apple.mobilesafari": "Safari",
    "com.apple.mobilemail": N_("Mail (Apple)"), "com.apple.mobilenotes": N_("Note (Apple)"), "com.google.chrome.ios": "Chrome",
    "com.viber": "Viber", "com.skype.skype": "Skype", "jp.naver.line": "LINE", "com.hammerandchisel.discord": "Discord",
    "group.viber.share.container": "Viber", "com.waze.iphone": "Waze", "com.brave.ios.browser": "Brave", "com.spotify.client": "Spotify",
    "com.google.Gmail": "Gmail", "imgurmobile": "Imgur", "com.enchantedcloud.photovault": "Private Photo Vault",
    "com.reddit.Reddit": "Reddit", "com.kik.chat": "Kik", "com.groupme.iphone-app": "GroupMe", "org.mozilla.ios.Firefox": "Firefox",
    "com.google.Dynamite": "Google Chat", "com.fitbit.FitbitMobile": "Fitbit", "co.babypenguin.imo": "imo",
    "com.atebits.Tweetie2": "X (Twitter)", "com.apple.Bridge": "Watch (Apple)", "com.apple.findmy": N_("Dov'è (Apple)"),
    "group.com.facebook.Messenger": "Messenger", "com.google.Maps": "Google Maps", "AlexisBarreyat.BeReal": "BeReal",
    "com.google.GVDialer": "Google Voice", "com.apple.podcasts": N_("Podcast (Apple)"), "com.apple.mobileslideshow.photo-picker": N_("Foto (Apple)"),
    "com.google.photos": N_("Google Foto"), "com.google.ios.youtube": "YouTube", "com.microsoft.skype.teams": "Microsoft Teams",
    "com.tinyspeck.chatlyio": "Slack", "com.life360.safetymap": "Life360", "com.zoomvideo.zoomios": "Zoom", "mega.ios": "MEGA",
    "ch.threema.iapp": "Threema", "com.wire": "Wire", "com.mewe.MeWeApp": "MeWe", "com.truthsocial.app": "Truth Social",
    # memorie di massa: Mac (identificativo nella Library dell'utente) e cartelle dei programmi di Windows e Linux
    "com.apple.Safari": "Safari", "com.apple.Photos": N_("Foto (Apple)"), "com.apple.iChat": N_("Messaggi (iMessage/SMS)"),
    "com.apple.mail": N_("Mail (Apple)"), "com.google.Chrome": "Chrome", "ru.keepcoder.Telegram": "Telegram",
    "Google Chrome": "Chrome", "Microsoft Edge": "Edge", "Mozilla Firefox": "Firefox", "Firefox": "Firefox",
    "BraveSoftware Brave-Browser": "Brave", "Opera Software Opera Stable": "Opera", "Telegram Desktop": "Telegram",
    "google-chrome": "Chrome", "mozilla": "Firefox", "chromium": "Chromium", "Microsoft Windows": "Windows",
    "Microsoft Teams": "Microsoft Teams", "Microsoft Outlook": "Outlook", "Microsoft Office": "Microsoft Office",
    "Microsoft.Windows.Photos": N_("Foto (Windows)"), "Microsoft.ScreenSketch": N_("Cattura e annota (Windows)"),
}
# iOS fuori dai contenitori delle app: solo i dati dell'utente (…/mobile/…); System/Library resta «Sistema»
RIGHE_IOS = ((re.compile(r"(^|/)mobile/Media/DCIM/"), "~dcim"), (re.compile(r"(^|/)mobile/Media/PhotoData/"), "~photodata"),
             (re.compile(r"(^|/)mobile/Library/SMS/Attachments/"), "com.apple.MobileSMS"),
             (re.compile(r"(^|/)mobile/Media/Recordings/"), "com.apple.VoiceMemos"),
             (re.compile(r"(^|/)mobile/Media/iTunes_Control/"), "~itunes"), (re.compile(r"(^|/)mobile/Library/Mail/"), "com.apple.mobilemail"),
             (re.compile(r"(^|/)mobile/(Library/Caches/CloudKit|Library/Application Support/CloudDocs|Library/Mobile Documents)/"), "~icloud"),
             (re.compile(r"(^|/)mobile/(Library/Photos/|Media/LoFiCloudAssets/)"), "com.apple.mobileslideshow"),
             (re.compile(r"(^|/)mobile/Media/Podcasts/"), "com.apple.podcasts"),
             (re.compile(r"(^|/)mobile/Library/UserNotifications/"), "~notifiche"))
AND_PKG = (re.compile(r"(?:^|/)data/(?:data|user/\d+|user_de/\d+)/([^/]+)/(.*)$"),
           re.compile(r"(?:^|/)data_mirror/data_(?:ce|de)/[^/]+/\d+/([^/]+)/(.*)$"),
           re.compile(r"(?:^|/)Android/(?:data|media|obb)/([^/]+)/(.*)$"))
AND_CONDIVISA = re.compile(r"(?:^|/)(?:media/\d+|sdcard|storage/emulated/\d+)/([^/]+)/(.*)$")
PKG_RE = re.compile(r"^[A-Za-z][\w]*(\.[\w-]+)+$")
# memorie di massa: cartella dell'utente (Windows, Mac, Linux) e cartelle note al suo interno
UTENTE_RE = re.compile(r"(?:^|/)(?:Users|Documents and Settings|home)/([^/]+)/(.+)$", re.I)
CARTELLE_UTENTE = {"pictures": "pictures", "immagini": "pictures", "my pictures": "pictures", "desktop": "desktop",
                   "scrivania": "desktop", "downloads": "download", "download": "download", "documents": "documents",
                   "documenti": "documents", "my documents": "documents", "videos": "movies", "movies": "movies",
                   "video": "movies", "my videos": "movies", "music": "music", "musica": "music", "my music": "music",
                   "onedrive": "onedrive", "dropbox": "dropbox", "google drive": "google drive", "icloud drive": "icloud"}
VENDOR = {"microsoft", "google", "mozilla", "apple", "apple computer", "adobe", "bravesoftware", "opera software",
          "packages"}
CESTINO_RE = re.compile(r"(?:^|/)(\$recycle\.bin|recycler|recycled|\.trashes|\.trash|\.local/share/trash)(?:/|$)", re.I)
SISTEMA_DISCO = {"windows", "winnt", "system", "library", "usr", "bin", "sbin", "lib", "etc", "var", "private", "boot",
                 "system volume information", "$extend", "recovery", "dev", "proc", "sys", "snap"}
PROGRAMMI_DISCO = {"program files", "program files (x86)", "programdata", "applications", "opt"}


def firma(h):
    """(tipo, formato) dai primi byte di un file; None se non è una foto, un video o un audio riconosciuto."""
    if h[:3] == b"\xff\xd8\xff":
        return "foto", "jpg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "foto", "png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "foto", "gif"
    if h[:4] == b"RIFF":
        return {b"WEBP": ("foto", "webp"), b"AVI ": ("video", "avi"), b"WAVE": ("audio", "wav")}.get(h[8:12])
    if h[4:8] == b"ftyp":
        b = h[8:12]
        if b in HEIF:
            return "foto", "avif" if b in (b"avif", b"avis") else "heic"
        if b in AUDIO_FTYP:
            return "audio", "m4a"
        return "video", "mov" if b == b"qt  " else "3gp" if b[:3] in (b"3gp", b"3g2") else "mp4"
    if h[:4] == b"\x1a\x45\xdf\xa3":
        return "video", "mkv"
    if h[:4] == b"OggS":
        return "audio", "ogg"
    if h[:6] == b"#!AMR\n" or h[:9] == b"#!AMR-WB\n":
        return "audio", "amr"
    if h[:3] == b"ID3":
        return "audio", "mp3"
    if h[:4] == b"fLaC":
        return "audio", "flac"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "foto", "tif"
    return None


AUDIO_MP4_EXT = {".m4a", ".m4b", ".m4r", ".aac", ".3ga", ".mp4a"}


def lettore(case):
    """Funzione (part, inode, n) -> (dimensione, primi n byte): estrazione del telefono o file system della copia forense."""
    import forense_agent as fa
    if fa.is_mobile(case):
        import forense_mobile as fm
        return lambda part, inode, n: fm.head_tail(case, part, inode, n)[:2]
    import forense_estesa as fe
    hr = fe.HeadReader(case)
    return lambda part, inode, n: hr.read(part, inode, n)[:2]


def riconosci(case, part, inode, ext, leggi=None):
    """(tipo, formato) di un file dal contenuto; i contenitori MP4 secondo la traccia (tipo_mp4)."""
    leggi = leggi or lettore(case)
    try:
        h = leggi(part, inode, 32)[1]
    except Exception:
        return None
    f = firma(h)
    if f and f[1] in ("mp4", "3gp", "mov"):
        try:
            hb = leggi(part, inode, 262144)[1] or h
        except Exception:
            hb = h
        if tipo_mp4(hb, ext) == "audio":
            f = ("audio", "m4a")
    return f


def tipo_mp4(testa, ext):
    """MP4/3GP/MOV generici («isom», «mp42», «3gp4»…) contengono video o solo audio (registrazioni, note vocali): decide
    la traccia. `testa` = primi 256 KB. Solo «soun» senza «vide» → audio; «vide» → video; senza tracce leggibili (indice
    in fondo al file) vale l'estensione audio, altrimenti video."""
    hs = any(testa[i + 8:i + 12] == b"soun" for i in _hdlr(testa))
    hv = any(testa[i + 8:i + 12] == b"vide" for i in _hdlr(testa))
    if hv or hs:
        return "video" if hv else "audio"
    return "audio" if ext in AUDIO_MP4_EXT else "video"


def _hdlr(b):
    """Posizioni dei box «hdlr» (il tipo di traccia è 8 byte dopo la parola hdlr: versione/flag e pre_defined)."""
    i = b.find(b"hdlr")
    while i >= 0:
        yield i + 4
        i = b.find(b"hdlr", i + 4)


def _area(resto):
    parti = [x.lower() for x in resto.split("/")[:-1]]
    return "cache" if any(x in CACHE_DIR or x.endswith("cache") or x.endswith("caches") for x in parti) else "app"


def proprietario(case, part, path, piattaforma):
    """(app, area): app = pacchetto o identificativo iOS, oppure «~cartella» per la memoria condivisa e il sistema;
    area = «cache», «app», «condivisa» o «sistema»."""
    import forense_mobile as fm
    p = path or ""
    if piattaforma == "ios":
        ident = fm.contenitore_ios(case, part, p)
        if ident:
            m = fm.IOS_CONT_RE.match(p)
            return ident, _area(p[len(m.group(1)) + 1:]) if m else "app"
        for rx, k in RIGHE_IOS:
            if rx.search(p):
                return k, ("cache" if k == "~photodata" or _area(p) == "cache" else "condivisa" if k.startswith("~") else "app")
        if "/mobile/" in p or "/Mobile/" in p:
            return "~altro", _area(p)
        return "~sistema", "sistema"
    for rx in AND_PKG:
        m = rx.search(p)
        if m and PKG_RE.match(m.group(1)):
            return m.group(1), _area(m.group(2))
    m = AND_CONDIVISA.search(p)
    if m:
        d = m.group(1).lower()
        if d in CARTELLE_APP:
            return CARTELLE_APP[d], _area(m.group(2))
        if d == "pictures" and m.group(2).lower().startswith("screenshots/"):
            return "~screenshots", "condivisa"
        if d in CONDIVISE:
            return "~" + d, "condivisa"
        return "~altro", "condivisa"
    if re.match(r"^(?:[^/]+/)?(system|vendor|product|apex|system_ext)/", p) or "/system/" in p or \
            re.search(r"(^|/)data/(system[^/]*|misc[^/]*|vendor[^/]*)/", p):
        return "~sistema", "sistema"
    return "~altro", _area(p)


def proprietario_disco(path):
    """(app, area) di un file di una memoria di massa: programma dalle cartelle dei dati dell'utente (AppData di Windows,
    Library del Mac, .cache/.config/.local/share di Linux), oppure «~cartella» (cartelle dell'utente, Temp, Cestino,
    Programmi, Sistema, Altre)."""
    p = path or ""
    if CESTINO_RE.search(p):
        return "~cestino", "condivisa"
    m = UTENTE_RE.search(p)
    if m:
        resto = m.group(2)
        parti = resto.split("/")
        low = [x.lower() for x in parti]
        if len(low) > 3 and low[0] == "appdata" and low[1] in ("local", "roaming", "locallow"):
            d = parti[2:]
            if low[2] == "temp":
                return "~temp", "cache"
            if low[2] in VENDOR and len(d) > 2:
                app = d[1].rsplit("_", 1)[0] if low[2] == "packages" else d[0] + " " + d[1]
                return app, _area("/".join(d[2:]))
            return d[0], _area("/".join(d[1:]))
        if len(low) > 3 and low[0] == "library" and low[1] in ("containers", "group containers", "caches",
                                                              "application support", "safari", "cookies"):
            if low[1] == "safari":
                return "com.apple.Safari", _area("/".join(parti[2:]))
            i = 3 if low[2] in VENDOR and len(parti) > 4 else 2           # Application Support/Google/Chrome/…
            app = parti[2] + " " + parti[3] if i == 3 else parti[2]
            return app, "cache" if low[1] == "caches" else _area("/".join(parti[i + 1:]))
        if len(low) > 2 and low[0] in (".cache", ".config", ".local") and not (low[0] == ".local" and low[1] != "share"):
            i = 2 if low[0] == ".local" else 1
            if len(parti) > i + 1:
                return parti[i], "cache" if low[0] == ".cache" else _area("/".join(parti[i + 1:]))
        if low[0] in ("temp", "tmp", "local settings") and len(low) > 1:
            return "~temp", "cache"
        if any(x.endswith(".photoslibrary") for x in low[:-1]):
            return "com.apple.Photos", "cache" if "derivatives" in low or "resources" in low else "app"
        if low[0] == "my documents" and len(low) > 2 and low[1] in CARTELLE_UTENTE:
            return "~" + CARTELLE_UTENTE[low[1]], "condivisa"
        if low[0] in CARTELLE_UTENTE and len(low) > 1:
            return "~" + CARTELLE_UTENTE[low[0]], "condivisa"
        return "~utente", _area(resto)
    primo = p.split("/")[0].lower()
    if primo in ("temp", "tmp") or re.search(r"(?:^|/)windows/temp/", p, re.I):
        return "~temp", "cache"
    if primo in PROGRAMMI_DISCO:
        return "~programmi", "sistema"
    if primo in SISTEMA_DISCO:
        return "~sistema", "sistema"
    return "~altro", _area(p)


# ---------------------------------------------------------------------------- cache dei browser Chromium

SIMPLE_INIZIO = struct.pack("<Q", 0xfcfb6d1ba7725c30)      # kSimpleInitialMagicNumber (net/disk_cache/simple)
SIMPLE_FINE = struct.pack("<Q", 0xf4fa6f45970d41d8)        # kSimpleFinalMagicNumber (record EOF)
SIMPLE_NOME = re.compile(r"^[0-9a-f]{16}_0$")
CHIAVE_RE = re.compile(r"^(?:\d+/\d+/)?(?:_dk_)?[A-Za-z][A-Za-z0-9+.\-]*:")      # «1/0/_dk_https://…» o «https://…»
CACHE_MAX = 200 << 20
STESSO_FORMATO = {"jpg": {".jpg", ".jpeg", ".jpe", ".jfif"}, "tif": {".tif", ".tiff"}, "heic": {".heic", ".heif"},
                  "mp4": {".mp4", ".m4v"}, "mkv": {".mkv", ".webm"}}
CACHE_SUB = "cache_web"


def voce_chromium(data):
    """Voce «_0» della Simple Cache di Chromium: (inizio, lunghezza, indirizzo web) del contenuto scaricato (stream 1),
    None se non lo è. Struttura: intestazione (24 byte; 20 nelle versioni a 32 bit), chiave, stream 1, record EOF,
    stream 0 (intestazioni HTTP), SHA-256 della chiave se il flag lo dice, record EOF finale (24 byte)."""
    n = len(data)
    if data[:8] != SIMPLE_INIZIO or n < 48:
        return None
    klen = struct.unpack_from("<I", data, 12)[0]
    fine = None
    if data[n - 24:n - 16] == SIMPLE_FINE:
        flags, _crc, s0 = struct.unpack_from("<III", data, n - 16)
        e1 = n - 24 - (32 if flags & 2 else 0) - s0 - 24
        if e1 > 0 and data[e1:e1 + 8] == SIMPLE_FINE:
            fine = e1
    for hdr in ((24, 20) if data[20:24] == b"\0\0\0\0" else (20,)):      # 24: con i 4 byte di riempimento a zero
        inizio = hdr + klen
        if inizio > n:
            continue
        chiave = data[hdr:inizio].decode("utf-8", "replace")
        if not CHIAVE_RE.match(chiave):
            continue
        e1 = fine if fine is not None and fine >= inizio else data.find(SIMPLE_FINE, inizio)
        if e1 < 0:
            e1 = n          # voce troncata: fino in fondo
        url = chiave.split()[-1] if chiave.split() else chiave
        return inizio, e1 - inizio, url[4:] if url.startswith("_dk_") else url
    return None


def nome_da_url(url, fmt):
    """Nome del file dall'indirizzo web, con l'estensione del formato riconosciuto."""
    try:
        base = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    except ValueError:
        base = ""
    base = re.sub(r"[^\w.\-]+", "_", base)[-100:].strip("._") or "cache"
    if Path(base).suffix.lower() not in STESSO_FORMATO.get(fmt, {"." + fmt}):
        base += "." + fmt           # es. «a.png» che contiene un JPEG → «a.png.jpg»
    return base


class CacheWeb:
    """Estrae le foto e i video dalle voci della cache dei browser Chromium tra i file estratti («cache_web»). Le voci
    già estratte in un'indicizzazione precedente restano con lo stesso numero (Preferiti, hash percettivi)."""

    def __init__(self, case, con):
        import forense_agent as fa
        import forense_estesa as fe
        self.case, self.con, self.fa, self.fe = case, con, fa, fe
        con.executescript(fe.SCHEMA[:fe.SCHEMA.index("CREATE TABLE IF NOT EXISTS mail")])
        self.prima = {(p, str(i)): (x, r, nm) for x, p, i, r, nm in con.execute(
            "SELECT id, part, inode, relpath, name FROM xitems WHERE kind = ?", (CACHE_SUB,))}
        self.visti, self.mapping = set(), {}
        self.tmp = Path(case.root) / "tmp_cache_web"
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.tmp.mkdir()
        if self.prima and fa.table_exists(con, "meta"):
            con.execute("DELETE FROM meta WHERE source = 'x' AND inode IN (SELECT CAST(id AS TEXT) FROM xitems WHERE kind = ?)",
                        (CACHE_SUB,))

    def voce(self, part, inode, path, deleted, leggi, mtime=None):
        """(tipo, formato, id dell'estratto, percorso mostrato, dimensione) se la voce contiene una foto o un video."""
        try:
            data = leggi(part, inode)
        except Exception:
            return None
        v = voce_chromium(data or b"")
        if not v:
            return None
        inizio, lung, url = v
        corpo = data[inizio:inizio + lung]
        f = firma(corpo[:32]) if len(corpo) >= MIN_BYTE else None
        if f and f[1] in ("mp4", "3gp", "mov") and tipo_mp4(corpo[:262144], "") == "audio":
            f = None
        if not f or f[0] not in ("foto", "video"):
            return None
        nome = nome_da_url(url, f[1])
        vpath = f"{path} › {nome}"             # come i file degli archivi: «contenitore › file»
        nota = tr("cache del browser: {url} (contenuto da 0x{off:X}, {n} byte, nel file d'origine)").format(url=url[:2000], off=inizio, n=lung)
        k = (part, str(inode))
        self.visti.add(k)
        old = self.prima.get(k)
        con, fe = self.con, self.fe
        if old and old[1] and old[2] == nome and (Path(self.case.root) / old[1]).exists():
            xid, rel = old[:2]
            con.execute("UPDATE xitems SET path=?, note=?, deleted=?, src_path=?, mtime=? WHERE id=?", (vpath, nota, deleted, path, mtime, xid))
        else:
            if old:                     # estratto mancante o nome cambiato: si rifà con lo stesso numero
                xid = old[0]
                self.togli_file(old[1])
                con.execute("UPDATE xitems SET path=?, name=?, note=?, deleted=?, src_path=?, mtime=? WHERE id=?",
                            (vpath, nome, nota, deleted, path, mtime, xid))
            else:
                xid = fe.new_xitem(con, kind=CACHE_SUB, part=part, inode=str(inode), src_path=path, path=vpath, name=nome,
                                   size=lung, note=nota, deleted=deleted, mtime=mtime)
            t = self.tmp / f"c_{xid}"
            t.write_bytes(corpo)
            n, md5, sha1, sha256 = fe.hashes_of(t)
            rel = fe.store_extracted(self.case, t, CACHE_SUB, xid, nome)
            con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, size=? WHERE id=?", (rel, md5, sha1, sha256, n, xid))
        self.mapping[str((Path(self.case.root) / rel).resolve())] = ("x", -1, str(xid), deleted, vpath)
        return f[0], f[1], xid, vpath, lung

    def togli_file(self, rel):
        if rel:
            f = Path(self.case.root) / rel
            try:
                f.chmod(0o644)
                f.unlink()
            except OSError:
                pass

    def chiudi(self, say=print):
        """Toglie gli estratti delle voci che non ci sono più e legge i metadati (exiftool) di quelli presenti."""
        con, fa = self.con, self.fa
        via = [(x, r) for k, (x, r, _n) in self.prima.items() if k not in self.visti]
        for x, r in via:
            con.execute("DELETE FROM xitems WHERE id=?", (x,))
            if fa.table_exists(con, "phash"):
                con.execute("DELETE FROM phash WHERE source = 'x' AND inode = ?", (str(x),))
            self.togli_file(r)
        shutil.rmtree(self.tmp, ignore_errors=True)
        con.commit()
        if not self.mapping or not fa.table_exists(con, "meta"):
            return
        say(tr("Metadati delle foto e dei video delle cache dei browser: {n}…").format(n=len(self.mapping)))
        fa.exif_run(con, Path(self.case.root) / self.fe.X_ROOT / CACHE_SUB, self.mapping)
        have = {i for (i,) in con.execute("SELECT inode FROM meta WHERE source = 'x'")}
        vuote = []
        for f, (_s, _p, xid, canc, vpath) in self.mapping.items():
            if xid not in have:
                fmt = Path(vpath).suffix.lower().lstrip(".")
                vuote.append((xid, canc, vpath, json.dumps({"RepertIA:Formato": FORMATI.get(fmt, fmt.upper())}, ensure_ascii=False)))
        con.executemany("INSERT INTO meta(source, part, inode, deleted, path, data) VALUES ('x', -1, ?, ?, ?, ?)", vuote)
        con.commit()


def etichetta(app):
    """Nome mostrato di un'app o di una cartella."""
    if not app:
        return tr("(non indicato)")
    if app.startswith("~"):
        return tr(CONDIVISE.get(app[1:], app[1:]))
    return tr(NOMI[app]) if app in NOMI else app


def run(case, con, say=print):
    """Scrive media_file e completa i metadati dei file riconosciuti solo dal contenuto. Restituisce il riepilogo."""
    import forense_agent as fa
    import forense_mobile as fm
    t0 = time.time()
    con.executescript(SCHEMA)
    con.execute("DELETE FROM media_file")
    plat = (case.meta.get("mobile") or {}).get("piattaforma")
    out = {"foto": 0, "video": 0, "audio": 0, "per_contenuto": 0, "per_estensione": 0, "cache": 0, "nuovi_metadati": 0,
           "cache_browser": 0}
    rows = []
    cw = CacheWeb(case, con)

    def aggiungi(part, i, path, size, tipo, fmt, metodo, app, area):
        rows.append((part, str(i), path, tipo, fmt, metodo, app, area, size))
        out[tipo] += 1
        out["per_" + metodo] += 1
        out["cache"] += area == "cache"
        if len(rows) >= 5000:
            con.executemany("INSERT INTO media_file VALUES (?,?,?,?,?,?,?,?,?)", rows)
            rows.clear()
    def da_cache(part, i, path, deleted, leggi, mtime=None):
        """Voce della cache di un browser Chromium con una foto o un video: riga dell'estratto (part -1)."""
        try:
            v = cw.voce(part, i, path, deleted, leggi, mtime)
        except Exception:               # (3.0.2) voce illeggibile (es. AD1 con tabella dei blocchi non valida): si salta
            return False
        if not v:
            return False
        app = proprietario(case, part, path, plat)[0] if fa.is_mobile(case) else proprietario_disco(path)[0]
        aggiungi(-1, v[2], v[3], v[4], v[0], v[1], "contenuto", app, "cache")
        out["cache_browser"] += 1
        return True
    if not fa.is_mobile(case):
        disco(case, con, say, aggiungi, da_cache)
    for s in (fm.sorgenti(case) if fa.is_mobile(case) else []):
        part = int(s["offset"])
        m = fm.mx(case)
        try:
            files = m.execute("SELECT id, path, size, mtime FROM mobile_files WHERE part=? AND isdir=0 AND link IS NULL AND size >= ?",
                              (part, MIN_BYTE)).fetchall()
        finally:
            m.close()
        say(tr("Foto, video e audio: esame del contenuto di {n} file…").format(n=len(files)))
        for k, (i, path, size, mtime) in enumerate(files, 1):
            ext = Path(path).suffix.lower()
            f = riconosci(case, part, i, ext)
            if not f and SIMPLE_NOME.match(Path(path).name) and size <= CACHE_MAX:
                da_cache(part, i, path, 0, lambda p, n: fa.icat_read(case, p, n, CACHE_MAX), mtime)
                continue
            if f:
                tipo, fmt, metodo = f[0], f[1], "contenuto"
            elif EXT_TIPO.get(ext):
                tipo, fmt, metodo = EXT_TIPO[ext], ext.lstrip("."), "estensione"
            else:
                continue
            app, area = proprietario(case, part, path, plat)
            aggiungi(part, i, path, size, tipo, fmt, metodo, app, area)
            if k % 20000 == 0:
                fa.avanz(fatti=k, totale=len(files))
                say(tr("  {k} di {n} file esaminati…").format(k=k, n=len(files)))
    con.executemany("INSERT INTO media_file VALUES (?,?,?,?,?,?,?,?,?)", rows)
    con.commit()
    cw.chiudi(say)
    out["nuovi_metadati"] = metadati(case, con, say)
    out["secondi"] = round(time.time() - t0)
    out["app"] = con.execute("SELECT COUNT(DISTINCT app) FROM media_file").fetchone()[0]
    say(tr("Foto {f}, video {v}, audio {a} ({c} riconosciuti dal contenuto, {e} dalla sola estensione, {k} nelle cache); "
           "app e cartelle: {n}.").format(f=out["foto"], v=out["video"], a=out["audio"], c=out["per_contenuto"],
                                          e=out["per_estensione"], k=out["cache"], n=out["app"]))
    if out["cache_browser"]:
        say(tr("Dalle cache dei browser (Chrome, Samsung Internet, Edge, …): {n} foto e video estratti.").format(n=out["cache_browser"]))
    case.log("media_contenuto", out)
    return out


def disco(case, con, say, aggiungi, da_cache=None):
    """Memorie di massa: i file del file system (come il controllo delle anomalie: prima quelli con il nome attuale, poi i
    cancellati; niente flussi ADS né file virtuali). Un cancellato riconosciuto SOLO dal contenuto entra se il contenuto
    letto è ancora il suo (verify_deleted «ok»)."""
    import forense_agent as fa
    import forense_estesa as fe
    hr = fe.HeadReader(case)

    def leggi(part, inode, n):
        return hr.read(part, inode, n)[:2]
    files = sorted(fe.fs_rows(con, "1=1"), key=lambda r: r[2] or 0)
    say(tr("Foto, video e audio: esame del contenuto di {n} file…").format(n=len(files)))
    seen = set()
    for k, (part, inode, deleted, path) in enumerate(files, 1):
        name = Path(path).name
        if ":" in name or (part, str(inode)) in seen:
            continue
        seen.add((part, str(inode)))
        ext = Path(name).suffix.lower()
        try:
            size, head = leggi(part, inode, 32)
        except Exception:
            size, head = None, b""
        f = None
        if da_cache and head[:8] == SIMPLE_INIZIO and SIMPLE_NOME.match(name) and (size or 0) <= CACHE_MAX:
            if not deleted or hr.verify_deleted(part, inode, name) == "ok":
                da_cache(part, inode, path, deleted, lambda p, i: fa.icat_read(case, p, i, CACHE_MAX), _mtime(hr, part, inode))
            continue
        if len(head) >= MIN_BYTE:
            f = riconosci(case, part, inode, ext, lambda p, i, n: (size, head) if n <= 32 else leggi(p, i, n))
        if f and deleted and EXT_TIPO.get(ext) != f[0] and hr.verify_deleted(part, inode, name) != "ok":
            f = None            # cancellato: il contenuto letto può essere di un altro file
        if f:
            tipo, fmt, metodo = f[0], f[1], "contenuto"
        elif EXT_TIPO.get(ext):
            tipo, fmt, metodo = EXT_TIPO[ext], ext.lstrip("."), "estensione"
        else:
            continue
        app, area = proprietario_disco(path)
        aggiungi(part, inode, path, size, tipo, fmt, metodo, app, area)
        if k % 20000 == 0:
            fa.avanz(fatti=k, totale=len(files))
            say(tr("  {k} di {n} file esaminati…").format(k=k, n=len(files)))


def _mtime(hr, part, inode):
    """Data di modifica (UTC, «AAAA-MM-GGThh:mm:ss») di un file del file system letto con pytsk3; None se non si legge."""
    try:
        fs = hr._fs(part)
        t = fs.open_meta(inode=int(str(inode).split("-")[0])).info.meta.mtime if fs is not None else 0
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) if t else None
    except Exception:
        return None


def metadati(case, con, say=print):
    """Metadati (exiftool) dei file di foto e video che non li hanno: copia temporanea con l'estensione del formato
    riconosciuto. Una riga anche senza metadati, con il formato, perché il file compaia nella sezione."""
    import forense_agent as fa
    if not fa.table_exists(con, "meta"):
        return 0
    have = {(p, str(i)) for p, i in con.execute("SELECT part, inode FROM meta")}
    todo = [r for r in con.execute("SELECT part, inode, path, formato, tipo, COALESCE((SELECT MIN(f.deleted) FROM files f "
                                   "WHERE f.part = media_file.part AND f.inode = media_file.inode), 0) FROM media_file "
                                   "WHERE tipo IN ('foto', 'video') AND part != -1")
            if (r[0], r[1]) not in have]
    if not todo:
        return 0
    say(tr("Metadati dei file riconosciuti dal contenuto: {n}…").format(n=len(todo)))
    tmp = Path(case.root) / "tmp_media"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    mapping, n = {}, 0

    def flush():
        nonlocal n
        if mapping:
            a, _g = fa.exif_run(con, tmp, mapping)
            n += a
        for x in mapping:
            Path(x).unlink(missing_ok=True)
        mapping.clear()
    try:
        for k, (part, inode, path, fmt, _tipo, canc) in enumerate(todo, 1):
            try:
                data = fa.icat_read(case, part, inode, fa.MAX_EXTRACT)
            except Exception:           # (3.0.2) file illeggibile dall'immagine: niente metadati, si va avanti
                continue
            if not data:
                continue
            f = tmp / f"{part}_{inode}.{fmt}"
            f.write_bytes(data)
            mapping[str(f.resolve())] = ("fs", part, inode, canc, path)
            if len(mapping) >= 200:
                flush()
                con.commit()
            if k % 2000 == 0:
                say(tr("  {k} di {n} file…").format(k=k, n=len(todo)))
        flush()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    have = {(p, str(i)) for p, i in con.execute("SELECT part, inode FROM meta")}
    vuote = [(part, inode, canc, path, json.dumps({"RepertIA:Formato": FORMATI.get(fmt, fmt.upper())}, ensure_ascii=False))
             for part, inode, path, fmt, _t, canc in todo if (part, inode) not in have]
    con.executemany("INSERT INTO meta(source, part, inode, deleted, path, data) VALUES ('fs', ?, ?, ?, ?, ?)", vuote)
    con.commit()
    return n + len(vuote)


# ---------------------------------------------------------------------------- interfaccia

def presente(con):
    return bool(con.execute("SELECT 1 FROM sqlite_master WHERE name='media_file'").fetchone())


def filtro(tipo, col_part="part", col_inode="inode", col_source=None):
    """Condizione SQL (senza parametri) per i file di un tipo («foto», «video», «audio») secondo media_file. Con
    `col_source` (tabella meta) anche le righe di altre fonti (carving, archivi, posta), che restano per estensione."""
    w = f"({col_part}, {col_inode}) IN (SELECT part, inode FROM media_file WHERE tipo = '{tipo}')"
    if col_source:
        col = col_source.rsplit(".", 1)[0] + ".path" if "." in col_source else "path"
        est = " OR ".join(f"lower({col}) LIKE '%{e}'" for e, t in sorted(EXT_TIPO.items()) if t == tipo)
        w = f"({col_source} = 'fs' AND {w} OR {col_source} IS NOT 'fs' AND ({est}))"
    return w


def per_app(con):
    """Conteggi per l'albero: {tipo: [[app, etichetta, n, n_cache], ...]} in ordine di numero."""
    out = {}
    for tipo, app, n, nc in con.execute("SELECT tipo, app, COUNT(*), SUM(area = 'cache') FROM media_file GROUP BY 1, 2 "
                                        "ORDER BY 3 DESC"):
        out.setdefault(tipo, []).append([app, etichetta(app), n, nc or 0])
    # memorie di massa: foto e video recuperati dal carving (fuori dal file system), per estensione
    if con.execute("SELECT 1 FROM sqlite_master WHERE name='meta'").fetchone():
        for tipo in ("foto", "video"):
            n = con.execute("SELECT COUNT(*) FROM meta WHERE source = 'carving' AND " + filtro(tipo, col_source="source")).fetchone()[0]
            if n:
                out.setdefault(tipo, []).append(["~carving", etichetta("~carving"), n, 0])
                out[tipo].sort(key=lambda x: -x[2])
    return out


def righe(con, rows):
    """Aggiunge alle righe di Foto/Video/Audio il tipo dal contenuto (`mtipo`), il formato, l'app o la cartella (`mapp`,
    `mapp_lbl`) e l'area («cache»…), per le miniature dei file senza estensione e la colonna App."""
    keys = [[r.get("part"), str(r.get("inode"))] for r in rows if r.get("inode") not in (None, "")]
    if not keys:
        return
    found = {(p, str(i)): (t, f, m, a, z) for p, i, t, f, m, a, z in con.execute(
        "SELECT part, inode, tipo, formato, metodo, app, area FROM media_file WHERE (part, inode) IN "
        "(SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))", (json.dumps(keys),))}
    for r in rows:
        if r.get("source") == "carving":       # memorie di massa: recuperati dal carving, tipo dall'estensione
            r.update(mtipo=EXT_TIPO.get(Path(r.get("path") or "").suffix.lower()), mapp="~carving", mapp_lbl=etichetta("~carving"))
            continue
        e = found.get((r.get("part"), str(r.get("inode"))))
        if e:
            r.update(mtipo=e[0], mformato=FORMATI.get(e[1], e[1].upper()), mmetodo=e[2], mapp=e[3], mapp_lbl=etichetta(e[3]),
                     marea=e[4])


# --------------------------------------------------------------------------------------------- agente IA

def agent_tools(case):
    """(3.0.1) Strumenti dell'agente sui media riconosciuti dal contenuto (tabella media_file), se il caso li ha."""
    import forense_agent as fa
    try:
        con = fa.db_ro(case)
        try:
            n = con.execute("SELECT COUNT(*) FROM media_file").fetchone()[0] if presente(con) else 0
        finally:
            con.close()
    except Exception:
        n = 0
    if not n:
        return []

    def _where(tipo, app, contains, metodo, area):
        w, a = ["1=1"], []
        if tipo:
            w.append("tipo = ?"); a.append(tipo.strip().lower())
        if app:
            w.append("app LIKE ? ESCAPE '\\'"); a.append(fa.like(app))
        if contains:
            w.append("path LIKE ? ESCAPE '\\'"); a.append(fa.like(contains))
        if metodo:
            w.append("metodo = ?"); a.append(metodo.strip().lower())
        if area:
            w.append("area = ?"); a.append(area.strip().lower())
        return " AND ".join(w), a

    def list_media(tipo: str = "", app: str = "", contains: str = "", metodo: str = "", area: str = "",
                   limit: int = 100, offset: int = 0) -> str:
        """Foto, video e audio del caso riconosciuti dal CONTENUTO (anche senza estensione o con estensioni delle cache,
        es. «.0», «.cnt», «.exo»), con formato vero, app o programma o cartella a cui appartengono e area (app, cache,
        condivisa). Ogni riga dice come leggere il file: offset e inode per file_exif, file_metadata, read_file_text;
        «estratto N» (foto e video dalla cache dei browser) per read_extracted.

        Args:
            tipo: foto, video o audio; vuoto per tutti
            app: parte del nome dell'app, del programma o della cartella (es. 'whatsapp', 'chrome', '~dcim'); vuoto per tutte
            contains: testo nel percorso
            metodo: contenuto (riconosciuto dalla firma) o estensione; vuoto per tutti
            area: app, cache o condivisa; vuoto per tutte
            limit: righe massime (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        w, a = _where(tipo, app, contains, metodo, area)
        con = fa.db_ro(case)
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM media_file WHERE {w}", a).fetchone()[0]
            rows = con.execute(f"SELECT part, inode, path, tipo, formato, metodo, app, area, size FROM media_file WHERE {w} "
                               "ORDER BY path LIMIT ? OFFSET ?", a + [max(1, min(int(limit), 300)), max(0, int(offset))]).fetchall()
        finally:
            con.close()
        out = []
        for p, i, path, t, f, m, ap, ar, z in rows:
            dove = tr("estratto {i}").format(i=i) if p == -1 else f"offset {p} inode {i}"
            out.append(f"- [{tr(VALORI.get(t, t))}] {path} | {FORMATI.get(f, (f or '?').upper())} | {tr(VALORI.get(m, m))} | "
                       f"{etichetta(ap)} ({ap or '-'}) | {tr(VALORI.get(ar, ar)) if ar else '-'} | {z} B | {dove}")
        return fa.pagina(out, tot, offset)

    def count_media(by: str = "app", tipo: str = "", app: str = "", metodo: str = "", area: str = "") -> str:
        """Conta foto, video e audio riconosciuti dal contenuto senza elencarli: da usare per primo.

        Args:
            by: app, tipo, formato, metodo o area
            tipo: foto, video o audio; vuoto per tutti
            app: parte del nome dell'app o della cartella; vuoto per tutte
            metodo: contenuto o estensione; vuoto per tutti
            area: app, cache o condivisa; vuoto per tutte
        """
        col = {"app": "app", "tipo": "tipo", "formato": "formato", "metodo": "metodo", "area": "area"}.get(str(by).strip().lower())
        if not col:
            return tr("Valori possibili per by: {v}").format(v="app, tipo, formato, metodo, area")
        w, a = _where(tipo, app, "", metodo, area)
        con = fa.db_ro(case)
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM media_file WHERE {w}", a).fetchone()[0]
            rows = con.execute(f"SELECT {col}, COUNT(*) FROM media_file WHERE {w} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 300", a).fetchall()
        finally:
            con.close()
        lbl = (lambda v: f"{etichetta(v)} ({v or '-'})") if col == "app" else (lambda v: tr(VALORI.get(v, v)) if v else "-")
        return fa.clip("\n".join([tr("{tot} file in {n} valori (ne sono elencati al massimo 300):").format(tot=tot, n=len(rows))]
                                 + [f"{lbl(v)}: {k}" for v, k in rows]))

    return [list_media, count_media]


def prompt_extra(case):
    """(3.0.1) Riga del prompt dell'agente sui media riconosciuti dal contenuto."""
    import forense_agent as fa
    try:
        con = fa.db_ro(case)
        try:
            r = con.execute("SELECT COUNT(*), SUM(metodo = 'contenuto'), SUM(area = 'cache') FROM media_file").fetchone() \
                if presente(con) else (0, 0, 0)
        finally:
            con.close()
    except Exception:
        r = (0, 0, 0)
    if not r[0]:
        return []
    return [tr("- Foto, video e audio riconosciuti dal contenuto: {n} file ({c} dalla firma, {k} nelle cache), con l'app o la "
               "cartella a cui appartengono: count_media, poi list_media. Molti non hanno l'estensione di una foto o di un "
               "video: find_files per estensione non li trova.").format(n=r[0], c=r[1] or 0, k=r[2] or 0)]
