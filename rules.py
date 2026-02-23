# ══════════════════════════════════════════════════════════════════════
#  NetWatch — Fichier de Règles de Détection
#  Modifiez ce fichier pour personnaliser la détection des paquets suspects
# ══════════════════════════════════════════════════════════════════════

# ─── Ports considérés comme sensibles / dangereux ─────────────────────
SUSPICIOUS_PORTS = {
    22,     # SSH
    23,     # Telnet (non chiffré, dangereux)
    3389,   # RDP — Bureau à distance Windows
    445,    # SMB — Partage de fichiers Windows
    1433,   # Microsoft SQL Server
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    8080,   # HTTP alternatif (souvent mal sécurisé)
    4444,   # Port favori des reverse shells (Metasploit)
    1337,   # Port utilisé par certains malwares
    31337,  # Port "élite" utilisé par des backdoors
}

# ─── Flags TCP considérés comme suspects ──────────────────────────────
SUSPICIOUS_FLAGS = [
    "S",      # SYN seul → scan de port possible
    "SF",     # SYN + FIN → comportement anormal
    "RSTO",   # Reset forcé → comportement anormal
    "FPU",    # FIN + PUSH + URG → Xmas scan
    "SFPU",   # SYN + FIN + PUSH + URG → scan agressif
]

# ─── IPs toujours bloquées (blacklist) ────────────────────────────────
BLACKLISTED_IPS = {
    # Ajoutez ici des IPs suspectes connues
    # Exemple : "192.168.1.99",
}

# ─── IPs toujours autorisées (whitelist) ──────────────────────────────
WHITELISTED_IPS = {
    "127.0.0.1",    # Loopback local
    "::1",          # Loopback IPv6
}

# ─── Taille de paquet suspecte (en octets) ────────────────────────────
MAX_SUSPICIOUS_SIZE = 65000   # Paquet anormalement grand

# ══════════════════════════════════════════════════════════════════════
#  Fonction principale de détection — Ne pas modifier sauf si vous
#  souhaitez ajouter de nouvelles logiques de détection
# ══════════════════════════════════════════════════════════════════════

def is_suspicious(pkt_info):
    """
    Analyse un paquet et retourne la liste des raisons de suspicion.
    Retourne une liste vide si le paquet est considéré comme normal.
    """
    reasons = []

    src = pkt_info.get("src", "")
    dst = pkt_info.get("dst", "")

    # Ignorer les IPs whitelistées
    if src in WHITELISTED_IPS or dst in WHITELISTED_IPS:
        return []

    # Vérification blacklist
    if src in BLACKLISTED_IPS:
        reasons.append(f"IP source blacklistée: {src}")
    if dst in BLACKLISTED_IPS:
        reasons.append(f"IP destination blacklistée: {dst}")

    # Vérification ports destination
    dport = pkt_info.get("dport")
    if dport in SUSPICIOUS_PORTS:
        reasons.append(f"Port destination sensible: {dport}")

    # Vérification ports source
    sport = pkt_info.get("sport")
    if sport in SUSPICIOUS_PORTS:
        reasons.append(f"Port source sensible: {sport}")

    # Vérification flags TCP
    flags = pkt_info.get("flags")
    if flags in SUSPICIOUS_FLAGS:
        reasons.append(f"Flag TCP suspect: {flags}")

    # Vérification taille du paquet
    length = pkt_info.get("length", 0)
    if length > MAX_SUSPICIOUS_SIZE:
        reasons.append(f"Paquet anormalement grand: {length} octets")

    return reasons
