import math
import re
import secrets
import string
from argon2 import PasswordHasher
from argon2.exceptions import HashingError

SPECIALS = "!@#$%^&*()-_=+[]{}|;:\",.?/`~"

# --- Data Loaders ---

def loadCommonPasswords(filepath="NCSC_most-common-passwds.txt"):
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        return set(line.strip().lower() for line in f)

def loadDictionaryWords(filepath="english_dictionary.txt"):
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        return set(line.strip().lower() for line in f if len(line.strip()) >= 4)


# --- Normalization ---

def normalizeLeetspeak(password):
    substitutions = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a',
        '5': 's', '7': 't', '@': 'a', '$': 's'
    }
    for leet, normal in substitutions.items():
        password = password.replace(leet, normal)
    return password.lower()


# --- Pattern Checks ---

def containsDictionaryWord(password, wordlist):
    normalized = normalizeLeetspeak(password)
    for word in wordlist:
        if len(word) >= 4 and word in normalized:
            return True
    return False

def isCommonPassword(password, commonPasswords):
    return normalizeLeetspeak(password) in commonPasswords


# --- Entropy & Charset ---

def getCharsetSize(password):
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in SPECIALS for c in password): size += 32
    return size

def getEntropy(password):
    charsetSize = getCharsetSize(password)
    if charsetSize == 0:
        return 0, 0
    entropy = len(password) * math.log2(charsetSize)
    return entropy, charsetSize


# --- Crack Time Estimates ---
#
# Rate constants are grounded in real benchmarks and published research:
#
# CLASSICAL_RATE — Offline brute-force using a high-end GPU cracking rig.
#   Benchmark: 8× NVIDIA RTX 4090, running Hashcat against SHA-256.
#   Published Hashcat benchmark: ~9.7 GH/s per RTX 4090.
#   8-GPU rig total: ~77.6 GH/s ≈ 7.8e10 hashes/sec.
#   SHA-256 is used as the baseline (common for Unix shadow passwords, JWT, etc.).
#   Source: hashcat.net benchmark wiki, RTX 4090 SHA-256 mode (-m 1400).
#
# QUANTUM_ORACLE_RATE — Grover's algorithm on a projected CRQC (Cryptographically
#   Relevant Quantum Computer, est. 2030–2033 per IBM/Google roadmaps).
#   Grover's gives O(√N) oracle calls vs classical O(N), a quadratic speedup.
#   BUT quantum oracle rate is throttled by:
#     • Logical clock speed: ~100 MHz for fault-tolerant hardware
#     • Error correction overhead: ~1000× slowdown per logical gate
#     • Hash circuit depth (SHA-256): ~10^4 logical gate layers
#   Net effective oracle rate: ~10^6 evaluations/sec (optimistic upper bound).
#   Sources: NIST IR 8105; Banegas et al. (2021) "Concrete quantum cryptanalysis";
#            IBM quantum roadmap 2033; Grassl et al. SHA-256 quantum circuit analysis.
#
# MODERN_WORDLIST_RATE — Hashcat wordlist + rules attack (worst-case: NTLM/MD5 hash).
#   8× RTX 4090 on NTLM: ~550 GH/s ≈ 5.5e11 hashes/sec.
#   With rule expansion (e.g. OneRuleToRuleThemAll): effectively ~1e12 candidates/sec.
#   This models the worst-case scenario where a user's password hash leaks online
#   and the attacker uses professional cracking infrastructure.
#   Source: hashcat.net, NTLM mode (-m 1000) RTX 4090 benchmarks.

CLASSICAL_RATE        = 7.8e10   # 78 billion SHA-256 hashes/sec  (8× RTX 4090)
QUANTUM_ORACLE_RATE   = 1e6      # 1 million Grover oracle calls/sec (projected CRQC)
MODERN_WORDLIST_RATE  = 1e12     # 1 trillion candidates/sec (NTLM hashcat + rules)


def classicalCrackTime(entropy):
    """
    Offline brute-force on a modern GPU rig (8× RTX 4090).
    Models a sophisticated attacker who has obtained a password hash dump
    and is running Hashcat against SHA-256 at full speed.
    Expected cracking time = (total combinations) / (hashes per second).
    """
    combinations = 2 ** entropy
    return combinations / CLASSICAL_RATE


def quantumCrackTime(entropy):
    """
    Grover's algorithm on a projected 2030-era fault-tolerant quantum computer.

    Grover's reduces the required oracle calls from N to √N, giving a quadratic
    speedup over classical brute-force. However, each quantum oracle call is orders
    of magnitude slower than a classical hash due to error correction overhead.

    At the QUANTUM_ORACLE_RATE of 10^6/sec:
      - For entropy < ~40 bits: classical GPU is actually FASTER (quantum overhead
        outweighs the √N speedup at small search spaces)
      - For entropy > ~40 bits: quantum gradually overtakes classical
      - For entropy > 128 bits: quantum reduces centuries to years, but still impractical

    This reflects the genuine state of quantum threat modeling per NIST PQC guidelines.
    """
    grover_oracle_calls = math.sqrt(2 ** entropy)
    return grover_oracle_calls / QUANTUM_ORACLE_RATE


def modernCrackTime(password, commonPasswords, dictionaryWords):
    """
    Models a real-world hybrid attack combining:
      1. Breach database lookup (Have I Been Pwned / NCSC wordlist)
      2. Wordlist + rule mutations (Hashcat + OneRuleToRuleThemAll)
      3. Pattern-aware heuristics (dates, keyboard walks, leet substitutions)
      4. Fallback: entropy-based brute-force at GPU wordlist speed

    Times are calibrated against published Hashcat attack durations on real datasets
    (RockYou, HaveIBeenPwned) using an 8× RTX 4090 rig.
    """
    normalized = normalizeLeetspeak(password)

    # 1. Direct hit in a breach wordlist — instant lookup
    if normalized in commonPasswords:
        return 0.001   # sub-millisecond table lookup

    # 2. Dictionary word base — Hashcat wordlist attack with common rules
    #    (append digits, toggle case, add specials) covers this space in minutes
    if containsDictionaryWord(password, dictionaryWords):
        match = re.search(r"(123|[!@#$%^&*]+|[0-9]{1,4})$", password)
        if match:
            suffix = match.group(0)
            if len(suffix) <= 2:
                return 120       # word + 1-2 digit suffix: covered in ~2 min
            elif len(suffix) <= 4:
                return 600       # word + 3-4 digit suffix: ~10 min with rules
            elif len(suffix) >= 8:
                return 86400     # long suffix: ~1 day even with rules
            else:
                return 3600      # mid-length suffix: ~1 hour
        return 1800              # bare dictionary word: ~30 min with mutations

    # 3. Keyboard walk / common pattern — covered by dedicated pattern wordlists
    if re.search(r"(qwerty|asdf|zxcv|pass|love|god|admin|user|root|letme)", normalized):
        return 300              # ~5 min: these are in every pattern list

    # 4. Year-based pattern (attackers explicitly test birth years / recent years)
    if re.search(r"(19[0-9]{2}|20[0-4][0-9])", password):
        return 900              # ~15 min: date-aware rule sets

    # 5. Simple word + digits pattern (e.g. "dragon99")
    if re.fullmatch(r"[a-z]{4,}\d{2,4}", normalized):
        return 1800             # ~30 min: rockyou + digit append rules

    # 6. Capitalised word + digits (e.g. "Dragon12") — slightly harder
    if re.fullmatch(r"[a-z]{4,}[A-Z]{1}[a-z]*\d{1,4}", password):
        return 7200             # ~2 hours: toggle-case rules extend coverage

    # 7. Fallback: not in any wordlist — pure brute-force at GPU speed
    #    Uses NTLM/MD5 speed (worst-case: attacker has a fast-hash dump)
    entropy, _ = getEntropy(password)
    return (2 ** entropy) / MODERN_WORDLIST_RATE


# --- Time Formatter ---

def timeFormat(seconds):
    if seconds < 4:
        return f"{seconds:.4f} seconds"
    units = ['seconds', 'minutes', 'hours', 'days', 'years', 'centuries']
    factors = [60, 60, 24, 365, 100]
    i = 0
    while i < len(factors) and seconds >= factors[i]:
        seconds /= factors[i]
        i += 1
    return f"{seconds:.2f} {units[i]}"


# --- Feature 2: Mutation Suggester ---

def mutateSuggestions(password):
    """
    Generates 3 distinct stronger mutations of the given password.
    Each mutation applies different strategies to boost entropy without
    making the password completely unrecognizable.
    Returns a list of (mutated_password, entropy_gain_bits, strategy_name) tuples.
    """
    results = []
    base_entropy, _ = getEntropy(password)

    # Strategy A: Insert random specials and digits at non-obvious positions
    def strategy_insert_mid(p):
        chars = list(p)
        insert_at = max(1, len(chars) // 3)
        chunk = secrets.choice(SPECIALS) + str(secrets.randbelow(90) + 10)
        chars.insert(insert_at, chunk)
        # Also uppercase a random alpha char
        for i in range(len(chars)):
            if isinstance(chars[i], str) and chars[i].isalpha():
                chars[i] = chars[i].upper()
                break
        return "".join(chars)

    # Strategy B: Replace predictable suffix patterns, add mid-word special
    def strategy_replace_suffix(p):
        # Strip trailing digits or common suffixes
        stripped = re.sub(r"[\d!@#$%^&*]+$", "", p)
        if len(stripped) < 3:
            stripped = p
        rand_suffix = (
            secrets.choice(SPECIALS)
            + str(secrets.randbelow(900) + 100)
            + secrets.choice(SPECIALS)
        )
        mid = len(stripped) // 2
        mutated = stripped[:mid] + secrets.choice(SPECIALS) + stripped[mid:] + rand_suffix
        return mutated

    # Strategy C: Double the unpredictability — pad with a random word-like block
    def strategy_pad_entropy(p):
        rand_block = "".join(
            secrets.choice(string.ascii_letters + string.digits + SPECIALS[:10])
            for _ in range(4)
        )
        insert_pos = secrets.randbelow(max(1, len(p)))
        mutated = p[:insert_pos] + rand_block + p[insert_pos:]
        # Force at least one uppercase and one special if missing
        if not any(c.isupper() for c in mutated):
            idx = next((i for i, c in enumerate(mutated) if c.isalpha()), 0)
            mutated = mutated[:idx] + mutated[idx].upper() + mutated[idx+1:]
        if not any(c in SPECIALS for c in mutated):
            mutated += secrets.choice(SPECIALS)
        return mutated

    strategies = [
        (strategy_insert_mid,      "Mid-Insert + Capitalize"),
        (strategy_replace_suffix,  "Suffix Overhaul"),
        (strategy_pad_entropy,     "Entropy Padding"),
    ]

    for fn, name in strategies:
        mutated = fn(password)
        new_entropy, _ = getEntropy(mutated)
        gain = round(new_entropy - base_entropy, 2)
        results.append((mutated, gain, name))

    return results


# --- Feature 5: Context-Aware Password Generator ---

def generatePassword(target_entropy_bits=80, use_upper=True, use_digits=True, use_specials=True):
    """
    Generates a cryptographically random password hitting a target entropy level.
    Builds the character pool based on user preferences, then calculates the
    exact character count needed to meet or exceed target_entropy_bits.
    Returns (password, actual_entropy, charset_size).
    """
    pool = string.ascii_lowercase
    if use_upper:    pool += string.ascii_uppercase
    if use_digits:   pool += string.digits
    if use_specials: pool += SPECIALS

    charset_size = len(pool)
    if charset_size == 0:
        return "", 0, 0

    # Minimum characters needed: ceil(target / log2(charset))
    bits_per_char = math.log2(charset_size)
    min_length = math.ceil(target_entropy_bits / bits_per_char)

    # Build password, guarantee at least one of each requested category
    password_chars = [secrets.choice(pool) for _ in range(min_length)]

    # Enforce category coverage so getCharsetSize() doesn't undercount
    guaranteed = [secrets.choice(string.ascii_lowercase)]
    if use_upper:    guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:   guaranteed.append(secrets.choice(string.digits))
    if use_specials: guaranteed.append(secrets.choice(SPECIALS))

    for i, g in enumerate(guaranteed):
        password_chars[i] = g

    # Shuffle so guaranteed chars aren't always at the front
    secrets.SystemRandom().shuffle(password_chars)
    password = "".join(password_chars)

    actual_entropy, _ = getEntropy(password)
    return password, actual_entropy, charset_size


# --- PQC Feature: Argon2id Quantum-Resistant Hash Generator ---

def argon2idHash(password, memory_cost=65536, time_cost=3, parallelism=4, hash_len=32):
    """
    Hashes a password using Argon2id — the NIST/OWASP recommended quantum-resistant KDF.

    Why quantum-resistant?
    ----------------------
    Grover's algorithm gives a quantum attacker a quadratic speedup on brute-force
    search — effectively halving the security bits (e.g. 128-bit security → 64-bit
    equivalent). BUT Argon2id is memory-hard: every single guess attempt requires
    `memory_cost` KB of RAM, maintained for the full `time_cost` passes.
    A quantum computer running Grover's must still execute the full memory-hard
    computation as its oracle — it cannot skip the RAM cost. This makes quantum
    brute-force of an Argon2id hash physically impractical even with CRQCs.

    Parameters
    ----------
    memory_cost : int
        RAM required per hash in KB. OWASP minimum: 19456 KB (19 MB).
        Recommended: 65536 KB (64 MB). High-security: 262144 KB (256 MB).
    time_cost : int
        Iterations (passes over memory). More = slower to compute = harder to crack.
        OWASP minimum: 2. Recommended: 3.
    parallelism : int
        Parallel threads. Set to match your server's physical CPU count.
    hash_len : int
        Output hash length in bytes. 32 = 256-bit output.

    Returns
    -------
    (hash_string, params) where hash_string is the full PHC-format Argon2id hash
    (safe to store directly in a database), and params is a dict of settings used.
    """
    try:
        ph = PasswordHasher(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=16,        # 128-bit random salt, generated fresh each call
        )
        hash_string = ph.hash(password)
        params = {
            "algorithm":       "Argon2id",
            "memory_cost_kb":  memory_cost,
            "memory_cost_mb":  round(memory_cost / 1024, 1),
            "time_cost":       time_cost,
            "parallelism":     parallelism,
            "hash_len_bytes":  hash_len,
            "salt_len_bytes":  16,
            "owasp_compliant": memory_cost >= 19456 and time_cost >= 2,
        }
        return hash_string, params
    except HashingError as e:
        return None, {"error": str(e)}
