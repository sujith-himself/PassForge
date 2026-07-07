# 🔐 PassForge — Password Strength Analyzer with a lil touch of PQC

> **Analyze, mutate, and generate cryptographically strong passwords — with quantum threat modeling built in.**

PassForge is a **Streamlit web application** that goes beyond simple password strength meters. It checks your password against real breach databases, estimates crack times against three distinct attacker models (including projected 2030-era quantum computers), suggests smarter mutations, generates entropy-guaranteed passwords, and hashes them with the NIST/OWASP gold-standard KDF — all in one tool.

---

## 📁 Project Structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI — 3-tab web interface |
| `passforge_core.py` | All core logic — entropy, cracking estimates, mutation, hashing |
| `NCSC_most-common-passwds.txt` | NCSC breach wordlist (~100k most common passwords) |
| `english_dictionary.txt` | English dictionary (~370k words) for pattern detection |

---

## 🚀 Getting Started

### 1. Install Dependencies

```bash
pip install streamlit argon2-cffi
```

### 2. Run the App

```bash
cd quantum-password-strength-analyzer
python -m streamlit run app.py
```

> **Note for Windows users:** Use `python -m streamlit run app.py` instead of the bare `streamlit` command — it's more reliable when `streamlit` isn't added to your system PATH.

The app will open in your browser at `http://localhost:8501`.

---

## 🧠 Features — 3 Tabs

### Tab 1 · 🔍 Analyze & Mutate

Enter any password and get a full security breakdown:

- **Breach detection** — checks against the NCSC wordlist of most commonly used passwords
- **Dictionary word detection** — catches embedded words even through leetspeak substitutions (e.g. `p@ssw0rd` → `password`)
- **Entropy & charset analysis** — shows bits of entropy and character pool size
- **Estimated crack times** against three real-world attacker models:

  | Attacker Model | Details |
  |---|---|
  | 🖥️ **Classical GPU** | 8× NVIDIA RTX 4090 running Hashcat on SHA-256 at ~78 GH/s |
  | ⚛️ **Quantum (Grover's)** | Projected 2030 CRQC at ~1M oracle calls/sec (NIST IR 8105) |
  | ⚙️ **Modern Hybrid** | Hashcat + wordlist + rules (NTLM) at ~1 trillion candidates/sec |

- **3 Mutation Suggestions** — stronger variants of your password, each using a different strategy:
  - **Mid-Insert + Capitalize** — injects a special character and digit at a non-obvious position
  - **Suffix Overhaul** — strips predictable suffixes and replaces with a randomized one
  - **Entropy Padding** — inserts a random block of characters mid-password

---

### Tab 2 · 🎲 Password Generator

Generate a cryptographically random password guaranteed to hit your target entropy:

- Set a **target entropy** anywhere from **40 to 256 bits**
- Toggle character classes: uppercase, digits, symbols
- The app calculates the **exact length needed** and generates using Python's `secrets` module (CSPRNG — safe for real use)
- Instantly shows a **full crack-time analysis** of the generated password

---

### Tab 3 · 🔒 Argon2id Hash Generator

Hash any password using **Argon2id** — the winner of the Password Hashing Competition (2015) and now recommended by **NIST SP 800-63B** and **OWASP** as the gold standard for password storage.

**Configurable parameters:**
- **Memory Cost** — RAM required per hash attempt (19 MB to 512 MB)
- **Iterations** — number of passes over memory
- **Parallelism** — number of threads
- **Hash Output Length** — 16, 32, or 64 bytes

**Live OWASP compliance check** — the UI flags whether your chosen parameters meet OWASP minimums (≥19 MB memory, ≥2 iterations).

**Output is in PHC string format** — self-describing, embeds the salt, ready to store directly in a database. No separate salt column needed.

**Ready-to-use code snippets** for Python (`argon2-cffi`) and Node.js (`argon2` package) are generated with your exact parameters.

---

## ⚛️ Why Argon2id Resists Quantum Attacks

Grover's algorithm gives a quantum computer a **quadratic speedup** over classical brute-force — effectively halving the security bits of any hash. SHA-256's 256-bit security drops to ~128-bit quantum security.

Argon2id defeats this through **memory-hardness**:

- Every single Grover oracle call must execute a **full Argon2id computation**
- That means allocating `memory_cost` KB of RAM *per guess attempt*
- Quantum parallelism **cannot collapse** these sequential, memory-dependent steps
- A 64 MB memory cost means a quantum attacker attempting 1 billion guesses/sec would need **64 petabytes of RAM** active simultaneously — physically impossible

> Argon2id's security comes from *thermodynamics*, not just math. It remains quantum-resistant as long as the memory cost stays infeasible to parallelize at scale.

---

## 🔬 Crack Time Methodology

All crack time estimates are grounded in real benchmarks and published research:

| Model | Rate | Source |
|---|---|---|
| Classical | 7.8 × 10¹⁰ hashes/sec | Hashcat RTX 4090 SHA-256 benchmark (`-m 1400`) |
| Quantum | 1 × 10⁶ oracle calls/sec | NIST IR 8105; Banegas et al. (2021); IBM quantum roadmap |
| Modern Hybrid | 1 × 10¹² candidates/sec | Hashcat NTLM benchmark + OneRuleToRuleThemAll rule set |

All times assume an **offline attack** against a leaked hash dump — the worst-case scenario for a user.

---

## 📦 Dependencies

```
streamlit
argon2-cffi
```

Both are installable via `pip`. No other external dependencies required.

---

## ⚠️ Disclaimer

Mutations and generated passwords are shown in plaintext for comparison purposes only. This tool is intended for **educational and security awareness** use. Do not use mutation suggestions as-is without reviewing them.
