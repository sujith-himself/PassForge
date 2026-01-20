import streamlit as st

st.set_page_config(
    page_title="PassForge — Password Strength Analyzer",
    page_icon="🔐",
    layout="centered"
)

# ── Imports ──────────────────────────────────────────────────────────────────
from passforge_core import (
    loadCommonPasswords,
    loadDictionaryWords,
    normalizeLeetspeak,
    isCommonPassword,
    containsDictionaryWord,
    getEntropy,
    getCharsetSize,
    classicalCrackTime,
    quantumCrackTime,
    modernCrackTime,
    timeFormat,
    mutateSuggestions,
    generatePassword,
    argon2idHash,
)

# ── Global Styles ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Mutation card */
.mutation-card {
    background: linear-gradient(135deg, #1e1e2e 0%, #16213e 100%);
    border: 1px solid #3d5a80;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 12px;
}
.mutation-card .strategy {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #7eb8f7;
    margin-bottom: 6px;
}
.mutation-card .password-text {
    font-family: 'Courier New', monospace;
    font-size: 1.05rem;
    color: #e2e8f0;
    background: #0d0d1a;
    border-radius: 6px;
    padding: 6px 10px;
    margin-bottom: 8px;
    word-break: break-all;
}
.mutation-card .gain-badge {
    display: inline-block;
    background: #22543d;
    color: #68d391;
    border-radius: 20px;
    padding: 2px 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

/* Generated password display */
.gen-display {
    background: #0d0d1a;
    border: 1px solid #4a5568;
    border-radius: 10px;
    font-family: 'Courier New', monospace;
    font-size: 1.1rem;
    color: #90cdf4;
    padding: 14px 18px;
    word-break: break-all;
    letter-spacing: 0.04em;
}

/* Section headers */
.section-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #e2e8f0;
    margin-bottom: 4px;
}

/* Argon2id hash output */
.hash-output {
    background: #0a0a14;
    border: 1px solid #2d6a4f;
    border-radius: 10px;
    font-family: 'Courier New', monospace;
    font-size: 0.82rem;
    color: #52b788;
    padding: 14px 16px;
    word-break: break-all;
    line-height: 1.7;
    margin: 8px 0;
}

/* Param badge row */
.param-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 10px 0;
}
.param-badge {
    background: #1a2634;
    border: 1px solid #2c4a6e;
    border-radius: 6px;
    padding: 4px 12px;
    font-size: 0.78rem;
    color: #90cdf4;
    font-weight: 600;
}
.owasp-ok  { border-color: #276749; color: #68d391; background: #1a2e23; }
.owasp-bad { border-color: #742a2a; color: #fc8181; background: #2d1515; }

/* Explainer box */
.explainer {
    background: #111827;
    border-left: 3px solid #4299e1;
    border-radius: 0 8px 8px 0;
    padding: 12px 16px;
    margin: 10px 0;
    font-size: 0.88rem;
    color: #cbd5e0;
    line-height: 1.7;
}
</style>
""", unsafe_allow_html=True)


# ── Load Word Lists (cached) ──────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def loadLists():
    return (
        loadCommonPasswords("NCSC_most-common-passwds.txt"),
        loadDictionaryWords("english_dictionary.txt"),
    )

with st.spinner("Loading wordlists..."):
    commonPasswords, dictionaryWords = loadLists()


# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔐 PassForge")
st.caption("Analyze, mutate, and generate cryptographically strong passwords.")
st.markdown("---")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB LAYOUT
# ═══════════════════════════════════════════════════════════════════════════════
tab_analyze, tab_generate, tab_hash = st.tabs([
    "🔍 Analyze & Mutate",
    "🎲 Password Generator",
    "🔒 Argon2id Hash",
])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: ANALYZE + MUTATION SUGGESTER
# ─────────────────────────────────────────────────────────────────────────────
with tab_analyze:
    password = st.text_input(
        "Enter a password to analyze:",
        type="password",
        placeholder="Type your password here…",
        key="analyze_input"
    )

    if st.button("🔍 Analyze", use_container_width=True, key="analyze_btn") and password:
        with st.spinner("Analyzing..."):
            st.markdown("---")

            # ── Verdict ──────────────────────────────────────────────────────
            normalized = normalizeLeetspeak(password)
            if isCommonPassword(password, commonPasswords):
                st.error("⚠️ **Very common password** — found in breach wordlists. Cracked instantly.")
            elif containsDictionaryWord(password, dictionaryWords):
                st.warning("📖 **Contains a dictionary word** — guessable with wordlist attacks.")
            else:
                st.success("✅ No common password or dictionary patterns detected.")

            # ── Metrics ──────────────────────────────────────────────────────
            entropy, charset = getEntropy(password)
            classical = classicalCrackTime(entropy)
            quantum   = quantumCrackTime(entropy)
            modern    = modernCrackTime(password, commonPasswords, dictionaryWords)
            strength  = min(int(entropy / 1.5), 100)

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### 🔤 Charset & Entropy")
                st.metric("Charset Size", f"{charset} chars")
                st.metric("Entropy", f"{entropy:.2f} bits")
                st.markdown("**Strength**")
                st.progress(strength)

            with col2:
                st.markdown("#### ⏱️ Estimated Crack Times")
                st.info(f"🖥️ **8× RTX 4090 (SHA-256, offline):** `{timeFormat(classical)}`")
                st.info(f"⚛️ **CRQC via Grover's (2030 est.):** `{timeFormat(quantum)}`")
                st.info(f"⚙️ **Hashcat + wordlist (NTLM, worst-case):** `{timeFormat(modern)}`")

            st.caption(
                "Classical: 8× RTX 4090 at 78 GH/s SHA-256. "
                "Quantum: projected CRQC at ~1M oracle calls/sec (NIST IR 8105). "
                "Modern: Hashcat wordlist + rules at 1T candidates/sec (NTLM). "
                "All times assume offline attack against a leaked hash dump."
            )

            # ── Feature 2: Mutation Suggester ─────────────────────────────────
            st.markdown("---")
            st.markdown("### 🧬 Mutation Suggestions")
            st.markdown(
                "Three stronger variants of your password — same structure, harder to crack."
            )

            mutations = mutateSuggestions(password)
            for mutated, gain, strategy in mutations:
                mut_entropy, _ = getEntropy(mutated)
                gain_str = f"+{gain:.1f} bits" if gain >= 0 else f"{gain:.1f} bits"
                st.markdown(f"""
<div class="mutation-card">
    <div class="strategy">Strategy: {strategy}</div>
    <div class="password-text">{mutated}</div>
    <span class="gain-badge">Entropy: {mut_entropy:.1f} bits &nbsp;|&nbsp; Gain: {gain_str}</span>
</div>
""", unsafe_allow_html=True)

            st.caption("⚠️ Mutations are shown in plaintext for comparison. Do not use them as-is without reviewing.")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: PASSWORD GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
with tab_generate:
    st.markdown("### 🎲 Context-Aware Password Generator")
    st.markdown(
        "Generates a **cryptographically random** password guaranteed to meet "
        "your chosen entropy target. Tweak the settings below."
    )

    col_a, col_b = st.columns([2, 1])

    with col_a:
        target_entropy = st.slider(
            "Target Entropy (bits)",
            min_value=40,
            max_value=256,
            value=80,
            step=8,
            help="Higher = harder to crack. 80 bits is very strong. 128+ is effectively uncrackable."
        )

    with col_b:
        use_upper    = st.checkbox("Uppercase (A–Z)", value=True)
        use_digits   = st.checkbox("Digits (0–9)",    value=True)
        use_specials = st.checkbox("Symbols (!@#…)",  value=True)

    # Entropy preview
    import math, string as _str
    SPECIALS_PREVIEW = "!@#$%^&*()-_=+[]{}|;:\",.?/`~"
    preview_pool_size = 26
    if use_upper:    preview_pool_size += 26
    if use_digits:   preview_pool_size += 10
    if use_specials: preview_pool_size += len(SPECIALS_PREVIEW)
    if preview_pool_size > 0:
        bits_per_char = math.log2(preview_pool_size)
        est_length    = math.ceil(target_entropy / bits_per_char)
        st.caption(f"Estimated password length: **{est_length} characters** at {bits_per_char:.2f} bits/char")

    if st.button("⚡ Generate Password", use_container_width=True, key="gen_btn"):
        gen_pass, actual_entropy, cset = generatePassword(
            target_entropy_bits=target_entropy,
            use_upper=use_upper,
            use_digits=use_digits,
            use_specials=use_specials,
        )

        st.markdown("#### Generated Password")
        st.markdown(f'<div class="gen-display">{gen_pass}</div>', unsafe_allow_html=True)
        st.code(gen_pass, language=None)   # copyable fallback

        st.markdown("---")
        st.markdown("#### Analysis of Generated Password")

        g_entropy, g_charset = getEntropy(gen_pass)
        g_classical = classicalCrackTime(g_entropy)
        g_quantum   = quantumCrackTime(g_entropy)
        g_modern    = modernCrackTime(gen_pass, commonPasswords, dictionaryWords)
        g_strength  = min(int(g_entropy / 1.5), 100)

        gcol1, gcol2 = st.columns(2)
        with gcol1:
            st.metric("Charset Size", f"{g_charset} chars")
            st.metric("Actual Entropy", f"{g_entropy:.2f} bits")
            st.markdown("**Strength**")
            st.progress(g_strength)
        with gcol2:
            st.info(f"🖥️ **Classical:** `{timeFormat(g_classical)}`")
            st.info(f"⚛️ **Quantum:** `{timeFormat(g_quantum)}`")
            st.info(f"⚙️ **Modern:** `{timeFormat(g_modern)}`")

        st.success(
            f"✅ Target was **{target_entropy} bits** — generated password achieves **{g_entropy:.1f} bits**."
        )
        st.caption("Generated using Python's `secrets` module (CSPRNG). Safe for real use.")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: ARGON2ID QUANTUM-RESISTANT HASH GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
with tab_hash:
    st.markdown("### 🔒 Argon2id — Quantum-Resistant Password Hashing")

    # ── What is Argon2id? ──────────────────────────────────────────────────
    st.markdown("""
<div class="explainer">
<strong>What is Argon2id?</strong><br>
Argon2id is the winner of the <a href="https://www.password-hashing.net/" style="color:#90cdf4">Password Hashing Competition (2015)</a>
and is now recommended by <strong>NIST SP 800-63B</strong> and <strong>OWASP</strong> as the gold standard
for storing passwords. It is a <em>Key Derivation Function (KDF)</em>, not just a hash — it is
deliberately slow and memory-hungry so that brute-forcing it is economically infeasible.
</div>
""", unsafe_allow_html=True)

    # ── Why quantum-resistant? ────────────────────────────────────────────
    with st.expander("⚛️ Why does Argon2id resist quantum attacks?", expanded=True):
        st.markdown("""
**The problem with Grover's algorithm:**  
Grover's algorithm gives a quantum computer a **quadratic speedup** over classical brute-force —
effectively **halving** the security bits of any hash. So SHA-256 (256 bits) drops to ~128-bit
quantum security. For a simple hash like MD5 or bcrypt, this is a serious threat.

**Why memory-hardness defeats Grover's:**  
Grover's works by running the hash function as a *quantum oracle* millions of times in superposition.
But each oracle call must still execute the **full Argon2id computation** — meaning:
- 🏗️ It must allocate `memory_cost` KB of RAM *per guess attempt*
- 🔄 It must complete all `time_cost` passes over that memory
- ⚡ Quantum parallelism cannot collapse these sequential, memory-dependent steps

A 64 MB memory cost means a quantum attacker attempting 1 billion guesses/sec would need
**64 petabytes of RAM** active simultaneously. That's physically impossible — not just computationally expensive.

**The result:** Argon2id's security comes from *thermodynamics*, not just math. It remains
quantum-resistant as long as the memory cost stays infeasible to parallelize at scale.
        """)

    st.markdown("---")
    st.markdown("#### ⚙️ Configure Hash Parameters")

    hcol1, hcol2 = st.columns(2)

    with hcol1:
        memory_mb = st.select_slider(
            "Memory Cost",
            options=[19, 32, 64, 128, 256, 512],
            value=64,
            format_func=lambda x: f"{x} MB",
            help="RAM required per hash attempt. OWASP min: 19 MB. Higher = harder to brute-force."
        )
        memory_cost_kb = memory_mb * 1024

        time_cost = st.slider(
            "Iterations (time cost)",
            min_value=1,
            max_value=10,
            value=3,
            help="Number of passes over memory. OWASP minimum: 2. More = slower computation."
        )

    with hcol2:
        parallelism = st.slider(
            "Parallelism (threads)",
            min_value=1,
            max_value=16,
            value=4,
            help="Parallel computation threads. Match to your server's CPU core count."
        )

        hash_len = st.selectbox(
            "Hash Output Length",
            options=[16, 32, 64],
            index=1,
            format_func=lambda x: f"{x} bytes ({x*8} bits)",
            help="Output digest size. 32 bytes (256-bit) is standard."
        )

    # OWASP compliance live check
    owasp_ok = memory_cost_kb >= 19456 and time_cost >= 2
    owasp_class = "owasp-ok" if owasp_ok else "owasp-bad"
    owasp_text  = "✅ OWASP Compliant" if owasp_ok else "⚠️ Below OWASP Minimum"
    st.markdown(
        f'<div class="param-row">'
        f'<span class="param-badge">Memory: {memory_mb} MB</span>'
        f'<span class="param-badge">Iterations: {time_cost}</span>'
        f'<span class="param-badge">Threads: {parallelism}</span>'
        f'<span class="param-badge">Output: {hash_len*8} bits</span>'
        f'<span class="param-badge {owasp_class}">{owasp_text}</span>'
        f'</div>',
        unsafe_allow_html=True
    )

    # ── Password input + Hash ──────────────────────────────────────────────
    hash_password = st.text_input(
        "Password to hash:",
        type="password",
        placeholder="Enter any password…",
        key="hash_input"
    )

    if st.button("🔐 Generate Argon2id Hash", use_container_width=True, key="hash_btn") and hash_password:
        with st.spinner("Hashing… (may take a moment at high memory settings)"):
            import time as _time
            t0 = _time.perf_counter()
            hash_str, params = argon2idHash(
                hash_password,
                memory_cost=memory_cost_kb,
                time_cost=time_cost,
                parallelism=parallelism,
                hash_len=hash_len,
            )
            elapsed = _time.perf_counter() - t0

        if hash_str is None:
            st.error(f"Hashing failed: {params.get('error', 'unknown error')}")
        else:
            st.markdown("#### Output Hash (PHC Format)")
            st.markdown(
                f'<div class="hash-output">{hash_str}</div>',
                unsafe_allow_html=True
            )
            st.code(hash_str, language=None)   # copyable

            st.caption(
                f"⏱️ Hash computed in **{elapsed*1000:.1f} ms** on your machine. "
                f"An attacker must pay this cost *per guess attempt*."
            )

            st.markdown("---")

            # ── What does the hash mean? ──────────────────────────────────
            with st.expander("🔍 Decode the hash format"):
                parts = hash_str.split("$")
                st.markdown("""
The output is in **PHC string format** — a self-describing hash that embeds all
parameters needed to verify it. You store this entire string in your database.
No separate salt column needed.

| Segment | Meaning |
|---|---|
| `$argon2id` | Algorithm identifier |
| `v=19` | Argon2 spec version |
| `m=...` | Memory cost in KB |
| `t=...` | Iteration count |
| `p=...` | Parallelism |
| `[salt]` | Base64-encoded 128-bit random salt (unique per hash) |
| `[hash]` | Base64-encoded output digest |

Because the salt is embedded and random, the same password hashed twice will
produce **different output every time** — making rainbow table attacks impossible.
                """)

            # ── How to use in production ──────────────────────────────────
            with st.expander("📋 How to use this in production code"):
                st.markdown("**Python (argon2-cffi)**")
                st.code("""
from argon2 import PasswordHasher

ph = PasswordHasher(
    memory_cost={memory_cost_kb},
    time_cost={time_cost},
    parallelism={parallelism},
    hash_len={hash_len},
)

# On registration — store this in your DB:
hash = ph.hash(user_password)

# On login — verify:
try:
    ph.verify(stored_hash, user_password)
    # ✅ Correct password
except argon2.exceptions.VerifyMismatchError:
    # ❌ Wrong password
    pass
""".format(**params), language="python")

                st.markdown("**Node.js (argon2 package)**")
                st.code("""
const argon2 = require('argon2');

// On registration:
const hash = await argon2.hash(password, {{
  type: argon2.argon2id,
  memoryCost: {memory_cost_kb},
  timeCost: {time_cost},
  parallelism: {parallelism},
  hashLength: {hash_len},
}});

// On login:
const valid = await argon2.verify(storedHash, password);
""".format(**params), language="javascript")

            # ── Quantum attack cost estimate ──────────────────────────────
            st.markdown("---")
            st.markdown("#### ⚛️ Quantum Attack Cost Estimate")

            # Each Grover oracle call costs one full Argon2id computation
            # RAM needed = guesses_in_parallel * memory_cost
            # Assume attacker has 1 billion quantum oracle calls/sec
            oracle_calls_per_sec = 1e9
            # Argon2id forces ~time_cost memory passes; effective serial factor
            effective_serial = time_cost
            # Parallel guesses limited by RAM budget (assume 1 TB attacker RAM budget)
            attacker_ram_tb   = 1
            attacker_ram_kb   = attacker_ram_tb * 1e9
            parallel_guesses  = max(1, int(attacker_ram_kb / memory_cost_kb))
            adjusted_rate     = oracle_calls_per_sec / effective_serial * (parallel_guesses / 1e6)
            adjusted_rate     = max(adjusted_rate, 1)

            entropy_val, _ = getEntropy(hash_password)
            quantum_combinations = (2 ** entropy_val) ** 0.5   # Grover
            quantum_seconds      = quantum_combinations / adjusted_rate

            qcol1, qcol2, qcol3 = st.columns(3)
            with qcol1:
                st.metric("RAM per guess",    f"{memory_mb} MB")
            with qcol2:
                st.metric("Parallel guesses", f"{parallel_guesses:,}")
            with qcol3:
                st.metric("Quantum crack time", timeFormat(quantum_seconds))

            st.caption(
                f"Assumes attacker has 1 TB RAM, 1B quantum oracle calls/sec, "
                f"and {elapsed*1000:.1f} ms per Argon2id computation. "
                f"Higher memory cost directly throttles parallel attacks."
            )
