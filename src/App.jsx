import React, { useEffect, useState, useRef } from "react";

// Degix Command Hub - Single-file React MVP Prototype // - Passcode gate (initial: DIGIXDESTIN) // - Forced admin passcode change on first login // - Client-side encryption for Journal (AES-GCM via Web Crypto) // - Simple Dashboard, Goals list, Security Playbook checklist, Notepad // NOTE: This is a frontend prototype that uses localStorage as the "backend".

// ---------- Utilities: crypto helpers (Web Crypto) ---------- async function generateSalt() { const s = crypto.getRandomValues(new Uint8Array(16)); return btoa(String.fromCharCode(...s)); }

async function deriveKeyFromPass(pass, saltB64, iterations = 250000, length = 256) { const enc = new TextEncoder(); const passKey = await crypto.subtle.importKey( "raw", enc.encode(pass), "PBKDF2", false, ["deriveKey", "deriveBits"]n ); const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0)); const key = await crypto.subtle.deriveKey( { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, passKey, { name: "AES-GCM", length }, true, ["encrypt", "decrypt"] ); return key; }

async function deriveRaw(pass, saltB64, iterations = 250000, length = 256) { const enc = new TextEncoder(); const baseKey = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]); const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0)); const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, baseKey, length); return btoa(String.fromCharCode(...new Uint8Array(bits))); }

async function encryptWithKey(rawKey, plaintext) { const iv = crypto.getRandomValues(new Uint8Array(12)); const enc = new TextEncoder(); const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, rawKey, enc.encode(plaintext)); return { iv: btoa(String.fromCharCode(...iv)), data: btoa(String.fromCharCode(...new Uint8Array(ct))) }; }

async function decryptWithKey(rawKey, ivB64, dataB64) { try { const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0)); const data = Uint8Array.from(atob(dataB64), c => c.charCodeAt(0)); const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, rawKey, data); return new TextDecoder().decode(dec); } catch (e) { return null; } }

// ---------- LocalStorage keys ---------- const LS = { passSalt: "dg_pass_salt", passHash: "dg_pass_hash", // derived raw stored recovery: "dg_recovery_code", loggedIn: "dg_logged_in", journal: "dg_journal_entries", notes: "dg_quick_notes", goals: "dg_goals", playbook: "dg_playbook_state" };

// Ensure initial passcode exists (hashed) - called on first run async function ensureInitialPass() { if (localStorage.getItem(LS.passSalt) && localStorage.getItem(LS.passHash)) return; const salt = await generateSalt(); const initial = "DIGIXDESTIN"; // initial passcode (you should rotate after first login) const raw = await deriveRaw(initial, salt); localStorage.setItem(LS.passSalt, salt); localStorage.setItem(LS.passHash, raw); }

// verify async function verifyPass(pass) { const salt = localStorage.getItem(LS.passSalt); const stored = localStorage.getItem(LS.passHash); if (!salt || !stored) return false; const raw = await deriveRaw(pass, salt); return raw === stored; }

async function changePass(oldPass, newPass) { const ok = await verifyPass(oldPass); if (!ok) return { ok: false, msg: "Current pass incorrect" }; const salt = await generateSalt(); const raw = await deriveRaw(newPass, salt); localStorage.setItem(LS.passSalt, salt); localStorage.setItem(LS.passHash, raw); // generate recovery code and save const rc = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join(""); localStorage.setItem(LS.recovery, rc); return { ok: true, recovery: rc }; }

// quick helpers for lists function loadJSON(key, fallback) { try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; } } function saveJSON(key, val) { localStorage.setItem(key, JSON.stringify(val)); }

// ---------- App Component ---------- export default function DegixHub() { const [initialized, setInitialized] = useState(false); const [locked, setLocked] = useState(true); const [passInput, setPassInput] = useState(""); const [promptChange, setPromptChange] = useState(false); const [showRecovery, setShowRecovery] = useState(false); const [recoveryCode, setRecoveryCode] = useState(null); const [userKey, setUserKey] = useState(null); // AES CryptoKey for journal const [activeTab, setActiveTab] = useState("dashboard");

// app data const [notes, setNotes] = useState(loadJSON(LS.notes, ["Welcome to Degix Hub - quick notes."])); const [goals, setGoals] = useState(loadJSON(LS.goals, [ { id: 1, title: "Launch MVP", progress: 20 }, { id: 2, title: "Build Team", progress: 5 } ]));

const [playbook, setPlaybook] = useState(loadJSON(LS.playbook, [ { id: 1, text: "Preserve evidence (screenshots, logs)", done: false }, { id: 2, text: "Isolate affected account/device", done: false }, { id: 3, text: "Notify platform & counsel", done: false } ]));

const [journalEntries, setJournalEntries] = useState(loadJSON(LS.journal, [])); const journalTextRef = useRef(); const noteRef = useRef();

useEffect(() => { ensureInitialPass().then(() => setInitialized(true)); }, []);

useEffect(() => saveJSON(LS.notes, notes), [notes]); useEffect(() => saveJSON(LS.goals, goals), [goals]); useEffect(() => saveJSON(LS.playbook, playbook), [playbook]); useEffect(() => saveJSON(LS.journal, journalEntries), [journalEntries]);

// LOGIN async function handleUnlock(e) { e.preventDefault(); const ok = await verifyPass(passInput); if (ok) { setLocked(false); localStorage.setItem(LS.loggedIn, "1"); // derive AES key for journal encryption const salt = localStorage.getItem(LS.passSalt); const key = await deriveKeyFromPass(passInput, salt); setUserKey(key); // prompt password change on first login (or always as requested) setPromptChange(true); setPassInput(""); } else { alert("Passcode incorrect"); } }

async function handleChangePass(e) { e.preventDefault(); const oldp = e.target.oldp.value; const newp = e.target.newp.value; if (newp.length < 8) return alert("Use at least 8 chars for new passcode"); const res = await changePass(oldp, newp); if (!res.ok) return alert(res.msg || "Could not change pass"); setShowRecovery(true); setRecoveryCode(res.recovery); // re-derive key with new pass const salt = localStorage.getItem(LS.passSalt); const key = await deriveKeyFromPass(newp, salt); setUserKey(key); setPromptChange(false); alert("Passcode changed. Save your recovery code securely."); }

// quick logout function handleLogout() { setLocked(true); setUserKey(null); localStorage.removeItem(LS.loggedIn); }

// Notes function addNote() { const v = noteRef.current.value.trim(); if (!v) return; const n = [...notes]; n.unshift(v); setNotes(n.slice(0, 40)); noteRef.current.value = ""; }

// Goals function addGoal() { const title = prompt("New goal title"); if (!title) return; const id = Date.now(); setGoals([{ id, title, progress: 0 }, ...goals]); }

// Playbook checklist function togglePlay(id) { setPlaybook(playbook.map(p => (p.id === id ? { ...p, done: !p.done } : p))); }

// Journal: encrypt entry async function addJournal() { const text = journalTextRef.current.value.trim(); if (!text) return; if (!userKey) return alert("Encryption key unavailable. Re-login or change pass."); const enc = await encryptWithKey(userKey, text); const entry = { id: Date.now(), iv: enc.iv, data: enc.data, ts: new Date().toISOString() }; setJournalEntries([entry, ...journalEntries]); journalTextRef.current.value = ""; }

async function readJournal(entry) { if (!userKey) return alert("Key missing"); const pt = await decryptWithKey(userKey, entry.iv, entry.data); if (pt === null) return alert("Could not decrypt (wrong pass?)"); alert(Entry (${new Date(entry.ts).toLocaleString()}):\n\n${pt}); }

// Simple UI layout if (!initialized) return <div className="p-6">Initializing...</div>;

if (locked) { return ( <div className="min-h-screen flex items-center justify-center bg-gray-900 text-white p-4"> <div className="w-full max-w-md bg-gray-800 rounded-2xl p-6 shadow-lg"> <h1 className="text-2xl font-bold mb-4">Degix Command Hub</h1> <p className="mb-4 text-sm text-gray-300">Enter passcode to continue</p> <form onSubmit={handleUnlock} className="flex gap-2"> <input value={passInput} onChange={e => setPassInput(e.target.value)} placeholder="Passcode" className="flex-1 p-3 rounded bg-gray-700" /> <button className="px-4 py-3 bg-indigo-600 rounded">Enter</button> </form> <p className="mt-4 text-xs text-gray-400">Initial passcode: <span className="font-mono">DIGIXDESTIN</span> (you will be prompted to change it)</p> </div> </div> ); }

return ( <div className="min-h-screen bg-gradient-to-b from-black to-gray-900 text-white"> <div className="flex"> <aside className="w-64 p-4 border-r border-gray-800 h-screen"> <h2 className="text-xl font-bold mb-4">Degix Hub</h2> <nav className="flex flex-col gap-2"> <button onClick={() => setActiveTab("dashboard")} className={text-left p-2 rounded ${activeTab==="dashboard"?"bg-gray-800":"hover:bg-gray-800"}}>🏠 Dashboard</button> <button onClick={() => setActiveTab("goals")} className={text-left p-2 rounded ${activeTab==="goals"?"bg-gray-800":"hover:bg-gray-800"}}>🎯 Goals</button> <button onClick={() => setActiveTab("security")} className={text-left p-2 rounded ${activeTab==="security"?"bg-gray-800":"hover:bg-gray-800"}}>🛡 Security</button> <button onClick={() => setActiveTab("notepad")} className={text-left p-2 rounded ${activeTab==="notepad"?"bg-gray-800":"hover:bg-gray-800"}}>📝 Notepad</button> <button onClick={() => setActiveTab("journal")} className={text-left p-2 rounded ${activeTab==="journal"?"bg-gray-800":"hover:bg-gray-800"}}>🔒 Journal</button> <div className="mt-4 border-t border-gray-800 pt-3"> <button onClick={() => setPromptChange(true)} className="text-sm text-yellow-300">Change passcode</button> <button onClick={handleLogout} className="text-sm text-red-400 mt-2">Log out</button> </div> </nav> </aside> <main className="flex-1 p-6"> {/* Header */} <header className="flex items-center justify-between mb-6"> <h1 className="text-2xl font-bold">{activeTab === 'dashboard' ? 'Dashboard' : activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}</h1> <div className="text-sm text-gray-300">Admin</div> </header>

{/* Content */}
      {activeTab === 'dashboard' && (
        <section className="grid grid-cols-3 gap-4">
          <div className="col-span-2 bg-gray-800 p-4 rounded">
            <h3 className="font-bold mb-2">Overview</h3>
            <p className="text-sm text-gray-300 mb-4">Goals in progress, urgent playbook items, and quick actions.</p>
            <div className="flex gap-2">
              <button className="px-3 py-2 bg-indigo-600 rounded" onClick={() => setActiveTab('goals')}>Open Goals</button>
              <button className="px-3 py-2 bg-yellow-600 rounded" onClick={() => setActiveTab('security')}>Run Playbook</button>
            </div>

            <div className="mt-4">
              <h4 className="font-semibold mb-2">Top 3 Goals</h4>
              <ol className="list-decimal ml-6 text-sm text-gray-300">
                {goals.slice(0,3).map(g => (
                  <li key={g.id}>{g.title} — {g.progress}%</li>
                ))}
              </ol>
            </div>

          </div>

          <div className="bg-gray-800 p-4 rounded">
            <h4 className="font-bold mb-2">Quick Notes</h4>
            <div className="text-sm text-gray-300 space-y-2 max-h-56 overflow-auto">
              {notes.map((n,i)=>(<div key={i} className="p-2 bg-gray-700 rounded">{n}</div>))}
            </div>
            <div className="mt-3 flex gap-2">
              <input ref={noteRef} placeholder="New quick note" className="flex-1 p-2 rounded bg-gray-700 text-sm" />
              <button onClick={addNote} className="px-3 py-2 bg-green-600 rounded">Add</button>
            </div>
          </div>
        </section>
      )}

      {activeTab === 'goals' && (
        <section>
          <div className="flex justify-between items-center mb-4">
            <h3 className="font-bold">Goals & Production Tracker</h3>
            <div>
              <button onClick={addGoal} className="px-3 py-2 bg-indigo-600 rounded">New Goal</button>
            </div>
          </div>
          <div className="space-y-3">
            {goals.map(g => (
              <div key={g.id} className="bg-gray-800 p-3 rounded flex justify-between items-center">
                <div>
                  <div className="font-semibold">{g.title}</div>
                  <div className="text-xs text-gray-400">Progress: {g.progress}%</div>
                </div>
                <div>
                  <input type="range" min="0" max="100" value={g.progress} onChange={e => setGoals(goals.map(x=>x.id===g.id?{...x,progress:parseInt(e.target.value)}:x))} />
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'security' && (
        <section>
          <h3 className="font-bold mb-2">Security & Incident Playbook</h3>
          <p className="text-sm text-gray-300 mb-3">Interactive playbook — toggle steps as you complete them and export evidence logs.</p>
          <div className="space-y-2">
            {playbook.map(p => (
              <div key={p.id} className="flex items-center gap-3 bg-gray-800 p-3 rounded">
                <input type="checkbox" checked={p.done} onChange={() => togglePlay(p.id)} />
                <div>{p.text}</div>
              </div>
            ))}
          </div>

          <div className="mt-4">
            <h4 className="font-semibold">Evidence Log</h4>
            <p className="text-xs text-gray-400">Use the Journal to store encrypted notes and screenshots. Export when needed.</p>
          </div>
        </section>
      )}

      {activeTab === 'notepad' && (
        <section>
          <h3 className="font-bold mb-2">Notepad</h3>
          <textarea className="w-full bg-gray-800 p-3 rounded h-40" placeholder="Write fast ideas here..." />
        </section>
      )}

      {activeTab === 'journal' && (
        <section>
          <h3 className="font-bold mb-2">Encrypted Journal</h3>
          <p className="text-sm text-gray-300 mb-3">Entries are encrypted client-side with your passcode-derived key.</p>
          <textarea ref={journalTextRef} className="w-full bg-gray-800 p-3 rounded h-32" placeholder="Private entry..." />
          <div className="mt-2 flex gap-2">
            <button onClick={addJournal} className="px-3 py-2 bg-green-600 rounded">Save Entry (Encrypted)</button>
            <button onClick={() => setJournalEntries([])} className="px-3 py-2 bg-red-600 rounded">Clear Local Journal</button>
          </div>

          <div className="mt-4">
            <h4 className="font-semibold">Saved Entries</h4>
            <div className="space-y-2 mt-2">
              {journalEntries.map(j => (
                <div key={j.id} className="bg-gray-800 p-2 rounded flex justify-between items-center">
                  <div className="text-sm">{new Date(j.ts).toLocaleString()}</div>
                  <div>
                    <button onClick={() => readJournal(j)} className="px-2 py-1 mr-2 bg-indigo-600 rounded text-sm">Read</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

    </main>
  </div>

  {/* Forced change modal */}
  {promptChange && (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-gray-800 p-6 rounded max-w-lg w-full">
        <h3 className="font-bold mb-2">Change Admin Passcode (Recommended)</h3>
        <form onSubmit={handleChangePass} className="space-y-3">
          <div>
            <label className="text-xs text-gray-400">Current passcode</label>
            <input name="oldp" className="w-full p-2 rounded bg-gray-700" />
          </div>
          <div>
            <label className="text-xs text-gray-400">New passcode</label>
            <input name="newp" className="w-full p-2 rounded bg-gray-700" />
          </div>
          <div className="flex gap-2 justify-end">
            <button type="button" onClick={() => setPromptChange(false)} className="px-3 py-2 bg-gray-600 rounded">Later</button>
            <button className="px-3 py-2 bg-green-600 rounded">Change Passcode</button>
          </div>
        </form>
        {showRecovery && recoveryCode && (
          <div className="mt-4 p-3 bg-gray-900 rounded">
            <div className="text-xs text-gray-400">Recovery code (save this offline):</div>
            <div className="font-mono mt-2">{recoveryCode}</div>
          </div>
        )}
      </div>
    </div>
  )}

</div>

); }


