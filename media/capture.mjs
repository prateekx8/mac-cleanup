// Captures every shot for the videos by driving the real UI (served with demo data)
// in headless Chrome, plus title/card/caption graphics in the same glass style.
//   node capture.mjs <long|short> <demo-url> <out-dir> <icon.png>
import { chromium } from "playwright-core";
import fs from "node:fs";
import path from "node:path";

const [fmt, url, out, iconPath] = process.argv.slice(2);
const LONG = fmt === "long";
// 1280x720 @1.5 = 1920x1080 ; 432x768 @2.5 = 1080x1920
const viewport = LONG ? { width: 1280, height: 720 } : { width: 432, height: 768 };
const scale = LONG ? 1.5 : 2.5;
const scenes = JSON.parse(fs.readFileSync(new URL("./scenes.json", import.meta.url)))[fmt];
const icon = "data:image/png;base64," + fs.readFileSync(iconPath).toString("base64");
fs.mkdirSync(path.join(out, "shots"), { recursive: true });
fs.mkdirSync(path.join(out, "captions"), { recursive: true });

const browser = await chromium.launch({ channel: "chrome" });
const ctx = await browser.newContext({ viewport, deviceScaleFactor: scale, colorScheme: "dark", reducedMotion: "no-preference" });
const page = await ctx.newPage();
page.on("dialog", d => d.accept());
const shot = async name => { await page.waitForTimeout(450); await page.screenshot({ path: path.join(out, "shots", name + ".png") }); };
const wanted = new Set(scenes.map(s => s.shot));
const maybe = async (name, fn) => { if (wanted.has(name)) { await fn(); await shot(name); } };
const scrollTo = async (sel, offset) => {
  await page.evaluate(([s, o]) => { const el = document.querySelector(s); window.scrollTo({ top: el.getBoundingClientRect().top + scrollY - o, behavior: "instant" }); }, [sel, offset]);
};
const panel = n => `section.panel:nth-of-type(${n})`;

// ---------------------------------------------------------------- UI shots
await page.goto(url);
await page.evaluate(() => { try { localStorage.clear() } catch (e) {} });
await page.reload();
await page.waitForTimeout(1200);  // blobs settle
await maybe("hero", async () => {});
// start scan, capture the spinner state
await page.click("#scanBtn");
if (wanted.has("scanning")) {
  if (!LONG) await scrollTo("section.panel", 90);
  await shot("scanning");
}
await page.waitForSelector(".item", { timeout: 15000 });
await maybe("results", () => scrollTo("section.panel", LONG ? 90 : 80));
await maybe("paths", async () => { await page.click('.item[data-i="0"] .more'); await scrollTo("section.panel", 90); });
if (wanted.has("paths")) { await page.click('.item[data-i="0"] .more'); }  // close again
await maybe("review", async () => {
  await page.click('.item:has-text("Android emulator images")');
  await page.locator('.item:has-text("Android emulator images")').evaluate((el, o) =>
    window.scrollTo({ top: el.getBoundingClientRect().top + scrollY - o, behavior: "instant" }), LONG ? 330 : 200);
});
if (wanted.has("review")) await page.click('.item:has-text("Android emulator images")');  // deselect for the clean
if (wanted.has("cleaning")) {
  await scrollTo("section.panel", 90);
  const p = page.click("#cleanBtn");
  await page.waitForTimeout(120);
  await shot("cleaning");
  await p;
} else {
  await page.click("#cleanBtn");
}
await page.waitForSelector("#toast.show", { timeout: 15000 });
const toastText = await page.textContent("#toast");
if (!/Freed/.test(toastText)) throw new Error("demo clean failed: " + toastText);
await page.evaluate(() => window.scrollTo(0, 0));
await page.waitForTimeout(300);
await maybe("cleaned", () => scrollTo(".stats", LONG ? 330 : 150));
await page.click("#checkAll");
await page.waitForSelector("#sec .f", { timeout: 15000 });
await page.waitForSelector("#net .f", { timeout: 15000 });
await page.waitForSelector("#apps .f", { timeout: 20000 });
await page.waitForSelector("#traffic .tr:not(.h)", { timeout: 20000 });
await maybe("security", () => scrollTo(panel(2), 90));
await maybe("network", () => scrollTo(panel(3), 90));
await maybe("apps", () => scrollTo(panel(4), 90));
await maybe("traffic", () => scrollTo(panel(5), 90));
await maybe("watcher", async () => {
  await page.click(".switch span");
  await page.waitForSelector("#toast.show");
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
});
await maybe("light", async () => { await page.click("#themeBtn"); await page.evaluate(() => window.scrollTo(0, 0)); await page.waitForTimeout(500); });

// ---------------------------------------------------------------- cards (same visual language)
const css = `
:root{--fg:#f4f5fb;--fg2:rgba(244,245,251,.72);--fg3:rgba(244,245,251,.5);--stroke:rgba(255,255,255,.16);
 --accent:linear-gradient(135deg,#7c5cff 0%,#3fa9ff 55%,#2ee6c5 100%)}
*{box-sizing:border-box;margin:0}
html,body{width:100%;height:100%;background:#0b0d1a;color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",sans-serif;overflow:hidden;-webkit-font-smoothing:antialiased}
.mesh{position:fixed;inset:0;overflow:hidden}
.mesh i{position:absolute;border-radius:50%;filter:blur(90px);opacity:.55}
.mesh i:nth-child(1){background:#6d4dff;width:60vmax;height:60vmax;left:-15vmax;top:-20vmax}
.mesh i:nth-child(2){background:#00c2ff;width:55vmax;height:55vmax;right:-18vmax;top:10vmax}
.mesh i:nth-child(3){background:#ff4d9d;width:45vmax;height:45vmax;left:20vmax;bottom:-25vmax;opacity:.38}
.stage{position:relative;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:6vmin}
.glass{background:rgba(255,255,255,.075);border:1px solid var(--stroke);border-radius:28px;box-shadow:0 30px 60px -25px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.12);backdrop-filter:blur(28px) saturate(170%)}
h1{font-weight:800;letter-spacing:-.045em;line-height:1}
.grad{background:var(--accent);-webkit-background-clip:text;background-clip:text;color:transparent}
p{color:var(--fg2)}
.chip{display:inline-flex;gap:10px;align-items:center;padding:10px 20px;border-radius:999px;font-size:${LONG ? 18 : 22}px;color:var(--fg2)}
.dot{width:9px;height:9px;border-radius:50%;background:#3ee09a;box-shadow:0 0 12px #3ee09a}
.mono{font-family:ui-monospace,"SF Mono",Menlo,monospace}
.term{width:${LONG ? "1040px" : "380px"};text-align:left;padding:0;overflow:hidden}
.term .tb{display:flex;gap:8px;padding:14px 16px;border-bottom:1px solid var(--stroke)}
.term .tb i{width:12px;height:12px;border-radius:50%;background:#ff5f57}.term .tb i:nth-child(2){background:#febc2e}.term .tb i:nth-child(3){background:#28c840}
.term pre{padding:${LONG ? "22px 26px" : "16px"};font:${LONG ? 17 : 11.5}px/1.6 ui-monospace,"SF Mono",Menlo,monospace;color:#d8dbf0;white-space:pre-wrap}
.g{color:#3ee09a}.y{color:#ffb547}.r{color:#ff6b6b}.b{color:#7fb2ff}.d{color:rgba(216,219,240,.5)}.w{color:#fff;font-weight:700}
ul{list-style:none;padding:0;text-align:left}
li{display:flex;gap:16px;align-items:center;padding:${LONG ? "16px 26px" : "16px 18px"};font-size:${LONG ? 26 : 22}px;font-weight:600}
li+li{border-top:1px solid var(--stroke)}
li b{width:38px;height:38px;flex:none;border-radius:12px;display:grid;place-items:center;background:var(--accent);font-size:18px}
`;
const card = async (name, body) => {
  if (!wanted.has(name)) return;
  await page.setContent(`<html><head><style>${css}</style></head><body><div class="mesh"><i></i><i></i><i></i></div><div class="stage">${body}</div></body></html>`);
  await shot(name);
};
const bigIcon = s => `<img src="${icon}" style="width:${s}px;height:${s}px;filter:drop-shadow(0 30px 50px rgba(109,77,255,.55))">`;
const H = LONG ? 1 : 0.86;

await card("title", `${bigIcon(LONG ? 200 : 260)}
  <h1 style="font-size:${LONG ? 96 : 70}px;margin-top:28px">Mac <span class="grad">Cleanup</span></h1>
  <p style="font-size:${LONG ? 28 : 24}px;margin-top:18px">Keep your developer Mac light &amp; safe</p>
  <div class="chip glass" style="margin-top:34px"><span class="dot"></span>Free · Local · Open source</div>`);

for (const name of ["problem", "hook"]) await card(name, `
  <p class="mono" style="font-size:${LONG ? 20 : 18}px;letter-spacing:.2em;text-transform:uppercase;color:var(--fg3)">Hidden on a typical dev Mac</p>
  <h1 class="grad" style="font-size:${LONG ? 210 : 118}px;margin:18px 0 8px;white-space:nowrap">25 GB</h1>
  <p style="font-size:${LONG ? 30 : 26}px;max-width:${LONG ? 900 : 380}px">of caches, simulators &amp; build leftovers you never see</p>
  <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;margin-top:34px;max-width:${LONG ? 1000 : 400}px">
    ${["DerivedData", "Simulators", "node_modules", "Gradle", "npm", "pip", "Old IDEs"].map(t => `<span class="chip glass">${t}</span>`).join("")}
  </div>`);

await card("cli", `<div class="term glass"><div class="tb"><i></i><i></i><i></i></div><pre><span class="g">❯</span> <span class="w">macguard scan</span>
<span class="d">Data volume: 431.2G used / 494.4G (63.2G free)</span>

  <span class="w">  11.2G</span>  <span class="g">safe  </span> sim-unavailable      Unavailable iOS simulators
  <span class="w">   4.3G</span>  <span class="g">safe  </span> xcode-derived        Xcode DerivedData
  <span class="w">   4.1G</span>  <span class="g">safe  </span> jetbrains-old        Old JetBrains IDE versions
  <span class="w">   4.5G</span>  <span class="y">review</span> android-avd          Android emulator images

<span class="g">Safe to clean: 25.1G</span>   <span class="y">Needs review: 8.0G</span>

<span class="g">❯</span> <span class="w">macguard security</span>
  <span class="r">HIGH  </span> macOS firewall is OFF
  <span class="y">MEDIUM</span> Screen Sharing is enabled
  <span class="g">OK    </span> FileVault on

<span class="g">❯</span> <span class="w">macguard clean --apply</span>  <span class="d"># dry-run unless you ask</span></pre></div>`);

await card("app", `${bigIcon(LONG ? 130 : 150)}
  <h1 style="font-size:${LONG ? 60 : 44}px;margin:22px 0 26px">App · Web UI · CLI</h1>
  <div class="term glass" style="width:${LONG ? "820px" : "380px"}"><pre><span class="d"># native app (universal, arm64 + x86_64)</span>
<span class="g">❯</span> <span class="w">./build_app.sh --install</span>

<span class="d"># or one-click setup + tests</span>
<span class="g">❯</span> <span class="w">./setup.sh</span>   <span class="g">✔ 75 tests passed</span></pre></div>`);

await card("privacy", `<h1 style="font-size:${LONG ? 64 : 46}px;margin-bottom:30px">Private by <span class="grad">design</span></h1>
  <ul class="glass" style="width:${LONG ? "760px" : "390px"}">
    <li><b>✓</b>No root access needed</li><li><b>✓</b>No telemetry, nothing uploaded</li>
    <li><b>✓</b>Dry-run &amp; confirm before delete</li><li><b>✓</b>Deletes only inside your home</li></ul>`);

await card("outro", `${bigIcon(LONG ? 170 : 220)}
  <h1 style="font-size:${LONG ? 84 : 62}px;margin-top:26px">Mac <span class="grad">Cleanup</span></h1>
  <p style="font-size:${LONG ? 28 : 26}px;margin-top:16px">A lighter machine. A safer one.</p>
  <div class="chip glass" style="margin-top:32px">${LONG ? "Links in the description" : "Full walkthrough on the channel"}</div>`);

// YouTube thumbnail (long only): big claim + real UI screenshot
if (LONG) {
  wanted.add("thumb");
  const ui = "data:image/png;base64," + fs.readFileSync(path.join(out, "shots", "results.png")).toString("base64");
  await card("thumb", `<div style="display:flex;align-items:center;gap:56px;width:100%;padding:0 30px">
    <div style="text-align:left;flex:1">
      <div style="display:flex;align-items:center;gap:18px">${bigIcon(96)}<span style="font-size:34px;font-weight:700">Mac Cleanup</span></div>
      <h1 style="font-size:118px;margin-top:22px">Free up<br><span class="grad">25 GB</span></h1>
      <p style="font-size:30px;margin-top:16px;color:#fff">of hidden dev junk — safely</p></div>
    <img src="${ui}" style="width:640px;border-radius:22px;border:1px solid rgba(255,255,255,.2);box-shadow:0 40px 80px -20px rgba(0,0,0,.8);transform:perspective(1400px) rotateY(-12deg)">
  </div>`);
}

// ---------------------------------------------------------------- captions (transparent PNG overlays)
const capPage = await ctx.newPage();
for (const [i, s] of scenes.entries()) {
  await capPage.setContent(`<html><head><style>
    html,body{margin:0;background:transparent;width:100%;height:100%}
    .c{position:absolute;left:50%;transform:translateX(-50%);${LONG ? "bottom:34px;max-width:1080px" : "bottom:150px;max-width:390px"};
      padding:${LONG ? "14px 26px" : "14px 18px"};border-radius:${LONG ? 18 : 20}px;background:rgba(10,12,28,.72);border:1px solid rgba(255,255,255,.14);
      color:#fff;font:600 ${LONG ? 25 : 23}px/1.35 -apple-system,BlinkMacSystemFont,"SF Pro Display",sans-serif;text-align:center;
      box-shadow:0 18px 40px -16px rgba(0,0,0,.7);width:max-content}
  </style></head><body><div class="c">${s.say}</div></body></html>`);
  await capPage.screenshot({ path: path.join(out, "captions", `${String(i).padStart(2, "0")}.png`), omitBackground: true });
}
await browser.close();
console.log(`captured ${fmt}: ${fs.readdirSync(path.join(out, "shots")).length} shots, ${scenes.length} captions`);
