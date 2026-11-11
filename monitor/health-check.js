const checks = [
  ["public website", "https://rs-oilfield-recruitment.onrender.com/"],
  ["admin dashboard", "https://rs-oilfield-recruitment.onrender.com/admin.html"],
  ["recruiting API", "https://rs-oilfield-api.onrender.com/health"]
];

async function check(name, url) {
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: "follow" });
    const elapsed = Date.now() - started;
    const ok = response.ok;
    console.log(JSON.stringify({ check: name, ok, status: response.status, elapsed_ms: elapsed, checked_at: new Date().toISOString() }));
    return ok;
  } catch (error) {
    console.error(JSON.stringify({ check: name, ok: false, error: error.name === "AbortError" ? "timeout" : error.message, checked_at: new Date().toISOString() }));
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

(async () => {
  const results = await Promise.all(checks.map(([name, url]) => check(name, url)));
  const failures = results.filter(ok => !ok).length;
  console.log(`Health check complete: ${results.length - failures}/${results.length} passed.`);
  if (failures) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
