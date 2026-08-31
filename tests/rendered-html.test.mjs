import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the Backtrace product surface and metadata", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>Backtrace — Agent flight recorder<\/title>/i);
  assert.match(html, /PYTHON-POWERED AGENT FLIGHT RECORDER/);
  assert.match(html, /See where your agent/);
  assert.match(html, /Ship the onboarding redesign/);
  assert.match(html, /RESTART FROM HERE/);
  assert.match(html, /raw\.githubusercontent\.com\/vishnugamini\/agent-backtrace\/main\/public\/og\.png/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("keeps trace import and restart behavior in the client source", async () => {
  const [page, trace, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../lib/trace.ts", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  assert.match(page, /accept="\.json,\.jsonl,\.txt,application\/json"/);
  assert.match(page, /buildRestartBrief/);
  assert.match(page, /--doctor/);
  assert.match(page, /--scan/);
  assert.match(page, /--history/);
  assert.match(page, /Fleet trend:/);
  assert.match(page, /--fail-on-fleet-regression/);
  assert.match(page, /Fleet gate: FAILED/);
  assert.match(page, /--webhook-url-env/);
  assert.match(page, /Fleet webhook: DELIVERED/);
  assert.match(page, /--webhook-format slack/);
  assert.match(page, /exact preview available/);
  assert.match(page, /navigator\.clipboard\.writeText/);
  assert.match(trace, /function parseTrace/);
  assert.match(trace, /function detectSignals/);
  assert.match(trace, /REDACTED_GITHUB_TOKEN/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
});
