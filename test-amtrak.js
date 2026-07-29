// test-amtrak.js — read Amtrak status honestly, or say "Unknown". Never invent "On Time".
const assert = require("assert");
const { parseComment, stationMatches, matchTrain, readStatus, toStatusResult } = require("./amtrak");

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", x = "\x1b[0m";
const t = (n, fn) => { try { fn(); console.log(`  ${g}✓${x} ${n}`); pass++; } catch (e) { console.log(`  ${r}✗ ${n}${x}\n    ${e.message}`); fail++; } };

// ── parseComment ──
t("parseComment: '' → null (silence is not on-time)", () => assert.strictEqual(parseComment(""), null));
t("parseComment: 'ON TIME' → 0", () => assert.deepStrictEqual(parseComment("ON TIME"), { mins: 0 }));
t("parseComment: '12 MIN LATE' → 12", () => assert.deepStrictEqual(parseComment("12 MIN LATE"), { mins: 12 }));
t("parseComment: '1 HR 30 MIN LATE' → 90", () => assert.deepStrictEqual(parseComment("1 HR 30 MIN LATE"), { mins: 90 }));
t("parseComment: '2 HR LATE' → 120", () => assert.deepStrictEqual(parseComment("2 HR LATE"), { mins: 120 }));
t("parseComment: '5 MIN EARLY' → -5", () => assert.deepStrictEqual(parseComment("5 MIN EARLY"), { mins: -5 }));
t("parseComment: 'SERVICE CANCELLED' → cancelled", () => assert.deepStrictEqual(parseComment("SERVICE CANCELLED"), { cancelled: true }));

// ── stationMatches ──
t("stationMatches: code CHI == 'chi'", () => assert.strictEqual(stationMatches({ code: "CHI", name: "Chicago Union" }, "chi"), true));
t("stationMatches: name overlap 'Chicago'", () => assert.strictEqual(stationMatches({ code: "CHI", name: "Chicago Union" }, "Chicago"), true));
t("stationMatches: wrong place → false", () => assert.strictEqual(stationMatches({ code: "CHI", name: "Chicago Union" }, "Boston"), false));

// Realistic Amtraker fixture: train 5, origin CHI.
const feed = (over = {}) => ({
  "5": [{
    trainNum: "5", trainID: "5-28", routeName: "California Zephyr", trainState: over.state || "Active",
    statusMsg: over.statusMsg || " ", origCode: "CHI", destCode: "EMY",
    stations: [
      { code: "CHI", name: "Chicago Union", schArr: "2026-08-01T14:00:00-05:00", schDep: "2026-08-01T14:00:00-05:00", arr: over.arr || "2026-08-01T14:00:00-05:00", dep: over.dep || "2026-08-01T14:00:00-05:00", arrCmnt: over.arrCmnt || "", depCmnt: over.depCmnt || "", platform: over.platform || "" },
      { code: "DEN", name: "Denver", schArr: "2026-08-02T07:56:00-06:00", schDep: "2026-08-02T08:46:00-06:00", arr: "", dep: "", arrCmnt: "", depCmnt: "", platform: "" },
    ],
  }],
});
const leg = (o = {}) => ({ trainNum: "5", from: "CHI", departsAt: "2026-08-01T19:00:00Z", ...o }); // 14:00 CDT

// ── matchTrain ──
t("matchTrain: finds train 5 at Chicago", () => {
  const { train, stop } = matchTrain(feed(), leg());
  assert.strictEqual(train.trainNum, "5");
  assert.strictEqual(stop.code, "CHI");
});
t("matchTrain: wrong number → no match", () => {
  assert.strictEqual(matchTrain(feed(), leg({ trainNum: "48" })).train, null);
});
t("matchTrain: right number but a run 3 days off → rejected", () => {
  assert.strictEqual(matchTrain(feed(), leg({ departsAt: "2026-08-05T19:00:00Z" })).train, null);
});

// ── readStatus / toStatusResult ──
t("status: Active train, no comment yet → Unknown (never fake On Time)", () => {
  assert.strictEqual(toStatusResult(feed(), leg()).status, "Unknown");
});
t("status: Predeparture, empty comment → Unknown", () => {
  assert.strictEqual(toStatusResult(feed({ state: "Predeparture" }), leg()).status, "Unknown");
});
t("status: depCmnt '45 MIN LATE' → Delayed 45, platform surfaced", () => {
  const rr = toStatusResult(feed({ depCmnt: "45 MIN LATE", platform: "2" }), leg());
  assert.strictEqual(rr.status, "Delayed");
  assert.strictEqual(rr.delayMins, 45);
  assert.strictEqual(rr.platform, "2");
});
t("status: explicit 'ON TIME' comment → On Time", () => {
  assert.strictEqual(toStatusResult(feed({ depCmnt: "ON TIME" }), leg()).status, "On Time");
});
t("status: statusMsg says cancelled → Cancelled", () => {
  assert.strictEqual(toStatusResult(feed({ statusMsg: "Train 5 Service Cancelled" }), leg()).status, "Cancelled");
});
t("status: Active + actual dep 20m after sched → Delayed 20 (time fallback)", () => {
  const rr = toStatusResult(feed({ dep: "2026-08-01T14:20:00-05:00" }), leg());
  assert.strictEqual(rr.status, "Delayed");
  assert.strictEqual(rr.delayMins, 20);
});
t("status: no such train in feed → Unknown", () => {
  assert.strictEqual(toStatusResult({}, leg()).status, "Unknown");
});
t("toStatusResult: always tags network+source", () => {
  const rr = toStatusResult(feed(), leg());
  assert.strictEqual(rr.network, "amtrak");
  assert.strictEqual(rr.source, "amtraker");
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
