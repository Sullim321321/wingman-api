// wallet.js — Apple Wallet .pkpass generation + signing (Design #8, Wallet half)
// Pure JS (node-forge + jszip): builds a boarding-pass-style .pkpass, computes the
// manifest, and produces a PKCS#7 detached signature from the Pass Type ID cert.
//
// Secrets/assets:
//   wallet-assets/signer.pem  — Pass Type ID certificate (public, committed)
//   wallet-assets/wwdr.pem    — Apple WWDR intermediate (public, committed)
//   PASS_SIGNER_KEY_B64 (env) — base64 of the private key PEM (secret)
//   (local dev fallback: /tmp/signer-key.pem)

const forge = require("node-forge");
const JSZip = require("jszip");
const crypto = require("crypto");
const flightid = require("./flightid");
const fs = require("fs");
const path = require("path");

const ASSET_DIR = path.join(__dirname, "wallet-assets");
const PASS_TYPE_ID = process.env.PASS_TYPE_ID || "pass.club.welcometothefight.wingman";
const TEAM_ID = process.env.PASS_TEAM_ID || "7BXHSR34RG";

const IMAGE_FILES = ["icon.png", "icon@2x.png", "icon@3x.png", "logo.png", "logo@2x.png"];

function loadSignerKeyPem() {
  if (process.env.PASS_SIGNER_KEY_B64) {
    return Buffer.from(process.env.PASS_SIGNER_KEY_B64, "base64").toString("utf8");
  }
  const local = "/tmp/signer-key.pem";
  if (fs.existsSync(local)) return fs.readFileSync(local, "utf8");
  return null;
}

// Is Wallet signing configured on this server?
function walletReady() {
  return (
    fs.existsSync(path.join(ASSET_DIR, "signer.pem")) &&
    fs.existsSync(path.join(ASSET_DIR, "wwdr.pem")) &&
    !!loadSignerKeyPem()
  );
}

function signManifest(manifestBuf, signerCertPem, keyPem, wwdrPem) {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestBuf.toString("binary"));
  const cert = forge.pki.certificateFromPem(signerCertPem);
  const wwdr = forge.pki.certificateFromPem(wwdrPem);
  const key = forge.pki.privateKeyFromPem(keyPem);
  p7.addCertificate(cert);
  p7.addCertificate(wwdr);
  p7.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign({ detached: true });
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, "binary");
}

// Build the pass.json payload for a flight leg (falls back gracefully for non-flights).
function passJsonForLeg(leg, trip) {
  const serial = `wingman-${leg.id}`;
  const ident = flightid.displayName(leg).trim();
  const fmtDate = (d) => d ? new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : "—";
  const fmtTime = (d) => d ? new Date(d).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" }) : null;

  const base = {
    formatVersion: 1,
    passTypeIdentifier: PASS_TYPE_ID,
    teamIdentifier: TEAM_ID,
    organizationName: "Wingman",
    description: ident ? `${ident} ${leg.origin || ""}→${leg.destination || ""}`.trim() : (trip?.title || "Wingman trip"),
    serialNumber: serial,
    backgroundColor: "rgb(26,23,20)",
    foregroundColor: "rgb(255,255,255)",
    labelColor: "rgb(201,169,110)",
    barcodes: [{
      format: "PKBarcodeFormatQR",
      message: leg.confirmation || serial,
      messageEncoding: "iso-8859-1",
      altText: leg.confirmation || undefined,
    }],
  };

  if (leg.type === "flight") {
    base.boardingPass = {
      transitType: "PKTransitTypeAir",
      headerFields: [{ key: "flight", label: "FLIGHT", value: ident || "—" }],
      primaryFields: [
        { key: "origin", label: leg.origin || "FROM", value: leg.origin || "—" },
        { key: "destination", label: leg.destination || "TO", value: leg.destination || "—" },
      ],
      secondaryFields: [
        { key: "date", label: "DATE", value: fmtDate(leg.departs_at) },
        ...(leg.gate ? [{ key: "gate", label: "GATE", value: String(leg.gate) }] : []),
        ...(leg.seat ? [{ key: "seat", label: "SEAT", value: String(leg.seat) }] : []),
      ],
      auxiliaryFields: [
        ...(fmtTime(leg.departs_at) ? [{ key: "dep", label: "DEPARTS", value: fmtTime(leg.departs_at) }] : []),
        ...(leg.confirmation ? [{ key: "conf", label: "CONFIRMATION", value: String(leg.confirmation) }] : []),
      ],
      backFields: [
        { key: "tracked", label: "Tracked by", value: "Wingman — wingmantravel.app" },
      ],
    };
  } else {
    // Generic pass for hotels/cars/etc.
    base.generic = {
      primaryFields: [{ key: "name", label: (leg.type || "BOOKING").toUpperCase(), value: leg.carrier || leg.destination || trip?.title || "Booking" }],
      secondaryFields: [
        { key: "date", label: "DATE", value: fmtDate(leg.departs_at) },
        ...(leg.confirmation ? [{ key: "conf", label: "CONF", value: String(leg.confirmation) }] : []),
      ],
    };
  }
  return base;
}

// Assemble + sign the .pkpass, returning a Buffer.
async function buildPkpass(passJson) {
  const signerCertPem = fs.readFileSync(path.join(ASSET_DIR, "signer.pem"), "utf8");
  const wwdrPem = fs.readFileSync(path.join(ASSET_DIR, "wwdr.pem"), "utf8");
  const keyPem = loadSignerKeyPem();
  if (!keyPem) throw new Error("PASS_SIGNER_KEY_B64 not configured");

  const files = { "pass.json": Buffer.from(JSON.stringify(passJson)) };
  for (const img of IMAGE_FILES) {
    const p = path.join(ASSET_DIR, img);
    if (fs.existsSync(p)) files[img] = fs.readFileSync(p);
  }

  const manifest = {};
  for (const [name, buf] of Object.entries(files)) {
    manifest[name] = crypto.createHash("sha1").update(buf).digest("hex");
  }
  const manifestBuf = Buffer.from(JSON.stringify(manifest));
  const signature = signManifest(manifestBuf, signerCertPem, keyPem, wwdrPem);

  const zip = new JSZip();
  for (const [name, buf] of Object.entries(files)) zip.file(name, buf);
  zip.file("manifest.json", manifestBuf);
  zip.file("signature", signature);
  return zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
}

module.exports = { walletReady, passJsonForLeg, buildPkpass, PASS_TYPE_ID, TEAM_ID };
