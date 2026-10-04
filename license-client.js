/*
 * KARTU STOCK — License Client v1.0.0
 * Isolated client. Does not touch stock/product/mutation/request logic.
 */
(function () {
  'use strict';

  const CACHE_KEY = 'ks_license_cache_v1';
  const DAY_MS = 24 * 60 * 60 * 1000;
  const BLOCKED = new Set(['suspended', 'expired', 'not-found', 'config-error']);

  let licenseDb = null;
  let licenseApp = null;
  let lastResult = null;

  function cfg() {
    return window.KS_LICENSE_CONFIG || {};
  }

  function getCode() {
    return String(cfg().licenseCode || '').trim().toUpperCase();
  }

  function requiredFirebaseReady() {
    const f = cfg().firebase || {};
    const required = ['apiKey', 'authDomain', 'projectId', 'storageBucket', 'messagingSenderId', 'appId'];
    return required.every(key => f[key] && !String(f[key]).startsWith('GANTI_'));
  }

  function el(id) {
    return document.getElementById(id);
  }

  function gateVisible(visible) {
    const gate = el('ks-license-gate');
    if (!gate) return;
    gate.classList.toggle('hidden', !visible);
  }

  function formatDate(value) {
    if (!value) return '-';
    const d = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(d.getTime())) return '-';
    return d.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', year: 'numeric' });
  }

  function toDate(value) {
    if (!value) return null;
    if (value instanceof Date) return value;
    if (value && typeof value.toDate === 'function') return value.toDate();
    if (value && typeof value.seconds === 'number') return new Date(value.seconds * 1000);
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  function remainingDays(expiry) {
    const d = toDate(expiry);
    if (!d) return 0;
    return Math.max(0, Math.ceil((d.getTime() - Date.now()) / DAY_MS));
  }

  function deriveStatus(data) {
    const publicStatus = String(data?.status || '').toLowerCase();
    if (publicStatus === 'suspended') return 'suspended';

    const expiry = toDate(data?.expiresAt);
    if (!expiry || expiry.getTime() <= Date.now()) return 'expired';

    const warningDays = Math.max(0, Number(data?.warningDays ?? 14));
    return remainingDays(expiry) <= warningDays ? 'warning' : 'active';
  }

  function setBadge(status, text) {
    const badge = el('ks-license-status-badge');
    if (!badge) return;
    badge.className = '';
    badge.id = 'ks-license-status-badge';
    badge.innerText = text;
    badge.classList.add(status === 'checking' ? 'is-checking' : status === 'active' ? 'is-active' : status === 'warning' ? 'is-warning' : 'is-blocked');
  }

  function setGate(status, title, message, expiry) {
    const code = getCode() || '-';
    if (el('ks-license-gate-title')) el('ks-license-gate-title').innerText = title;
    if (el('ks-license-gate-message')) el('ks-license-gate-message').innerText = message;
    if (el('ks-license-code-view')) el('ks-license-code-view').innerText = code;
    if (el('ks-license-status-view')) el('ks-license-status-view').innerText = status.toUpperCase();
    if (el('ks-license-expiry-view')) el('ks-license-expiry-view').innerText = formatDate(expiry);
  }

  function showWarning(message) {
    const box = el('ks-license-warning');
    if (!box) return;
    box.innerText = message;
    box.classList.add('is-visible');
  }

  function clearWarning() {
    const box = el('ks-license-warning');
    if (!box) return;
    box.innerText = '';
    box.classList.remove('is-visible');
  }

  function setAppStateAllowed() {
    document.body.classList.remove('ks-license-pending', 'ks-license-blocked');
    gateVisible(false);
  }

  function setAppStateBlocked() {
    document.body.classList.remove('ks-license-pending');
    document.body.classList.add('ks-license-blocked');
    gateVisible(true);
  }

  function cacheWrite(payload) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(payload));
    } catch (error) {
      console.warn('License cache write failed:', error);
    }
  }

  function cacheRead() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (error) {
      return null;
    }
  }

  function cacheAllowsOffline() {
    const cached = cacheRead();
    if (!cached) return false;
    const checkedAt = Number(cached.checkedAt || 0);
    const graceMs = Math.max(0, Number(cfg().offlineGraceHours ?? 24)) * 60 * 60 * 1000;
    const expiry = toDate(cached.expiresAt);
    const status = String(cached.status || '').toLowerCase();
    if (!checkedAt || Date.now() - checkedAt > graceMs) return false;
    if (!expiry || expiry.getTime() <= Date.now()) return false;
    return status === 'active' || status === 'warning';
  }

  function normalizePayload(data) {
    return {
      licenseCode: getCode(),
      status: deriveStatus(data),
      expiresAt: (() => {
        const d = toDate(data?.expiresAt);
        return d ? d.toISOString() : null;
      })(),
      warningDays: Math.max(0, Number(data?.warningDays ?? 14)),
      version: Number(data?.version ?? 1),
      updatedAt: (() => {
        const d = toDate(data?.updatedAt);
        return d ? d.toISOString() : null;
      })(),
      checkedAt: Date.now()
    };
  }

  function initLicenseFirebase() {
    if (!window.firebase) throw new Error('Firebase SDK belum tersedia.');
    if (!requiredFirebaseReady()) throw new Error('Konfigurasi License Management belum lengkap.');

    const appName = 'kartustock-license-management';
    const existing = (firebase.apps || []).find(app => app.name === appName);
    licenseApp = existing || firebase.initializeApp(cfg().firebase, appName);
    licenseDb = licenseApp.firestore();
    return licenseDb;
  }

  async function fetchLicense() {
    const db = licenseDb || initLicenseFirebase();
    const code = getCode();
    if (!code) throw new Error('License Code belum diatur.');

    const snap = await db.collection('licensePublic').doc(code).get();
    if (!snap.exists) {
      const error = new Error('License tidak ditemukan.');
      error.code = 'not-found';
      throw error;
    }
    return normalizePayload(snap.data());
  }

  async function runCheck() {
    clearWarning();
    setBadge('checking', 'LICENSE CHECKING...');
    setGate('checking', 'Memeriksa License...', 'Mohon tunggu. Kartu Stock sedang memverifikasi license.');
    gateVisible(true);
    document.body.classList.add('ks-license-pending');
    document.body.classList.remove('ks-license-blocked');

    try {
      const result = await fetchLicense();
      lastResult = result;
      cacheWrite(result);

      if (result.status === 'active') {
        setBadge('active', 'LICENSE ACTIVE');
        setGate('active', 'License Valid', `Kartu Stock siap digunakan.\nSisa ${remainingDays(result.expiresAt)} hari.` , result.expiresAt);
        setAppStateAllowed();
        return true;
      }

      if (result.status === 'warning') {
        setBadge('warning', `LICENSE WARNING · ${remainingDays(result.expiresAt)} HARI`);
        setGate('warning', 'License Mendekati Expiry', `License masih valid, tetapi masa berlaku segera berakhir.\nSisa ${remainingDays(result.expiresAt)} hari.`, result.expiresAt);
        setAppStateAllowed();
        showWarning(`License KARTU STOCK masuk WARNING. Sisa ${remainingDays(result.expiresAt)} hari.`);
        return true;
      }

      const title = result.status === 'suspended' ? 'License Suspended' : 'License Expired';
      const message = result.status === 'suspended'
        ? 'License saat ini dinonaktifkan oleh Owner. Kartu Stock tidak dapat digunakan.'
        : 'Masa berlaku license sudah berakhir. Hubungi Owner untuk perpanjangan.';
      setBadge('blocked', `LICENSE ${result.status.toUpperCase()}`);
      setGate(result.status, title, message, result.expiresAt);
      setAppStateBlocked();
      return false;
    } catch (error) {
      console.error('KARTU STOCK license check failed:', error);

      if (cacheAllowsOffline()) {
        const cached = cacheRead();
        lastResult = cached;
        setBadge('warning', 'LICENSE OFFLINE GRACE');
        setGate('warning', 'Server License Tidak Terjangkau', 'Koneksi ke License Management sedang bermasalah.\nKartu Stock memakai cache license yang terakhir berhasil, sementara.', cached?.expiresAt);
        setAppStateAllowed();
        showWarning('License server tidak terjangkau. Mode offline grace aktif sementara.');
        return true;
      }

      const status = error?.code === 'not-found' ? 'not-found' : 'config-error';
      setBadge('blocked', status === 'not-found' ? 'LICENSE NOT FOUND' : 'LICENSE CHECK FAILED');
      setGate(status, status === 'not-found' ? 'License Tidak Ditemukan' : 'License Check Gagal', error?.message || 'License tidak dapat diverifikasi. Kartu Stock dikunci sampai pemeriksaan berhasil.', null);
      setAppStateBlocked();
      return false;
    }
  }

  function block(message) {
    setBadge('blocked', 'LICENSE BLOCKED');
    setGate('blocked', 'Aplikasi Dikunci', message || 'Aplikasi tidak dapat digunakan sebelum license valid.', lastResult?.expiresAt);
    setAppStateBlocked();
  }

  async function initializeKSLicenseGuard() {
    if (!el('ks-license-retry')) throw new Error('License gate UI tidak ditemukan.');
    el('ks-license-retry').onclick = runCheck;
    return runCheck();
  }

  window.initializeKSLicenseGuard = initializeKSLicenseGuard;
  window.KSLicenseUI = { block, check: runCheck };
  window.KSLicense = {
    getCode,
    getStatus: () => lastResult ? String(lastResult.status || '').toLowerCase() : 'checking',
    getResult: () => lastResult ? { ...lastResult } : null,
    recheck: runCheck
  };
})();
