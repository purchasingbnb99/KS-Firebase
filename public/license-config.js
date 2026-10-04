/*
 * KARTU STOCK — License Client Configuration
 *
 * Ubah HANYA file ini jika license/customer berubah.
 * Jangan menaruh Service Account / private key di frontend.
 */
window.KS_LICENSE_CONFIG = Object.freeze({
  appName: 'KARTU STOCK',
  licenseCode: 'LIC-6E9D101N',

  // License Management project (bukan project Kartu Stock).
  // Isi apiKey dan appId dari Firebase Web App milik License Management.
  firebase: {
    apiKey: 'AIzaSyBoEpf4J-_k4q0sWeUPEX-iKJC2HFKNqr0SHBOARD',
    authDomain: 'license-management-6355c.firebaseapp.com',
    projectId: 'license-management-6355c',
    storageBucket: 'license-management-6355c.firebasestorage.app',
    messagingSenderId: '973389684293',
    appId: '1:1003835562694:web:46b8c202365ce08c5655c7'
  },

  // Jika internet sementara putus setelah pernah sukses check,
  // aplikasi boleh memakai cache license valid maksimal 24 jam.
  offlineGraceHours: 24
});
