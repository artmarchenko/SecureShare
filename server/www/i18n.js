(function() {
  var T = {
    en: {
      hero_subtitle: "Transfer files directly between devices with end-to-end encryption. No registration, no cloud, no traces.",
      badge_no_reg: "No registration",
      badge_5gb: "Up to 5 GB",
      features_title: "Why SecureShare?",
      features_sub: "Built for those who value privacy and simplicity",
      feat_e2e_title: "End-to-end encryption",
      feat_e2e_desc: "X25519 key exchange + AES-256-GCM. The server only sees ciphertext \u2014 never your data.",
      feat_noreg_title: "No registration",
      feat_noreg_desc: "No account, email, or phone needed. Just open the app and share the session code.",
      feat_5gb_title: "Up to 5 GB",
      feat_5gb_desc: "Transfer large files without cloud service limits. Interrupted transfer resumption included.",
      feat_reconnect_title: "Auto-reconnect",
      feat_reconnect_desc: "Lost connection? The app will automatically reconnect and resume from where it left off.",
      feat_verify_title: "Verification",
      feat_verify_desc: "Verification code ensures you\u2019re communicating with the right person. MITM attack protection.",
      feat_nocloud_title: "No cloud storage",
      feat_nocloud_desc: "Files are transferred directly. Nothing is stored on the server \u2014 zero traces after transfer.",
      how_title: "How does it work?",
      how_sub: "Three simple steps \u2014 and your file is secure",
      step1_title: "Sender creates a session",
      step1_desc: "Click \u201cSend\u201d, choose a file. The app generates a unique 8-character session code.",
      step2_title: "Receiver connects",
      step2_desc: "Enter the code in your app. Both devices exchange keys and verify the connection.",
      step3_title: "File is transferred",
      step3_desc: "Data is encrypted on the sender\u2019s device and decrypted only on the receiver\u2019s. The server sees only noise.",
      sec_title: "Security first",
      sec_sub: "Every aspect is designed with privacy in mind",
      sec_x25519: "Elliptic-curve Diffie-Hellman for generating a shared key without transmitting secrets over the network.",
      sec_aes_title: "AES-256-GCM with AAD",
      sec_aes: "Authenticated encryption. Session code is bound as Associated Data \u2014 prevents ciphertext substitution.",
      sec_sha_title: "SHA-256 integrity check",
      sec_sha: "Every transferred file is verified by hash. Even a single changed byte will be detected.",
      sec_tls_title: "TLS 1.3 transport",
      sec_tls: "WebSocket over WSS with automatic Let\u2019s Encrypt certificate. Double layer of encryption.",
      sec_zk_title: "Zero-knowledge server",
      sec_zk: "The relay server never sees file contents. Session codes are hashed \u2014 no content logs whatsoever.",
      sec_oss_title: "Open source",
      sec_oss: "All code is available on GitHub. Review, audit, and suggest improvements.",
      cta_title: "Ready to transfer files securely?",
      cta_sub: "Download SecureShare for free. No registration, no limits.",
      changelog_title: "Development history",
      changelog_sub: "The project is actively evolving \u2014 each version makes file transfer more secure and convenient",
      date_feb_2026: "February 2026",
      date_jan_2026: "January 2026",
      tag_security: "Security",
      tag_major: "Major release",
      tag_features: "Features",
      tag_first_release: "First release",
      cl_331_1: "Comprehensive security audit: 87 tests, 6 vulnerabilities fixed",
      cl_331_2: "Protection against IP spoofing, CRLF injection, memory DoS",
      cl_331_3: "CVE-2026-26007 \u2014 cryptographic library updates",
      cl_331_4: "pip-audit in CI \u2014 automatic CVE monitoring",
      cl_331_5: "Reliable auto-update: rename+copy instead of bat script",
      cl_331_6: "Protection against updating from archive/temp folders",
      cl_331_7: "UI redesign: toolbar with labeled buttons, new help sections",
      cl_331_8: "CI build compatibility: pinned Python 3.12.10 + PyInstaller 6.19.0",
      cl_330_1: "Auto-update with SHA-256 verification and integrity check",
      cl_330_2: "Anonymous telemetry and crash reporting",
      cl_330_3: "Admin dashboard with charts and statistics",
      cl_330_4: "Donation support via Ko-fi",
      cl_330_5: "CI/CD split into 4 independent workflows",
      cl_330_6: "MIT license \u2014 fully open source",
      cl_32_1: "Linux build \u2014 cross-platform support",
      cl_32_2: "Auto-reconnect on connection loss",
      cl_32_3: "Interrupted transfer resumption (resume)",
      cl_32_4: "Landing page for relay server",
      cl_32_5: "DNS retry \u2014 more stable connections",
      cl_30_1: "E2E encryption: X25519 + AES-256-GCM + SHA-256",
      cl_30_2: "VPS relay server with Docker + Caddy + TLS 1.3",
      cl_30_3: "User-friendly GUI with progress bar and verification",
      cl_30_4: "CI/CD: automated build, tests, deployment",
      cl_30_5: "Pentest and basic security hardening",
      cl_30_6: "Documentation for users and developers",
      all_releases: "All releases on GitHub",
      support_title: "Support the project",
      support_text1: "SecureShare is a <strong>free open-source project</strong> created by one person in their spare time. Server, domain, and development cost money, and motivation needs your support.",
      support_text2: "Every cup of coffee helps keep the relay server online, improve security, and add new features. Even a small donation is a signal that this project matters to people.",
      support_server: "Server",
      support_server_desc: "Relay runs 24/7 for you",
      support_security: "Security",
      support_security_desc: "Audits, updates, patches",
      support_dev: "Development",
      support_dev_desc: "New platforms and features",
      support_btn: "Buy me a coffee",
      support_note: "You can also star us on <a href=\"https://github.com/artmarchenko/SecureShare\" target=\"_blank\" rel=\"noopener\">GitHub</a> \u2014 it\u2019s free and very motivating!",
      footer_docs: "Documentation",
      footer_devs: "For developers",
      footer_changelog: "What\u2019s new",
      footer_bug: "Report a bug",
      footer_support: "Support"
    }
  };

  var ukTexts = {};

  function cacheUk() {
    var els = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < els.length; i++) {
      ukTexts[els[i].getAttribute('data-i18n')] = els[i].innerHTML;
    }
  }

  function applyLang(lang) {
    var els = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < els.length; i++) {
      var key = els[i].getAttribute('data-i18n');
      if (lang === 'uk') {
        if (ukTexts[key]) els[i].innerHTML = ukTexts[key];
      } else if (T[lang] && T[lang][key]) {
        els[i].innerHTML = T[lang][key];
      }
    }
    document.documentElement.lang = (lang === 'uk') ? 'uk' : 'en';
    document.title = (lang === 'uk')
      ? 'SecureShare \u2014 \u0411\u0435\u0437\u043f\u0435\u0447\u043d\u0430 \u043f\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043b\u0456\u0432'
      : 'SecureShare \u2014 Secure File Transfer';

    var btns = document.querySelectorAll('.lang-btn');
    for (var j = 0; j < btns.length; j++) {
      if (btns[j].getAttribute('data-lang') === lang) {
        btns[j].className = 'lang-btn active';
      } else {
        btns[j].className = 'lang-btn';
      }
    }
  }

  function setLang(lang) {
    try { localStorage.setItem('ss_lang', lang); } catch(e) {}
    applyLang(lang);
  }

  document.getElementById('btnUk').addEventListener('click', function() { setLang('uk'); });
  document.getElementById('btnEn').addEventListener('click', function() { setLang('en'); });

  cacheUk();
  var saved = 'uk';
  try { saved = localStorage.getItem('ss_lang') || 'uk'; } catch(e) {}
  if (saved !== 'uk') applyLang(saved);
})();
