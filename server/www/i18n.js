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
      tag_i18n: "Multilingual",
      cl_340_1: "3-language support in desktop app: Ukrainian, English, German",
      cl_340_2: "Live language switching without restart",
      cl_340_3: "Multilingual landing page: UA / EN / DE",
      cl_340_4: "Clickable website link in help section",
      cl_340_5: "Linter fixes and code refactoring",
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
      preview_title: "See it in action",
      preview_sub: "This is what a secure file transfer looks like from start to finish",
      preview_cap1_title: "Connection",
      preview_cap1_desc: "Key exchange and connection verification",
      preview_cap2_title: "Verification",
      preview_cap2_desc: "Security code protects against MITM attacks",
      preview_cap3_title: "Sending",
      preview_cap3_desc: "Real-time E2E encryption, 15+ MB/s",
      preview_cap4_title: "Receiving",
      preview_cap4_desc: "Automatic decryption and integrity check",
      faq_title: "Frequently Asked Questions",
      faq_sub: "Answers to the most common questions about SecureShare",
      faq_q1: "Are my files really encrypted?",
      faq_a1: "Yes. Every file is encrypted on the sender\u2019s device using AES-256-GCM with a unique key generated via X25519. The relay server only sees encrypted data and has no way to decrypt it.",
      faq_q2: "What is the maximum file size?",
      faq_a2: "Up to 5 GB. Files are transferred in 256 KB chunks with interrupted transfer resumption \u2014 even if the connection drops, you don\u2019t need to start over.",
      faq_q3: "Is registration required?",
      faq_a3: "No. Just download the app, choose a file, and share the session code with the recipient. No account, email, or phone needed.",
      faq_q4: "What is the verification code?",
      faq_a4: "After connecting, both participants see the same 8-character code. If the codes match \u2014 the connection is secure. This protects against man-in-the-middle (MITM) attacks.",
      faq_q5: "Which operating systems are supported?",
      faq_a5: "Windows 10/11 and Linux (x64). The app requires no installation \u2014 just download and run.",
      faq_q6: "Are files stored on the server?",
      faq_a6: "No. The relay server only forwards encrypted packets between participants in real time. After the transfer is complete \u2014 zero traces. Session codes are hashed and not logged.",
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
      footer_faq: "FAQ",
      footer_docs: "Documentation",
      footer_devs: "For developers",
      footer_changelog: "What\u2019s new",
      footer_bug: "Report a bug",
      footer_support: "Support"
    },
    de: {
      hero_subtitle: "Dateien direkt zwischen Ger\u00e4ten mit Ende-zu-Ende-Verschl\u00fcsselung \u00fcbertragen. Ohne Registrierung, ohne Cloud, ohne Spuren.",
      badge_no_reg: "Ohne Registrierung",
      badge_5gb: "Bis zu 5 GB",
      features_title: "Warum SecureShare?",
      features_sub: "Entwickelt f\u00fcr alle, die Privatsph\u00e4re und Einfachheit sch\u00e4tzen",
      feat_e2e_title: "Ende-zu-Ende-Verschl\u00fcsselung",
      feat_e2e_desc: "X25519-Schl\u00fcsselaustausch + AES-256-GCM. Der Server sieht nur Chiffretext \u2014 niemals Ihre Daten.",
      feat_noreg_title: "Ohne Registrierung",
      feat_noreg_desc: "Kein Konto, keine E-Mail, kein Telefon n\u00f6tig. Einfach die App \u00f6ffnen und den Sitzungscode teilen.",
      feat_5gb_title: "Bis zu 5 GB",
      feat_5gb_desc: "Gro\u00dfe Dateien ohne Cloud-Beschr\u00e4nkungen \u00fcbertragen. Wiederaufnahme unterbrochener \u00dcbertragungen inklusive.",
      feat_reconnect_title: "Auto-Reconnect",
      feat_reconnect_desc: "Verbindung verloren? Die App verbindet sich automatisch wieder und setzt dort fort, wo sie aufgeh\u00f6rt hat.",
      feat_verify_title: "Verifizierung",
      feat_verify_desc: "Der Verifizierungscode stellt sicher, dass Sie mit der richtigen Person kommunizieren. Schutz vor MITM-Angriffen.",
      feat_nocloud_title: "Kein Cloud-Speicher",
      feat_nocloud_desc: "Dateien werden direkt \u00fcbertragen. Nichts wird auf dem Server gespeichert \u2014 null Spuren nach der \u00dcbertragung.",
      how_title: "Wie funktioniert es?",
      how_sub: "Drei einfache Schritte \u2014 und Ihre Datei ist sicher",
      step1_title: "Absender erstellt eine Sitzung",
      step1_desc: "Klicken Sie auf \u201eSenden\u201c, w\u00e4hlen Sie eine Datei. Die App generiert einen einzigartigen 8-stelligen Sitzungscode.",
      step2_title: "Empf\u00e4nger verbindet sich",
      step2_desc: "Geben Sie den Code in Ihrer App ein. Beide Ger\u00e4te tauschen Schl\u00fcssel aus und verifizieren die Verbindung.",
      step3_title: "Datei wird \u00fcbertragen",
      step3_desc: "Die Daten werden auf dem Ger\u00e4t des Absenders verschl\u00fcsselt und nur beim Empf\u00e4nger entschl\u00fcsselt. Der Server sieht nur Rauschen.",
      sec_title: "Sicherheit an erster Stelle",
      sec_sub: "Jeder Aspekt wurde mit Blick auf Privatsph\u00e4re entwickelt",
      sec_x25519: "Elliptische-Kurven-Diffie-Hellman zur Erzeugung eines gemeinsamen Schl\u00fcssels ohne \u00dcbertragung von Geheimnissen \u00fcber das Netzwerk.",
      sec_aes_title: "AES-256-GCM mit AAD",
      sec_aes: "Authentifizierte Verschl\u00fcsselung. Der Sitzungscode ist als Associated Data gebunden \u2014 verhindert Chiffretext-Substitution.",
      sec_sha_title: "SHA-256 Integrit\u00e4tspr\u00fcfung",
      sec_sha: "Jede \u00fcbertragene Datei wird per Hash verifiziert. Selbst ein einziges ge\u00e4ndertes Byte wird erkannt.",
      sec_tls_title: "TLS 1.3 Transport",
      sec_tls: "WebSocket \u00fcber WSS mit automatischem Let\u2019s-Encrypt-Zertifikat. Doppelte Verschl\u00fcsselungsschicht.",
      sec_zk_title: "Zero-Knowledge-Server",
      sec_zk: "Der Relay-Server sieht niemals Dateiinhalte. Sitzungscodes werden gehasht \u2014 keinerlei Inhalts-Logs.",
      sec_oss_title: "Open Source",
      sec_oss: "Der gesamte Code ist auf GitHub verf\u00fcgbar. Pr\u00fcfen, auditieren und Verbesserungen vorschlagen.",
      cta_title: "Bereit, Dateien sicher zu \u00fcbertragen?",
      cta_sub: "Laden Sie SecureShare kostenlos herunter. Ohne Registrierung, ohne Einschr\u00e4nkungen.",
      changelog_title: "Entwicklungsgeschichte",
      changelog_sub: "Das Projekt entwickelt sich aktiv weiter \u2014 jede Version macht den Dateitransfer sicherer und komfortabler",
      date_feb_2026: "Februar 2026",
      date_jan_2026: "Januar 2026",
      tag_security: "Sicherheit",
      tag_major: "Gro\u00dfes Release",
      tag_features: "Features",
      tag_first_release: "Erstes Release",
      tag_i18n: "Mehrsprachigkeit",
      cl_340_1: "3 Sprachen in der Desktop-App: Ukrainisch, Englisch, Deutsch",
      cl_340_2: "Live-Sprachwechsel ohne Neustart",
      cl_340_3: "Mehrsprachige Landingpage: UA / EN / DE",
      cl_340_4: "Klickbarer Website-Link im Hilfe-Bereich",
      cl_340_5: "Linter-Fixes und Code-Refactoring",
      cl_331_1: "Umfassendes Sicherheitsaudit: 87 Tests, 6 behobene Schwachstellen",
      cl_331_2: "Schutz vor IP-Spoofing, CRLF-Injection, Memory-DoS",
      cl_331_3: "CVE-2026-26007 \u2014 Aktualisierung kryptografischer Bibliotheken",
      cl_331_4: "pip-audit in CI \u2014 automatische CVE-\u00dcberwachung",
      cl_331_5: "Zuverl\u00e4ssiges Auto-Update: Rename+Copy statt Bat-Skript",
      cl_331_6: "Schutz vor Updates aus Archiv-/Temp-Ordnern",
      cl_331_7: "UI-Redesign: Symbolleiste mit beschrifteten Buttons, neue Hilfe-Abschnitte",
      cl_331_8: "CI-Build-Kompatibilit\u00e4t: Python 3.12.10 + PyInstaller 6.19.0 gepinnt",
      cl_330_1: "Auto-Update mit SHA-256-Verifizierung und Integrit\u00e4tspr\u00fcfung",
      cl_330_2: "Anonyme Telemetrie und Crash-Reporting",
      cl_330_3: "Admin-Dashboard mit Diagrammen und Statistiken",
      cl_330_4: "Spendenunterst\u00fctzung \u00fcber Ko-fi",
      cl_330_5: "CI/CD in 4 unabh\u00e4ngige Workflows aufgeteilt",
      cl_330_6: "MIT-Lizenz \u2014 vollst\u00e4ndig Open Source",
      cl_32_1: "Linux-Build \u2014 plattform\u00fcbergreifende Unterst\u00fctzung",
      cl_32_2: "Auto-Reconnect bei Verbindungsverlust",
      cl_32_3: "Wiederaufnahme unterbrochener \u00dcbertragungen (Resume)",
      cl_32_4: "Landingpage f\u00fcr den Relay-Server",
      cl_32_5: "DNS-Retry \u2014 stabilere Verbindungen",
      cl_30_1: "E2E-Verschl\u00fcsselung: X25519 + AES-256-GCM + SHA-256",
      cl_30_2: "VPS-Relay-Server mit Docker + Caddy + TLS 1.3",
      cl_30_3: "Benutzerfreundliche GUI mit Fortschrittsanzeige und Verifizierung",
      cl_30_4: "CI/CD: automatischer Build, Tests, Deployment",
      cl_30_5: "Pentest und grundlegende Sicherheitsh\u00e4rtung",
      cl_30_6: "Dokumentation f\u00fcr Benutzer und Entwickler",
      preview_title: "Sehen Sie es in Aktion",
      preview_sub: "So sieht eine sichere Datei\u00fcbertragung von Anfang bis Ende aus",
      preview_cap1_title: "Verbindung",
      preview_cap1_desc: "Schl\u00fcsselaustausch und Verbindungsverifizierung",
      preview_cap2_title: "Verifizierung",
      preview_cap2_desc: "Sicherheitscode sch\u00fctzt vor MITM-Angriffen",
      preview_cap3_title: "Senden",
      preview_cap3_desc: "Echtzeit-E2E-Verschl\u00fcsselung, 15+ MB/s",
      preview_cap4_title: "Empfangen",
      preview_cap4_desc: "Automatische Entschl\u00fcsselung und Integrit\u00e4tspr\u00fcfung",
      faq_title: "H\u00e4ufig gestellte Fragen",
      faq_sub: "Antworten auf die h\u00e4ufigsten Fragen zu SecureShare",
      faq_q1: "Werden meine Dateien wirklich verschl\u00fcsselt?",
      faq_a1: "Ja. Jede Datei wird auf dem Ger\u00e4t des Absenders mit AES-256-GCM und einem \u00fcber X25519 erzeugten Schl\u00fcssel verschl\u00fcsselt. Der Relay-Server sieht nur verschl\u00fcsselte Daten und kann sie nicht entschl\u00fcsseln.",
      faq_q2: "Wie gro\u00df darf eine Datei maximal sein?",
      faq_a2: "Bis zu 5 GB. Dateien werden in 256-KB-Bl\u00f6cken \u00fcbertragen, mit Wiederaufnahme unterbrochener \u00dcbertragungen \u2014 selbst bei Verbindungsabbruch muss nicht von vorne begonnen werden.",
      faq_q3: "Ist eine Registrierung erforderlich?",
      faq_a3: "Nein. Laden Sie einfach die App herunter, w\u00e4hlen Sie eine Datei und teilen Sie den Sitzungscode mit dem Empf\u00e4nger. Kein Konto, keine E-Mail, kein Telefon n\u00f6tig.",
      faq_q4: "Was ist der Verifizierungscode?",
      faq_a4: "Nach der Verbindung sehen beide Teilnehmer denselben 8-stelligen Code. Stimmen die Codes \u00fcberein, ist die Verbindung sicher. Dies sch\u00fctzt vor Man-in-the-Middle-Angriffen (MITM).",
      faq_q5: "Welche Betriebssysteme werden unterst\u00fctzt?",
      faq_a5: "Windows 10/11 und Linux (x64). Die App erfordert keine Installation \u2014 einfach herunterladen und starten.",
      faq_q6: "Werden Dateien auf dem Server gespeichert?",
      faq_a6: "Nein. Der Relay-Server leitet nur verschl\u00fcsselte Pakete in Echtzeit zwischen den Teilnehmern weiter. Nach Abschluss der \u00dcbertragung \u2014 null Spuren. Sitzungscodes werden gehasht und nicht protokolliert.",
      all_releases: "Alle Releases auf GitHub",
      support_title: "Unterst\u00fctzen Sie das Projekt",
      support_text1: "SecureShare ist ein <strong>kostenloses Open-Source-Projekt</strong>, das von einer Person in der Freizeit entwickelt wird. Server, Domain und Entwicklung kosten Geld, und Motivation braucht Ihre Unterst\u00fctzung.",
      support_text2: "Jede Tasse Kaffee hilft, den Relay-Server online zu halten, die Sicherheit zu verbessern und neue Features hinzuzuf\u00fcgen. Selbst eine kleine Spende ist ein Zeichen, dass dieses Projekt Menschen wichtig ist.",
      support_server: "Server",
      support_server_desc: "Relay l\u00e4uft 24/7 f\u00fcr Sie",
      support_security: "Sicherheit",
      support_security_desc: "Audits, Updates, Patches",
      support_dev: "Entwicklung",
      support_dev_desc: "Neue Plattformen und Features",
      support_btn: "Einen Kaffee spendieren",
      support_note: "Sie k\u00f6nnen uns auch einen Stern auf <a href=\"https://github.com/artmarchenko/SecureShare\" target=\"_blank\" rel=\"noopener\">GitHub</a> geben \u2014 das ist kostenlos und sehr motivierend!",
      footer_faq: "FAQ",
      footer_docs: "Dokumentation",
      footer_devs: "F\u00fcr Entwickler",
      footer_changelog: "Was gibt\u2019s Neues",
      footer_bug: "Fehler melden",
      footer_support: "Unterst\u00fctzen"
    }
  };

  var TITLES = {
    uk: "SecureShare \u2014 \u0411\u0435\u0437\u043f\u0435\u0447\u043d\u0430 \u043f\u0435\u0440\u0435\u0434\u0430\u0447\u0430 \u0444\u0430\u0439\u043b\u0456\u0432",
    en: "SecureShare \u2014 Secure File Transfer",
    de: "SecureShare \u2014 Sichere Datei\u00fcbertragung"
  };

  var LANG_CODES = { uk: "uk", en: "en", de: "de" };

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
    document.documentElement.lang = LANG_CODES[lang] || lang;
    document.title = TITLES[lang] || TITLES['uk'];

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
  document.getElementById('btnDe').addEventListener('click', function() { setLang('de'); });

  cacheUk();
  var saved = 'uk';
  try { saved = localStorage.getItem('ss_lang') || 'uk'; } catch(e) {}
  if (saved !== 'uk') applyLang(saved);

  /* ── Theme Toggle (dark / light) ─────────────── */
  var themeBtn = document.getElementById('themeToggle');
  var iconSun  = themeBtn ? themeBtn.querySelector('.icon-sun') : null;
  var iconMoon = themeBtn ? themeBtn.querySelector('.icon-moon') : null;

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (iconSun && iconMoon) {
      iconSun.style.display  = theme === 'dark' ? 'block' : 'none';
      iconMoon.style.display = theme === 'dark' ? 'none'  : 'block';
    }
    try { localStorage.setItem('ss-theme', theme); } catch(e) {}
  }

  /* init: check saved pref or OS pref */
  var savedTheme = null;
  try { savedTheme = localStorage.getItem('ss-theme'); } catch(e) {}
  if (savedTheme) {
    applyTheme(savedTheme);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    applyTheme('dark');
  }

  if (themeBtn) {
    themeBtn.addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme');
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });
  }

  /* ── Scroll Reveal (IntersectionObserver) ──────── */
  if ('IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(function(entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) {
          entries[i].target.classList.add('visible');
          revealObserver.unobserve(entries[i].target);
        }
      }
    }, { threshold: 0.15 });
    var fadeEls = document.querySelectorAll('.fade-up');
    for (var i = 0; i < fadeEls.length; i++) {
      revealObserver.observe(fadeEls[i]);
    }
  } else {
    /* fallback: show everything if IO unsupported */
    var fadeEls2 = document.querySelectorAll('.fade-up');
    for (var i = 0; i < fadeEls2.length; i++) {
      fadeEls2[i].classList.add('visible');
    }
  }

  /* ── FAQ Accordion ──────────────────────────────── */
  var faqItems = document.querySelectorAll('.faq-item');
  for (var f = 0; f < faqItems.length; f++) {
    (function(item) {
      var btn = item.querySelector('.faq-q');
      if (btn) {
        btn.addEventListener('click', function() {
          var isOpen = item.classList.contains('open');
          /* close all */
          for (var k = 0; k < faqItems.length; k++) {
            faqItems[k].classList.remove('open');
            var b = faqItems[k].querySelector('.faq-q');
            if (b) b.setAttribute('aria-expanded', 'false');
          }
          /* toggle clicked */
          if (!isOpen) {
            item.classList.add('open');
            btn.setAttribute('aria-expanded', 'true');
          }
        });
      }
    })(faqItems[f]);
  }

  /* ── Gallery Carousel ─────────────────────────── */
  var track = document.getElementById('galTrack');
  var dots  = document.querySelectorAll('#galDots .dot');
  var prev  = document.getElementById('galPrev');
  var next  = document.getElementById('galNext');

  if (track && dots.length) {
    var cards = track.querySelectorAll('.gallery-card');
    var current = 0;

    function scrollToCard(idx) {
      if (idx < 0) idx = cards.length - 1;
      if (idx >= cards.length) idx = 0;
      current = idx;
      cards[idx].scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
      updateDots();
    }

    function updateDots() {
      for (var i = 0; i < dots.length; i++) {
        dots[i].className = i === current ? 'dot active' : 'dot';
      }
    }

    prev.addEventListener('click', function() { scrollToCard(current - 1); });
    next.addEventListener('click', function() { scrollToCard(current + 1); });

    for (var d = 0; d < dots.length; d++) {
      (function(idx) {
        dots[idx].addEventListener('click', function() { scrollToCard(idx); });
      })(d);
    }

    /* sync dots on manual scroll */
    var scrollTimer;
    track.addEventListener('scroll', function() {
      clearTimeout(scrollTimer);
      scrollTimer = setTimeout(function() {
        var trackRect = track.getBoundingClientRect();
        var center = trackRect.left + trackRect.width / 2;
        var closest = 0;
        var minDist = Infinity;
        for (var i = 0; i < cards.length; i++) {
          var r = cards[i].getBoundingClientRect();
          var cardCenter = r.left + r.width / 2;
          var dist = Math.abs(cardCenter - center);
          if (dist < minDist) { minDist = dist; closest = i; }
        }
        current = closest;
        updateDots();
      }, 80);
    });
  }
})();
