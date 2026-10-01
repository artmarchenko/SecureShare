// Invitation page /r#<code>. The code lives only in the URL fragment, which
// the browser never sends to the server; this script makes no requests.
(function () {
  var T = {
    uk: {
      title: "Вам надсилають файл через SecureShare",
      sub: "Передача зашифрована наскрізно: файл бачите лише ви й відправник.",
      code_label: "Код сесії",
      copy: "Копіювати код",
      copied: "Скопійовано ✓",
      bad: "Посилання пошкоджене — попросіть відправника надіслати його ще раз.",
      open_app: "Відкрити в SecureShare",
      get_android: "Завантажити SecureShare для Android",
      android_note: "Після встановлення відкрийте це посилання ще раз — код підставиться сам.",
      step1: "Відкрийте SecureShare на комп'ютері (версія 4.0 або новіша).",
      step2: "Вкладка «Отримати» → вставте код.",
      step3: "Порівняйте код перевірки з відправником і підтвердіть.",
      privacy: "Код не залишає ваш браузер: сервер SecureShare його не отримує.",
      more: "Що таке SecureShare?"
    },
    en: {
      title: "Someone is sending you a file with SecureShare",
      sub: "The transfer is end-to-end encrypted: only you and the sender can see the file.",
      code_label: "Session code",
      copy: "Copy code",
      copied: "Copied ✓",
      bad: "The link is damaged — ask the sender to send it again.",
      open_app: "Open in SecureShare",
      get_android: "Get SecureShare for Android",
      android_note: "After installing, open this link again — the code is filled in for you.",
      step1: "Open SecureShare on your computer (version 4.0 or newer).",
      step2: "Receive tab → paste the code.",
      step3: "Compare the verification code with the sender and confirm.",
      privacy: "The code never leaves your browser: the SecureShare server does not receive it.",
      more: "What is SecureShare?"
    },
    de: {
      title: "Dir wird eine Datei mit SecureShare gesendet",
      sub: "Die Übertragung ist Ende-zu-Ende-verschlüsselt: Nur du und der Absender sehen die Datei.",
      code_label: "Sitzungscode",
      copy: "Code kopieren",
      copied: "Kopiert ✓",
      bad: "Der Link ist beschädigt — bitte den Absender, ihn erneut zu senden.",
      open_app: "In SecureShare öffnen",
      get_android: "SecureShare für Android laden",
      android_note: "Nach der Installation diesen Link erneut öffnen — der Code wird automatisch eingetragen.",
      step1: "SecureShare am Computer öffnen (Version 4.0 oder neuer).",
      step2: "Tab „Empfangen“ → Code einfügen.",
      step3: "Prüfcode mit dem Absender vergleichen und bestätigen.",
      privacy: "Der Code verlässt deinen Browser nicht: Der SecureShare-Server erhält ihn nicht.",
      more: "Was ist SecureShare?"
    }
  };

  var lang = null;
  try { lang = localStorage.getItem("ss_lang"); } catch (e) {}
  if (!T[lang]) {
    var nav = (navigator.language || "en").slice(0, 2).toLowerCase();
    lang = T[nav] ? nav : "en";
  }
  var t = T[lang];
  document.documentElement.lang = lang;
  document.title = t.title + " — SecureShare";
  var nodes = document.querySelectorAll("[data-t]");
  for (var i = 0; i < nodes.length; i++) {
    var k = nodes[i].getAttribute("data-t");
    if (t[k]) nodes[i].textContent = t[k];
  }

  // abcd-1234 / ABCD1234 → abcd-1234; anything else is rejected
  var raw = decodeURIComponent((location.hash || "").slice(1)).replace(/\s+/g, "").toLowerCase();
  var m = /^([a-z0-9]{4})-?([a-z0-9]{4})$/.exec(raw);
  if (!m) {
    document.getElementById("codeCard").classList.add("hidden");
    document.getElementById("bad").classList.remove("hidden");
    return;
  }
  var code = m[1] + "-" + m[2];
  document.getElementById("code").textContent = code;

  var copy = document.getElementById("copy");
  copy.addEventListener("click", function () {
    var done = function () { copy.textContent = t.copied; };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(code).then(done, function () {});
    }
  });

  if (/Android/i.test(navigator.userAgent)) {
    // Chrome opens the app (if installed) without loading anything; the code
    // goes in the query here because an intent: URL uses the fragment itself.
    document.getElementById("openApp").href =
      "intent://" + location.host + "/r?c=" + code +
      "#Intent;scheme=https;package=io.github.artmarchenko.secureshare;" +
      "S.browser_fallback_url=" + encodeURIComponent(location.origin + "/download/SecureShare.apk") + ";end";
    document.getElementById("android").classList.remove("hidden");
  } else {
    document.getElementById("desktop").classList.remove("hidden");
  }
})();
