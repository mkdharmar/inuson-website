/* Inuson International Inc. — Script v2 */
document.addEventListener('DOMContentLoaded', function () {

  /* ── Mobile nav toggle ── */
  var toggle = document.getElementById('nav-toggle');
  var mobileNav = document.getElementById('nav-mobile');
  if (toggle && mobileNav) {
    toggle.addEventListener('click', function () {
      var open = mobileNav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
  }

  /* ── Desktop dropdown (click for touch/keyboard; hover via CSS) ── */
  document.querySelectorAll('.nav-dropdown').forEach(function (dd) {
    var btn = dd.querySelector('.nav-dropdown-btn');
    if (!btn) return;
    btn.addEventListener('click', function (e) {
      var isOpen = dd.classList.contains('open');
      // close all
      document.querySelectorAll('.nav-dropdown.open').forEach(function (d) { d.classList.remove('open'); });
      if (!isOpen) dd.classList.add('open');
    });
  });
  document.addEventListener('click', function (e) {
    if (!e.target.closest('.nav-dropdown')) {
      document.querySelectorAll('.nav-dropdown.open').forEach(function (d) { d.classList.remove('open'); });
    }
  });

  /* ── Mobile dropdown group toggles ── */
  document.querySelectorAll('.nav-mobile-group-head').forEach(function (head) {
    head.addEventListener('click', function () {
      var subId = head.id.replace('-head', '-sub');
      var sub = document.getElementById(subId);
      if (!sub) return;
      var isOpen = sub.classList.contains('open');
      sub.classList.toggle('open', !isOpen);
      head.classList.toggle('open', !isOpen);
    });
  });

  /* ── Auto-detect active nav ── */
  (function () {
    var page = window.location.pathname.split('/').pop() || 'index.html';
    if (!page) page = 'index.html';
    // direct nav links
    document.querySelectorAll('.nav-links .nav-link[href]').forEach(function (a) {
      if (a.getAttribute('href') === page) a.classList.add('active');
    });
    // dropdown buttons — mark active if child matches
    document.querySelectorAll('.nav-dropdown').forEach(function (dd) {
      dd.querySelectorAll('.nav-dropdown-menu a[href]').forEach(function (a) {
        if (a.getAttribute('href') === page) {
          var btn = dd.querySelector('.nav-dropdown-btn');
          if (btn) btn.classList.add('active');
        }
      });
    });
  })();

  /* ── Counter animation ── */
  var counterEls = document.querySelectorAll('[data-counter]');
  if (counterEls.length) {
    var animated = false;
    function runCounters() {
      if (animated) return;
      animated = true;
      counterEls.forEach(function (el) {
        var target = parseFloat(el.getAttribute('data-counter'));
        var suffix = el.getAttribute('data-suffix') || '';
        var dur = 1500;
        var start = Date.now();
        var ease = function (t) { return 1 - Math.pow(1 - t, 3); };
        var timer = setInterval(function () {
          var p = Math.min(1, (Date.now() - start) / dur);
          el.textContent = Math.round(target * ease(p)) + suffix;
          if (p >= 1) clearInterval(timer);
        }, 33);
      });
    }
    var band = document.getElementById('stat-band');
    if (band && 'IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { if (e.isIntersecting) runCounters(); });
      }, { threshold: 0, rootMargin: '0px 0px -10% 0px' });
      io.observe(band);
      setTimeout(runCounters, 3500);
    } else {
      setTimeout(runCounters, 400);
    }
  }

  /* ── FAQ accordion ── */
  document.querySelectorAll('.faq-question').forEach(function (btn) {
    var answer = btn.nextElementSibling;
    if (answer) answer.style.display = 'none';
    btn.addEventListener('click', function () {
      var isOpen = btn.classList.contains('open');
      document.querySelectorAll('.faq-question.open').forEach(function (b) {
        b.classList.remove('open');
        var sym = b.querySelector('.faq-sym');
        if (sym) sym.textContent = '+';
        var ans = b.nextElementSibling;
        if (ans) ans.style.display = 'none';
      });
      if (!isOpen) {
        btn.classList.add('open');
        var sym = btn.querySelector('.faq-sym');
        if (sym) sym.textContent = '−';
        if (answer) answer.style.display = 'block';
      }
    });
  });

  /* ── Blog / resource category filter ── */
  document.querySelectorAll('.blog-cat-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var cat = btn.getAttribute('data-cat');
      document.querySelectorAll('.blog-cat-btn').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      document.querySelectorAll('[data-cat-item]').forEach(function (card) {
        var c = card.getAttribute('data-cat-item');
        card.style.display = (cat === 'All' || c === cat) ? '' : 'none';
      });
      // also support old data-cat on blog-card
      document.querySelectorAll('.blog-card[data-cat]').forEach(function (card) {
        var c = card.getAttribute('data-cat');
        card.style.display = (cat === 'All' || c === cat) ? '' : 'none';
      });
    });
  });

  /* ── Contact form submit ── */
  var formEl = document.getElementById('contact-form-el');
  var formWrap = document.getElementById('form-wrap');
  var formSuccess = document.getElementById('form-success');
  if (formEl && formWrap && formSuccess) {
    formEl.addEventListener('submit', function (e) {
      e.preventDefault();
      formWrap.style.display = 'none';
      formSuccess.style.display = 'block';
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

});
