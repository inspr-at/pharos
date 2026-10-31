// Theme, menu, live search and a quiet refresh. The pages work without it.
(() => {
  // A browser policy can make reaching the storage itself throw, so take its name.
  const stored = (name, key) => {
    try {
      return window[name].getItem(key);
    } catch {
      return null;
    }
  };
  const store = (name, key, value) => {
    try {
      window[name].setItem(key, value);
    } catch {
      // Private windows may refuse storage; the choice just does not persist.
    }
  };

  const THEME_KEY = "pharos-theme";
  const SCROLL_KEY = "pharos-scroll";
  const REFRESH_MS = 60_000;

  const root = document.documentElement;
  const saved = stored("localStorage", THEME_KEY);
  const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = saved === "light" || saved === "dark" ? saved : prefersDark ? "dark" : "light";

  const showTheme = () => {
    for (const button of document.querySelectorAll("[data-set-theme]")) {
      const on = button.dataset.setTheme === root.dataset.theme;
      button.classList.toggle("on", on);
      button.setAttribute("aria-pressed", String(on));
    }
  };

  const search = () => {
    const input = document.querySelector("[data-host-search]");
    if (!input) return;
    const query = input.value.trim().toLowerCase();
    for (const item of document.querySelectorAll("[data-host]")) {
      item.hidden = query !== "" && !item.dataset.host.includes(query);
    }
    for (const group of document.querySelectorAll("[data-host-group]")) {
      group.hidden = !group.querySelector("[data-host]:not([hidden])");
    }
    const empty = document.querySelector("[data-host-empty]");
    if (empty) empty.hidden = Boolean(document.querySelector("[data-host-group]:not([hidden])"));
    const keep = (url) => {
      if (query) url.searchParams.set("q", input.value.trim());
      else url.searchParams.delete("q");
      return url;
    };
    window.history.replaceState(null, "", keep(new URL(window.location.href)));
    // Links drawn by the server still carry the search it was drawn with.
    for (const link of document.querySelectorAll("a[data-keep-search]")) {
      link.href = keep(new URL(link.href));
    }
  };

  document.addEventListener("DOMContentLoaded", () => {
    showTheme();
    for (const button of document.querySelectorAll("[data-set-theme]")) {
      button.addEventListener("click", () => {
        root.dataset.theme = button.dataset.setTheme;
        store("localStorage", THEME_KEY, root.dataset.theme);
        showTheme();
      });
    }

    const side = document.querySelector(".side");
    const menu = document.querySelector(".side-menu");
    menu?.addEventListener("click", () => {
      const open = side.classList.toggle("open");
      menu.setAttribute("aria-expanded", String(open));
    });

    for (const time of document.querySelectorAll("time[data-local-time]")) {
      const when = new Date(time.dateTime);
      if (!Number.isNaN(when.getTime())) {
        time.textContent = when.toLocaleTimeString([], { hour12: false });
      }
    }

    document.querySelector("[data-host-search]")?.addEventListener("input", search);
    const arrange = document.querySelector("[data-arrange]");
    arrange?.addEventListener("change", () => arrange.form.requestSubmit());

    // Selecting a card loads the same page, so keep the reader where they were.
    for (const link of document.querySelectorAll("[data-keep-scroll]")) {
      link.addEventListener("click", () => store("sessionStorage", SCROLL_KEY, String(window.scrollY)));
    }
    const scroll = stored("sessionStorage", SCROLL_KEY);
    if (scroll !== null) {
      try {
        window.sessionStorage.removeItem(SCROLL_KEY);
      } catch {
        // Nothing to clean up without storage.
      }
      window.scrollTo(0, Number(scroll));
    }

    const busy = () =>
      document.activeElement?.matches("input, select") ||
      document.querySelector("details[open]") ||
      side?.classList.contains("open");
    setInterval(() => {
      if (document.visibilityState === "visible" && !busy()) window.location.reload();
    }, REFRESH_MS);
  });
})();
