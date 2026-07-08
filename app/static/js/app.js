(function () {
  const root = document.documentElement;
  const savedTheme = localStorage.getItem("cloudshield-theme") || "dark";
  root.setAttribute("data-theme", savedTheme);

  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", nextTheme);
      localStorage.setItem("cloudshield-theme", nextTheme);
    });
  }

  document.querySelectorAll("[data-dropdown-target]").forEach((trigger) => {
    trigger.addEventListener("click", (event) => {
      event.stopPropagation();
      const target = document.getElementById(trigger.dataset.dropdownTarget);
      document.querySelectorAll(".dropdown-menu.open").forEach((menu) => {
        if (menu !== target) menu.classList.remove("open");
      });
      if (target) target.classList.toggle("open");
    });
  });

  document.addEventListener("click", () => {
    document.querySelectorAll(".dropdown-menu.open").forEach((menu) => menu.classList.remove("open"));
  });

  const sidebar = document.getElementById("appSidebar");
  const mobileOverlay = document.getElementById("mobileOverlay");
  const mobileMenuButton = document.getElementById("mobileMenuButton");

  function closeSidebar() {
    sidebar?.classList.remove("open");
    mobileOverlay?.classList.remove("open");
  }

  mobileMenuButton?.addEventListener("click", () => {
    sidebar?.classList.add("open");
    mobileOverlay?.classList.add("open");
  });
  mobileOverlay?.addEventListener("click", closeSidebar);
})();
