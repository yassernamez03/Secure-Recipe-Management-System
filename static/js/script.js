document.addEventListener("DOMContentLoaded", function () {
  const passwordInput = document.querySelector('input[name="password"]');
  const requirementsDiv = document.getElementById("password-requirements");

  function checkRequirements(password) {
    return {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /\d/.test(password),
      special: /[@$!%*#?&]/.test(password),
    };
  }

  function updateRequirements(password) {
    const requirements = checkRequirements(password);

    // Show requirements div when user starts typing
    if (password.length > 0) {
      requirementsDiv.classList.add("visible");
    } else {
      requirementsDiv.classList.remove("visible");
    }

    // Update each requirement's status
    Object.keys(requirements).forEach((requirement) => {
      const li = requirementsDiv.querySelector(
        `li[data-requirement="${requirement}"]`
      );
      const icon = li.querySelector(".icon");

      if (requirements[requirement]) {
        li.classList.add("met");
        li.classList.remove("unmet");
        icon.textContent = "✓";
      } else {
        li.classList.add("unmet");
        li.classList.remove("met");
        icon.textContent = "✗";
      }
    });
  }

  passwordInput.addEventListener("input", function (e) {
    updateRequirements(e.target.value);
  });

  // Hide requirements initially
  passwordInput.addEventListener("focus", function () {
    if (this.value.length > 0) {
      requirementsDiv.classList.add("visible");
    }
  });
});

function adjustServings() {
  // Implement servings adjustment logic
  alert("Servings adjustment feature coming soon!");
}

function toggleAdvanced() {
  const advancedSearch = document.getElementById("advancedSearch");
  const currentDisplay = window.getComputedStyle(advancedSearch).display;
  advancedSearch.style.display = currentDisplay === "none" ? "block" : "none";
}

// Category selector: Add_recipe page
document.addEventListener("DOMContentLoaded", function () {
  // Initialize Materialize select dropdowns
  const selectElems = document.querySelectorAll("select");
  if (selectElems.length > 0) {
    M.FormSelect.init(selectElems, {}); // Initialize only if elements exist
  }

  // Initialize Materialize sidenav (if needed)
  const sidenavElems = document.querySelectorAll(".sidenav");
  if (sidenavElems.length > 0) {
    M.Sidenav.init(sidenavElems, {}); // Initialize only if elements exist
  }
});
