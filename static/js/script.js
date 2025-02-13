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

document.getElementById('generateRecipeBtn')?.addEventListener('click', async function() {
  const prompt = document.getElementById('recipePrompt').value;
  if (!prompt) {
      M.toast({html: 'Please enter a recipe description'});
      return;
  }

  // Get CSRF token from the meta tag
  const csrf_token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

  try {
      const response = await fetch('/generate_recipe_ajax', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': csrf_token
          },
          body: JSON.stringify({ prompt: prompt })
      });

      if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const recipe = await response.json();
      
      // Fill the form fields with generated data
      document.getElementById('recipe_name').value = recipe.recipe_name;
      
      // Update the select dropdown for category
      const categorySelect = document.getElementById('category_name');
      const categoryInstance = M.FormSelect.getInstance(categorySelect);
      categorySelect.value = recipe.category_name;
      categoryInstance.destroy();
      M.FormSelect.init(categorySelect);
      
      document.getElementById('recipe_intro').value = recipe.recipe_intro;
      document.getElementById('ingredients').value = recipe.ingredients;
      document.getElementById('description').value = recipe.description;
      document.getElementById('preparation_time').value = recipe.preparation_time;
      document.getElementById('photo_url').value = recipe.photo_url;

      // Update Materialize form fields
      M.updateTextFields();
      M.toast({html: 'Recipe generated successfully!'});
      
  } catch (error) {
      console.error('Error:', error);
      M.toast({html: 'Failed to generate recipe. Please try again.'});
  }
});