// ========================================
// REFLECTION APP - MAIN JAVASCRIPT FILE
// ========================================

// ========== GLOBAL VARIABLES ==========
let currentReflectionData = {};
let expandedReflectionData = null;
let reflectionToDelete = null;

// ========== UTILITY FUNCTIONS ==========

/**
 * Get formatted current date and time
 */
function getUserDateTime() {
  return new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long', 
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true
  });
}

/**
 * Show toast notification with Tailwind styling
 * @param {string} message - The message to display
 * @param {string} type - Toast type (success, error, warning, info)
 */
function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('toast-container');
  
  // Create toast container if it doesn't exist
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.className = 'fixed top-4 right-4 z-50 space-y-2';
    document.body.appendChild(toastContainer);
  }

  // Color mapping for different toast types
  const colorClasses = {
    success: 'bg-green-600 border-green-500',
    error: 'bg-red-600 border-red-500',
    warning: 'bg-yellow-600 border-yellow-500',
    info: 'bg-blue-600 border-blue-500'
  };

  const iconPaths = {
    success: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
    error: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z',
    warning: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z',
    info: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
  };

  const toastId = 'toast-' + Date.now();
  const colorClass = colorClasses[type] || colorClasses.info;
  const iconPath = iconPaths[type] || iconPaths.info;

  const toastHtml = `
    <div id="${toastId}" class="flex items-center p-4 mb-2 text-white ${colorClass} border rounded-lg shadow-lg transform translate-x-full transition-transform duration-300">
      <svg class="w-5 h-5 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${iconPath}"></path>
      </svg>
      <div class="text-sm font-medium">${message}</div>
      <button type="button" class="ml-auto -mx-1.5 -my-1.5 text-white hover:text-gray-200 rounded-lg p-1.5 hover:bg-black/10 transition-colors duration-200" onclick="removeToast('${toastId}')">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
        </svg>
      </button>
    </div>
  `;
  
  toastContainer.insertAdjacentHTML('beforeend', toastHtml);
  
  // Animate in
  const toastElement = document.getElementById(toastId);
  setTimeout(() => {
    toastElement.classList.remove('translate-x-full');
  }, 100);
  
  // Auto remove after 4 seconds
  setTimeout(() => {
    removeToast(toastId);
  }, 2000);
}

/**
 * Remove toast notification
 */
function removeToast(toastId) {
  const toastElement = document.getElementById(toastId);
  if (toastElement) {
    toastElement.classList.add('translate-x-full');
    setTimeout(() => {
      toastElement.remove();
    }, 200);
  }
}

// ========== EXPAND MODE FUNCTIONALITY ==========

/**
 * Show expand mode indicator
 */
function showExpandModeIndicator() {
  const indicator = document.getElementById('expandModeIndicator');
  const submitText = document.getElementById('submit-text');
  
  if (indicator) {
    indicator.classList.remove('hidden');
  }
  
  if (submitText) {
    submitText.textContent = 'Update Reflection';
  }
}

/**
 * Hide expand mode indicator
 */
function hideExpandModeIndicator() {
  const indicator = document.getElementById('expandModeIndicator');
  const submitText = document.getElementById('submit-text');
  
  if (indicator) {
    indicator.classList.add('hidden');
  }
  
  if (submitText) {
    submitText.textContent = 'Save Reflection';
  }
}

/**
 * Exit expand mode
 */
function exitExpandMode() {
  expandedReflectionData = null;
  hideExpandModeIndicator();
  
  // Clear the form
  const form = document.getElementById("reflectionForm");
  const charCount = document.getElementById("charCount");
  
  if (form) form.reset();
  if (charCount) charCount.textContent = "0 characters";
  
}

// ========== QUESTION MANAGEMENT ==========

/**
 * Show custom title input interface
 */
function showCustomTitleInput() {
  const customTitleDiv = document.getElementById('custom-title-input');
  const titleElement = document.getElementById('title');
  
  if (!customTitleDiv) return;
  
  titleElement.style.display = 'none';
  customTitleDiv.classList.remove('hidden');
  
  customTitleDiv.innerHTML = `
    <div class="max-w-md mx-auto space-y-4">
      <label class="block text-sm font-medium text-gray-300">Write your custom reflection question:</label>
      <input type="text" id="custom-title-input-field" 
             dir="auto"
             class="w-full px-4 py-3 bg-gray-800 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200" 
             value="">
      <div class="flex space-x-3 justify-center">
        <button class="px-4 py-2 text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors duration-200" onclick="cancelCustomTitleInput()">Cancel</button>
        <button class="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors duration-200" onclick="saveCustomTitle()">Save</button>
      </div>
    </div>
  `;
  
  const titleInput = document.getElementById('custom-title-input-field');
  titleInput.focus();
}

/**
 * Save custom title
 */
function saveCustomTitle() {
  const titleInput = document.getElementById('custom-title-input-field');
  const newTitle = titleInput.value.trim();
  
  if (!newTitle) {
    showToast("Please enter a custom title!", "warning");
    return;
  }
  
  const titleElement = document.getElementById('title');
  const customTitleDiv = document.getElementById('custom-title-input');
  
  titleElement.textContent = newTitle;
  customTitleDiv.classList.add('hidden');
  titleElement.style.display = 'block';
  customTitleDiv.innerHTML = '';
  
}

/**
 * Cancel custom title input
 */
function cancelCustomTitleInput() {
  const titleElement = document.getElementById('title');
  const customTitleDiv = document.getElementById('custom-title-input');
  
  customTitleDiv.classList.add('hidden');
  titleElement.style.display = 'block';
  customTitleDiv.innerHTML = '';
}

/**
 * Get random question from API
 */
async function getRandomQuestion() {
  try {
    const response = await fetch("/reflection/get-questions", {
      method: "GET",
      credentials: 'include'
    });
    
    if (!response.ok) {
      showToast("Failed to load questions", "error");
      return;
    }
    
    const questions = await response.json();
    
    if (questions.length === 0) {
      showToast("No questions available", "warning");
      return;
    }
    
    // Select random question
    const randomIndex = Math.floor(Math.random() * questions.length);
    const randomQuestion = questions[randomIndex];
    
    const titleElement = document.getElementById('title');
    titleElement.textContent = randomQuestion.question;
        
  } catch (error) {
    showToast("Error loading random question", "error");
  }
}

// ========== MAIN TITLE EDITING ==========

/**
 * Enable editing of the main page title
 */
function edit_current_title() {
  const titleElement = document.getElementById('title');
  const titleEditDiv = document.getElementById('current-title-edit');
  const currentTitle = titleElement.textContent;
  
  titleElement.style.display = 'none';
  titleEditDiv.classList.remove('hidden');
  
  titleEditDiv.innerHTML = `
    <div class="max-w-md mx-auto space-y-4">
      <label class="block text-sm font-medium text-gray-300">Edit Title:</label>
      <input type="text" id="current-title-input" 
          dir="auto"
          class="w-full px-4 py-3 bg-gray-800 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200 text-center" 
          value="${currentTitle}">

      <div class="flex space-x-3 justify-center">
        <button class="px-4 py-2 text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors duration-200" onclick="cancel_current_title_edit()">Cancel</button>
        <button class="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors duration-200" onclick="save_current_title()">Save</button>
      </div>
    </div>
  `;
  
  const titleInput = document.getElementById('current-title-input');
  titleInput.focus();
  titleInput.select();
}

/**
 * Cancel editing of main title
 */
function cancel_current_title_edit() {
  const titleElement = document.getElementById('title');
  const titleEditDiv = document.getElementById('current-title-edit');
  
  titleEditDiv.classList.add('hidden');
  titleElement.style.display = 'block';
  titleEditDiv.innerHTML = '';
}

/**
 * Save the edited main title
 */
function save_current_title() {
  const titleInput = document.getElementById('current-title-input');
  const newTitle = titleInput.value.trim();
  
  if (!newTitle) {
    showToast("Title cannot be empty!", "warning");
    return;
  }
  
  const titleElement = document.getElementById('title');
  const titleEditDiv = document.getElementById('current-title-edit');
  
  titleElement.textContent = newTitle;
  titleEditDiv.classList.add('hidden');
  titleElement.style.display = 'block';
  titleEditDiv.innerHTML = '';
  
}

// ========== FORM SUBMISSION ==========

/**
 * Handle reflection form submission
 */
function initializeReflectionForm() {
  const form = document.getElementById("reflectionForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const reflection = document.getElementById("reflection").value;
    const title = document.getElementById("title").textContent;

    // Validation
    if (!reflection.trim()) {
      showToast("Please write your reflection before saving.", "warning");
      return;
    }

    if (!title.trim()) {
      showToast("Please set a title for your reflection.", "warning");
      return;
    }

    try {
      if (expandedReflectionData) {
        await updateExistingReflection(reflection, title);
      } else {
        await createNewReflection(reflection, title);
      }
      
    } catch (error) {
      showToast("Connection error. Please check your internet and try again.", "error");
    }
  });
}

/**
 * Update an existing reflection
 */
async function updateExistingReflection(reflection, title) {
  const response = await fetch("/reflection/update-reflection-by-id", {
    method: "PUT",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      "reflection": reflection,
      "title": title,
      "id": parseInt(expandedReflectionData.id)
    }),
    credentials: 'include'
  });
  
  if (response.status === 401) {
    showToast("Your session has expired. Please log in again.", "error");
    setTimeout(() => { window.location.href = "/login"; }, 2000);
    return;
  }

  if (!response.ok) {
    showToast("Failed to update your reflection. Please try again.", "error");
    return;
  }
  
  expandedReflectionData = null;
  document.getElementById("reflectionForm").reset();
  document.getElementById("charCount").textContent = "0 characters";
  hideExpandModeIndicator();
  showToast("Reflection updated successfully! 🎉", "success");
}

/**
 * Create a new reflection
 */
async function createNewReflection(reflection, title) {
  const response = await fetch("/reflection/add-reflection", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ 
      reflection: reflection,
      date: getUserDateTime(),
      title: title
    }),
    credentials: 'include'
  });

  if (response.status === 401) {
    showToast("Please log in to save your reflection.", "error");
    setTimeout(() => { window.location.href = "/login"; }, 2000);
    return;
  }

  if (response.status === 422) {
    showToast("Please check your reflection content and try again.", "warning");
    return;
  }

  if (!response.ok) {
    showToast("Failed to save your reflection. Please try again.", "error");
    return;
  }

  const data = await response.json();
  addNewReflectionToList(data.date, data.id, data.title);
  document.getElementById("reflectionForm").reset();
  document.getElementById("charCount").textContent = "0 characters";
  showToast("Reflection saved successfully! 🌟", "success");
  getRandomQuestion()
}

/**
 * Add new reflection to the sidebar list
 */
function addNewReflectionToList(date, id, title) {
  const reflectionsList = document.getElementById('reflectionsList');
  if (!reflectionsList) return;

  // Remove empty state if exists
  const emptyState = document.getElementById('emptyReflectionsState');
  if (emptyState) {
    emptyState.remove();
    console.log('Removed empty state - user now has reflections');
  }

  // Get current date info for grouping
  const currentYear = new Date().getFullYear();
  const dateObj = new Date(date.split(' at ')[0]);
  const year = dateObj.getFullYear();
  const month = dateObj.getMonth();
  const monthNames = ["January", "February", "March", "April", "May", "June",
                     "July", "August", "September", "October", "November", "December"];
  const monthName = monthNames[month];
  
  // Determine group name
  const groupName = year === currentYear ? monthName : `${monthName} ${year}`;
  
  // Look for existing group
  let existingGroup = document.querySelector(`[data-group="${groupName}"]`);
  
  if (existingGroup) {
    // Add to existing group
    const reflectionsContainer = existingGroup.querySelector('.space-y-3');
    reflectionsContainer.insertAdjacentHTML('afterbegin', createReflectionHTML(date, id, title));
  } else {
    // Create new group and add to the top
    const newGroupHTML = `
      <div class="mb-6 animate-slide-up" data-group="${groupName}">
        <!-- Month/Year Header -->
        <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 px-2">
          ${groupName}
        </h3>
        
        <!-- Reflections in this group -->
        <div class="space-y-3">
          ${createReflectionHTML(date, id, title)}
        </div>
      </div>
    `;
    
    reflectionsList.insertAdjacentHTML('afterbegin', newGroupHTML);
  }
  
  console.log('Added new reflection to sidebar:', { date, id, title });
}

/**
 * Create HTML for a single reflection item
 */
function createReflectionHTML(date, id, title) {
  return `
    <div class="bg-gray-800/50 border border-gray-700 rounded-xl p-4 hover:bg-gray-800 transition-colors duration-200 group animate-slide-up" 
         id="reflection-item-${id}">
      <div class="reflection-summary" id="summary-${id}">
        <div class="text-xs text-gray-500 mb-2">${date}</div>
        <h3 class="text-gray-100 font-medium mb-3 cursor-pointer hover:text-primary-400 transition-colors duration-200" 
            onclick="edit_title('${id}')" 
            title="Click to edit title">
          ${title}
        </h3>
        <div class="flex space-x-2">
          <button onclick="view_reflection('${id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-primary-400 hover:text-primary-300 hover:bg-primary-900/20 rounded-lg transition-colors duration-200">
            View
          </button>
          <button onclick="delete_reflection('${id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-red-400 hover:text-red-300 hover:bg-red-900/20 rounded-lg transition-colors duration-200">
            Delete
          </button>
        </div>
      </div>
      <div class="reflection-content hidden" id="content-${id}"></div>
      <div class="title-edit hidden" id="title-edit-${id}"></div>
    </div>
  `;
}

// ========== REFLECTION VIEWING & EDITING ==========

/**
 * View and edit reflection content
 */
async function view_reflection(reflection_id) {
  const summaryDiv = document.getElementById(`summary-${reflection_id}`);
  const contentDiv = document.getElementById(`content-${reflection_id}`);
  
  // Toggle view if already open
  if (!contentDiv.classList.contains('hidden')) {
    hideReflectionContent(reflection_id);
    return;
  }

  try {
    // Fetch reflection data
    const data = await fetchReflectionById(reflection_id);
    if (!data) return;
    
    currentReflectionData[reflection_id] = data;
    
    // Show content view
    summaryDiv.classList.add('hidden');
    contentDiv.classList.remove('hidden');
    
    contentDiv.innerHTML = `
      <div class="space-y-4 animate-slide-up">
        <div class="text-xs text-gray-500">${data.date}</div>
        <h3 class="text-gray-100 font-medium">${data.title}</h3>
        <textarea id="textarea-${reflection_id}" 
                  class="w-full h-40 px-3 py-3 bg-gray-800 border border-gray-600 rounded-lg text-gray-100 placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent resize-none transition-all duration-200 text-sm leading-relaxed"
                                        dir="auto">${data.reflection}</textarea>
        <div class="flex space-x-2">
          <button onclick="cancel_reflection_edit('${reflection_id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-700 rounded-lg transition-colors duration-200">
            Cancel
          </button>
          <button onclick="expand_to_main('${reflection_id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-blue-400 hover:text-blue-300 hover:bg-blue-900/20 rounded-lg transition-colors duration-200">
            Expand
          </button>
          <button onclick="save_reflection('${reflection_id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-green-400 hover:text-green-300 hover:bg-green-900/20 rounded-lg transition-colors duration-200">
            Save
          </button>
        </div>
      </div>
    `;
    
    document.getElementById(`textarea-${reflection_id}`).focus();
    
  } catch (error) {
    showToast("Error viewing reflection", "error");
  }
}

/**
 * Hide reflection content view
 */
function hideReflectionContent(reflection_id) {
  const summaryDiv = document.getElementById(`summary-${reflection_id}`);
  const contentDiv = document.getElementById(`content-${reflection_id}`);
  
  contentDiv.classList.add('hidden');
  summaryDiv.classList.remove('hidden');
  contentDiv.innerHTML = '';
}

/**
 * Cancel reflection editing
 */
function cancel_reflection_edit(reflection_id) {
  hideReflectionContent(reflection_id);
}

/**
 * Expand reflection to main editor
 */
function expand_to_main(reflection_id) {
  const textarea = document.getElementById(`textarea-${reflection_id}`);
  const data = currentReflectionData[reflection_id];
  
  if (!textarea || !data) return;
  
  // Store expanded reflection data
  expandedReflectionData = {
    id: reflection_id,
    title: data.title,
    date: data.date,
    reflection: textarea.value
  };
  
  // Update main page
  const mainTitle = document.getElementById('title');
  const mainReflection = document.getElementById('reflection');
  const charCount = document.getElementById('charCount');
  
  if (mainTitle) mainTitle.textContent = data.title;
  if (mainReflection) {
    mainReflection.value = textarea.value;
    if (charCount) charCount.textContent = `${textarea.value.length} characters`;
  }
  
  // Show expand mode indicator
  showExpandModeIndicator();
  
  // Close sidebar and content view
  closeSidebar();
  cancel_reflection_edit(reflection_id);
  
  if (mainReflection) mainReflection.focus();
  
}

/**
 * Save reflection changes
 */
async function save_reflection(reflection_id) {
  const textarea = document.getElementById(`textarea-${reflection_id}`);
  const newContent = textarea.value.trim();
  
  if (!newContent) {
    showToast("Reflection content cannot be empty.", "warning");
    return;
  }
  
  try {
    const response = await fetch("/reflection/update-reflection-by-id", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        "reflection": newContent,
        "id": parseInt(reflection_id)
      }),
      credentials: 'include'
    });

    if (response.status === 401) {
      showToast("Your session has expired. Please log in again.", "error");
      return;
    }

    if (!response.ok) {
      showToast("Failed to save changes. Please try again.", "error");
      return;
    }
   
    currentReflectionData[reflection_id].reflection = newContent;
    cancel_reflection_edit(reflection_id);
    showToast("Reflection updated successfully! ✨", "success");
     getRandomQuestion()
    
  } catch (error) {
    showToast("Connection error. Please try again.", "error");
  }
}

// ========== TITLE EDITING ==========

/**
 * Edit reflection title
 */
async function edit_title(reflection_id) {
  try {
    // Fetch data if not already loaded
    if (!currentReflectionData[reflection_id]) {
      const data = await fetchReflectionById(reflection_id);
      if (!data) return;
      currentReflectionData[reflection_id] = data;
    }

    const summaryDiv = document.getElementById(`summary-${reflection_id}`);
    const titleEditDiv = document.getElementById(`title-edit-${reflection_id}`);
    const data = currentReflectionData[reflection_id];
    
    summaryDiv.classList.add('hidden');
    titleEditDiv.classList.remove('hidden');
    
    titleEditDiv.innerHTML = `
      <div class="space-y-4 animate-slide-up">
        <div class="text-xs text-gray-500">${data.date}</div>
        <div>
          <label class="block text-xs font-medium text-gray-400 mb-2">Edit Title:</label>
          <input type="text" id="title-input-${reflection_id}" 
                 dir="auto"
                 class="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200" 
                 value="${data.title}">
        </div>
        <div class="flex space-x-2">
          <button onclick="cancel_title_edit('${reflection_id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-700 rounded-lg transition-colors duration-200">
            Cancel
          </button>
          <button onclick="save_title('${reflection_id}')"
                  class="flex-1 px-3 py-2 text-xs font-medium text-green-400 hover:text-green-300 hover:bg-green-900/20 rounded-lg transition-colors duration-200">
            Save
          </button>
        </div>
      </div>
    `;
    
    const titleInput = document.getElementById(`title-input-${reflection_id}`);
    titleInput.focus();
    titleInput.select();
    
  } catch (error) {
    showToast("Error editing title", "error");
  }
}

/**
 * Cancel title editing
 */
function cancel_title_edit(reflection_id) {
  const summaryDiv = document.getElementById(`summary-${reflection_id}`);
  const titleEditDiv = document.getElementById(`title-edit-${reflection_id}`);
  
  titleEditDiv.classList.add('hidden');
  summaryDiv.classList.remove('hidden');
  titleEditDiv.innerHTML = '';
}

/**
 * Save title changes
 */
async function save_title(reflection_id) {
  const titleInput = document.getElementById(`title-input-${reflection_id}`);
  const newTitle = titleInput.value.trim();
  
  if (!newTitle) {
    showToast("Title cannot be empty.", "warning");
    return;
  }
  
  try {
    const currentData = currentReflectionData[reflection_id];
    
    const response = await fetch("/reflection/update-reflection-by-id", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        "reflection": currentData.reflection,
        "title": newTitle,
        "id": parseInt(reflection_id)
      }),
      credentials: 'include'
    });

    if (response.status === 401) {
      showToast("Your session has expired. Please log in again.", "error");
      return;
    }

    if (!response.ok) {
      showToast("Failed to save title. Please try again.", "error");
      return;
    }
    
    // Update UI and data
    currentReflectionData[reflection_id].title = newTitle;
    const summaryDiv = document.getElementById(`summary-${reflection_id}`);
    const titleEditDiv = document.getElementById(`title-edit-${reflection_id}`);
    const titleElement = summaryDiv.querySelector('h3');
    
    titleElement.textContent = newTitle;
    titleEditDiv.classList.add('hidden');
    summaryDiv.classList.remove('hidden');
    titleEditDiv.innerHTML = '';
    
    
  } catch (error) {
    showToast("Connection error. Please try again.", "error");
  }
}

// ========== DELETION ==========

/**
 * Show delete confirmation modal
 */
function delete_reflection(reflection_id) {
  reflectionToDelete = reflection_id;
  const modal = document.getElementById('confirmDeleteModal');
  modal.classList.remove('hidden', 'opacity-0');
  modal.querySelector('div > div').classList.remove('scale-95');
}

/**
 * Perform actual deletion
 */
async function performDelete(reflection_id) {
  try{
    const response = await fetch("/reflection/delete-reflection-by-id", {
      method: "DELETE",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({"id": parseInt(reflection_id)}),
      credentials: 'include'
    });

    if (response.status === 401) {
      showToast("Your session has expired. Please log in again.", "error");
      return;
    }

    if (!response.ok) {
      showToast("Failed to delete reflection. Please try again.", "error");
      return;
    }
    
    // Remove from UI and clean up data
    const reflection_item = document.getElementById(`reflection-item-${reflection_id}`);
    const parentGroup = reflection_item.closest('[data-group]');
    
    reflection_item.remove();
    delete currentReflectionData[reflection_id];
    
    // Check if group is now empty
    if (parentGroup) {
      const remainingReflections = parentGroup.querySelectorAll('[id^="reflection-item-"]');
      if (remainingReflections.length === 0) {
        parentGroup.remove();
      }
    }
    
    // Check if reflections list is completely empty
    const reflectionsList = document.getElementById('reflectionsList');
    const remainingItems = reflectionsList.querySelectorAll('[id^="reflection-item-"]');
    
    if (remainingItems.length === 0) {
      // Show empty state again
      reflectionsList.innerHTML = `
        <div id="emptyReflectionsState" class="text-center py-12 text-gray-500 animate-fade-in">
          <svg class="w-16 h-16 mx-auto mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253z"></path>
          </svg>
          <p class="text-lg font-medium mb-2">No memories yet</p>
          <p class="text-sm">Write your first reflection to get started!</p>
          <p class="text-xs text-gray-600 mt-4">Your reflections will appear here after saving</p>
        </div>
      `;
    }
    
    showToast("Reflection deleted successfully! 🗑️", "success");
    
  } catch (error) {
    showToast("Connection error. Please try again.", "error");
  }
}

// ========== API HELPERS ==========

/**
 * Fetch reflection data by ID
 */
async function fetchReflectionById(reflection_id) {
  const response = await fetch("/reflection/get-reflection-by-id", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({"id": parseInt(reflection_id)}),
    credentials: 'include'
  });

  if (!response.ok) {
    showToast("Failed to fetch reflection", "error");
    return null;
  }

  return await response.json();
}

/**
 * Close the sidebar
 */
function closeSidebar() {
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const sidebar = document.getElementById('sidebar');
  
  if (sidebarOverlay && sidebar) {
    sidebarOverlay.classList.add('opacity-0');
    sidebar.classList.add('translate-x-full');
    setTimeout(() => {
      sidebarOverlay.classList.add('hidden');
    }, 300);
  }
}

// ========== LOGIN HANDLING ==========

/**
 * Initialize login form
 */
function initializeLoginForm() {
  const loginForm = document.getElementById("loginForm");
  if (!loginForm) return;

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();

    // Validation
    if (!username) {
      showToast("Please enter your username.", "warning");
      return;
    }

    if (!password) {
      showToast("Please enter your password.", "warning");
      return;
    }

    try {
      const response = await fetch("/user/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username, password }),
        credentials: 'include' 
      });

      if (response.ok) {
        showToast("Logged in successfully!", "success");
        setTimeout(() => { window.location.href = "/"; }, 1000);
      } else {
        // Handle all error cases the same way for simplicity
        console.log("Login failed with status:", response.status);
      }
    } catch (error) {
      showToast("Connection error. Please check your internet and try again.", "error");
      console.error("Login error:", error);
    }
  });
}

// ========== LOGOUT ==========

/**
 * Handle user logout
 */
function logout() {
  fetch('/user/logout', {
    method: 'POST',
    credentials: 'include'
  }).then(() => {
      window.location.href = '/';

  }).catch(() => {    
    window.location.href = '/';
  });
}

// ========== INITIALIZATION ==========

/**
 * Initialize all event listeners and functionality
 */
document.addEventListener('DOMContentLoaded', function() {
  // ========== SIDEBAR FUNCTIONALITY ==========
  const openSidebarBtn = document.getElementById('openSidebarBtn');
  const closeSidebarBtn = document.getElementById('closeSidebarBtn');
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const sidebar = document.getElementById('sidebar');

  // Function to open sidebar
  function openSidebar() {
    if (sidebarOverlay && sidebar) {
      sidebarOverlay.classList.remove('hidden');
      setTimeout(() => {
        sidebarOverlay.classList.remove('opacity-0');
        sidebar.classList.remove('translate-x-full');
      }, 10);
    }
  }

  // Function to close sidebar
  function closeSidebar() {
    if (sidebarOverlay && sidebar) {
      sidebarOverlay.classList.add('opacity-0');
      sidebar.classList.add('translate-x-full');
      setTimeout(() => {
        sidebarOverlay.classList.add('hidden');
      }, 300);
    }
  }

  // Sidebar open button
  if (openSidebarBtn) {
    openSidebarBtn.addEventListener('click', function() {
      console.log('Opening sidebar...');
      openSidebar();
    });
  } else {
    console.log('Open sidebar button not found');
  }

  // Sidebar close button
  if (closeSidebarBtn) {
    closeSidebarBtn.addEventListener('click', closeSidebar);
  }

  // Close sidebar when clicking overlay
  if (sidebarOverlay) {
    sidebarOverlay.addEventListener('click', function(e) {
      if (e.target === sidebarOverlay) {
        closeSidebar();
      }
    });
  }

  // ========== FORM INITIALIZATION ==========
  initializeReflectionForm();
  
  // ========== DELETE CONFIRMATION ==========
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');
  
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener('click', async function() {
      if (reflectionToDelete) {
        await performDelete(reflectionToDelete);
        reflectionToDelete = null;
        
        const modal = document.getElementById('confirmDeleteModal');
        modal.classList.add('opacity-0');
        modal.querySelector('div > div').classList.add('scale-95');
        setTimeout(() => {
          modal.classList.add('hidden');
        }, 300);
      }
    });
  }
  
  if (cancelDeleteBtn) {
    cancelDeleteBtn.addEventListener('click', function() {
      reflectionToDelete = null;
      const modal = document.getElementById('confirmDeleteModal');
      modal.classList.add('opacity-0');
      modal.querySelector('div > div').classList.add('scale-95');
      setTimeout(() => {
        modal.classList.add('hidden');
      }, 300);
    });
  }
  
  // ========== EXIT EXPAND MODE ==========
  const exitExpandModeBtn = document.getElementById('exitExpandMode');
  if (exitExpandModeBtn) {
    exitExpandModeBtn.addEventListener('click', function() {
      exitExpandMode();
    });
  }
  
  // ========== EDIT TITLE FUNCTIONALITY ==========
  const editTitleBtn = document.getElementById('editTitleBtn');
  if (editTitleBtn) {
    editTitleBtn.addEventListener('click', function() {
      showCustomTitleInput();
    });
  }
  
  // ========== RANDOM QUESTION FUNCTIONALITY ==========
  const randomQuestionBtn = document.getElementById('randomQuestionBtn');
  if (randomQuestionBtn) {
    randomQuestionBtn.addEventListener('click', async function() {
      // Add loading state to button
      const originalIcon = this.innerHTML;
      this.innerHTML = `
        <svg class="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="m4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
      `;
      this.disabled = true;
      
      try {
        await getRandomQuestion();
      } finally {
        // Restore button state
        setTimeout(() => {
          this.innerHTML = originalIcon;
          this.disabled = false;
        }, 300);
      }
    });
  }
  
  // ========== TITLE CLICK FUNCTIONALITY ==========
  const titleElement = document.getElementById('title');
  if (titleElement) {
    titleElement.addEventListener('click', function() {
      edit_current_title();
    });
  }
  
  console.log('Page initialization complete');
});



