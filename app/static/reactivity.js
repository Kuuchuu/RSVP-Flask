document.addEventListener("DOMContentLoaded", function() {
    const flashMessages = document.getElementById('flash-messages');
    if (flashMessages && flashMessages.children.length > 0) {
        flashMessages.style.display = 'block';
        setTimeout(function() {
            flashMessages.style.display = 'none';
        }, 8000);
    }

    const toggleSections = document.querySelectorAll('.toggle-section');
    toggleSections.forEach(section => {
        section.addEventListener('click', function() {
            const content = this.nextElementSibling;
            content.style.display = content.style.display === 'none' ? 'block' : 'none';
        });
    });

    const themeDropdown = document.getElementById('theme');
    const customCssTextarea = document.getElementById('custom_css');

    function loadThemeCss(theme) {
        fetch(`/load_theme_css?theme=${theme}`)
            .then(response => response.text())
            .then(css => {
                customCssTextarea.value = css;
            });
    }

    if (themeDropdown) {
        // Load the currently selected theme's CSS on page load
        loadThemeCss(themeDropdown.value);

        themeDropdown.addEventListener('change', function() {
            const theme = this.value;
            loadThemeCss(theme);
        });
    }

    if (customCssTextarea) {
        customCssTextarea.addEventListener('input', function() {
            themeDropdown.value = 'custom.css';
        });
    }
});

function showConfirmation(entityId, type) {
    const deleteButton = document.getElementById(`delete-btn-${type}-${entityId}`);
    const confirmBox = document.getElementById(`confirm-box-${type}-${entityId}`);
    const crossOutButton = document.getElementById(`cross-out-btn-${entityId}`);
    deleteButton.style.display = 'none';
    confirmBox.style.display = 'inline';
    if (crossOutButton) {
        crossOutButton.style.display = 'none';
    }
}

function cancelDeletion(entityId, type) {
    const deleteButton = document.getElementById(`delete-btn-${type}-${entityId}`);
    const confirmBox = document.getElementById(`confirm-box-${type}-${entityId}`);
    const crossOutButton = document.getElementById(`cross-out-btn-${entityId}`);
    deleteButton.style.display = 'inline';
    confirmBox.style.display = 'none';
    if (crossOutButton) {
        crossOutButton.style.display = 'inline';
    }
}

function preventFormSubmission(formId) {
    const form = document.getElementById(formId);
    form.addEventListener('submit', function(event) {
        event.preventDefault();
    });
}

function submitForm(formId) {
    const form = document.getElementById(formId);
    form.submit();
}

function toggleFields() {
    const attending = document.querySelector('input[name="attending"]:checked').value;
    const attendingFields = document.getElementById('attending-fields');
    attendingFields.style.display = (attending === 'yes') ? 'block' : 'none';
}
