document.addEventListener('DOMContentLoaded', function() {
    const adminLoginLink = document.getElementById('admin-login-link');
    const adminPasskeyModal = document.getElementById('admin-passkey-modal');
    const adminPasskeyForm = document.getElementById('admin-passkey-form');

    if (adminLoginLink) {
        adminLoginLink.addEventListener('click', function(e) {
            e.preventDefault();
            adminPasskeyModal.style.display = 'block';
        });
    }

    if (adminPasskeyForm) {
        adminPasskeyForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const passkey = document.getElementById('admin-passkey').value;

            fetch('/check_admin_passkey', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `passkey=${encodeURIComponent(passkey)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.valid) {
                    window.location.href = '/admin_register';
                } else {
                    alert('Invalid passkey');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred. Please try again.');
            });
        });
    }

    // Close the modal when clicking outside of it
    window.onclick = function(event) {
        if (event.target == adminPasskeyModal) {
            adminPasskeyModal.style.display = "none";
        }
    }
});