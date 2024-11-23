
// for fade-in and fade-out message;
var date = new Date().getFullYear()

document.getElementById("currentYear").innerHTML = date 




// ABOUT FADEIN, FADEOUT MESSAGE IN confirmaion dialog;
document.addEventListener('DOMContentLoaded', () => {
  const deleteButtons = document.querySelectorAll('.button2');
  const modal = document.getElementById('confirmModal');
  const closeBtn = document.querySelector('.close-button');
  const confirmBtn = document.getElementById('confirmBtn');
  const cancelBtn = document.getElementById('cancelBtn');
  let postId;

  deleteButtons.forEach(button => {
    button.addEventListener('click', function(event) {
      event.preventDefault();
      postId = this.form.action.split('/').pop();
      modal.style.display = 'block';
    });
  });

  closeBtn.onclick = function() {
    modal.style.display = 'none';
  }

  confirmBtn.onclick = function() {
    modal.style.display = 'none';
    fetch(`/delete/${postId}`, { method: 'POST' })
      .then(response => {
        if (response.ok) {
          showMessage('Post deleted successfully.', 'success',);
          setTimeout(() => window.location.href = '/',1000 );
        } else {
          showMessage('Failed to delete the post.', 'error',);
        }
      });
  }


  cancelBtn.onclick = function() {
    modal.style.display = 'none';
    showMessage('Post deletion cancelled.', 'error');
  }

  window.onclick = function(event) {
    if (event.target == modal) {
      modal.style.display = 'none';
    }
  }
  function showMessage(message, type) {
    const messageBox = document.createElement('div');
    messageBox.classList.add('message', type);
    messageBox.textContent = message;

    document.body.appendChild(messageBox);

    // Fade in the message box
    setTimeout(() => {
      messageBox.classList.add('visible');
    }, 100);

    // Fade out the message box after 3 seconds
    setTimeout(() => {
      messageBox.classList.remove('visible');
      // Remove the message box from the DOM after it fades out
      setTimeout(() => {
        document.body.removeChild(messageBox);
      }, 1000);
    }, 3000);
  }
});

