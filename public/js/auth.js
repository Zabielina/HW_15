const auth_form = document.getElementById("auth_form");

const auth_user = (data) => {
  fetch("http://localhost:3050/user/signin", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });
};
auth_form.addEventListener("submit", (e) => {
  e.preventDefault();
  const form_data = new FormData(e.target);
  const data = Object.fromEntries(form_data);
  auth_user(data);
});
