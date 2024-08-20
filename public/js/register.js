const register_form = document.getElementById("register_form");
const HOST = "http://localhost:3050";
const request_add_user = (data) => {
  fetch(HOST + "/user/signup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })
    .then((res) => res.json())
    .then((res) => {
      localStorage.setItem("token", res.token);
      document.location.href = HOST;
    })
    .catch((err) => console.error(err));
};
register_form.addEventListener("submit", (e) => {
  e.preventDefault();
  const form_data = new FormData(e.target);
  const data = Object.fromEntries(form_data);
  request_add_user(data);
});
