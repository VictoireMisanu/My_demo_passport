const express = require("express");
const PORT = process.env.PORT || 3000;
const passport = require("passport");
const LocalStategy = require("passport-local");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");
const users = require("./db/users.json");

const app = express();
const saltRounds = 10;

app.set("view engine", "ejs");
app.use(express.json());
app.set("views", __dirname + "/views");
app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: "kadea academy",
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({ db: "sessions.db", dir: "./var/db" }),
  })
);

app.use(passport.authenticate("session"));

function findUserIndex(id, arr) {
  return arr.findIndex((el) => el.id === id);
}
function verify(email, password, cb) {
  const user = users.find((user) => user.email === email);

  if (!user) {
    return cb(null, false, { message: "Incorrect email or password" });
  }

  bcrypt.compare(password, user.password, function (err, result) {
    if (err) {
      return cb(err);
    }
    if (result) {
      return cb(null, user);
    }
    return cb(null, false, { message: "Incorrect email" });
  });
}

function authenticate(req, res, next) {
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(400).json({ error: info.message });
    }
    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }
      return res.redirect("/auth/profile");
    });
  })(req, res, next);
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/auth/login");
}

function ensureAdmin(req, res, next) {
  if (req.user.role === "admin" && req.isAuthenticated()) {
    return next();
  }
  return res.render("error", {
    message: "You're not authorized",
    error: { status: 403 },
  });
}

const localStategy = new LocalStategy(
  {
    usernameField: "email",
    passwordField: "password",
  },
  verify
);

passport.use(localStategy);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, email: user.email, role: user.role });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

app.get("/", (req, res) => {
  res.render("index", { title: "Home Page", user: req.user });
});

app.get("/auth/login", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/auth/profile");
  }
  res.render("auth/login", { title: "Login Page", user: req.user });
});

app.post("/auth/login", authenticate);

app.get("/auth/signup", (req, res) => {
  res.render("auth/signup", { title: "Register Page", user: req.user });
});

app.post("/auth/signup", async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
  const user = {
    id: crypto.randomUUID(),
    email: req.body.email,
    password: hashedPassword,
    name: req.body.name,
    role: "member",
  };
  users.push(user);
  res.redirect("/auth/login");
});

app.post("/auth/logout", ensureAuthenticated, (req, res, next) => {
  req.logOut(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/auth/profile", ensureAuthenticated, (req, res) => {
  res.render("auth/profile", { title: "Profile", user: req.user });
});

app.get("/auth/admin/users", ensureAdmin, (req, res) => {
  res.render("admin/users", { title: "Users", user: req.user, users });
});

app.get("/auth/admin/users/:targetUserId", ensureAdmin, (req, res) => {
  const { targetUserId } = req.params;
  const targetUser = users.find((user) => user.id === targetUserId);
  if (targetUser) {
    return res.render("admin/user", { user: req.user, targetUser });
  }
  return res.render("error", {
    message: "user not found",
    error: { status: 404 },
  });
});

app.post("/admin/users/:targetUserId/delete", ensureAdmin, (req, res) => {
  const { targetUserId } = req.params;
  const targetUserIndex = findUserIndex(targetUserId, users);
  if (targetUserIndex < 0) {
    return res.render("error", {
      message: "user not found",
      error: { status: 404 },
    });
  }

  users.splice(targetUserIndex, 1);
  return res.redirect("/auth/admin/users");
});

app.post("/admin/users/:targetUserId/edit", ensureAdmin, (req, res) => {
  const { email, role } = req.body;
  const { targetUserId } = req.params;
  const targetUser = users.find((user) => user.id === targetUserId);

  if (targetUser) {
    targetUser.email = email;
    targetUser.role = role;

    return res.redirect(`/auth/admin/users/${targetUser.id}`);
  }
  return res.render("error", {
    message: "user not found",
    error: { status: 404 },
  });
});

app.use(function (err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};
  res.status(err.status || 500);
  res.render("error");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`App is running on http://localhost:${PORT}`);
});
