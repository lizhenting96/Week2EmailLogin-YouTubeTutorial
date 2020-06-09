// npm install express
// npm install -D nodemon
// npm install ejs: a template view engine. All ejs files are in the folder "views"
// npm install pg
// npm install dotenv: used to create or store environment variables

const express = require("express");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt")
const session = require("express-session")
const flash = require("express-flash")
const passport = require("passport")

const initializePassport = require("./passportConfig")
initializePassport(passport)

// process.env.PORT is the PORT used in production
// PORT 4000 is used in development mode
const PORT = process.env.PORT || 4000;

app.set("view engine", "ejs");
// midware part, send name, password... details from front end to server
app.use(express.urlencoded({ extended: false }));
app.use(session({
   secret: "secret",
   resave: false,
   saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.get("/", (req, res) =>{
   res.render("index");
});

app.get("/users/register", checkAuthenticated, (req, res) => {
   res.render("register")
})

app.get("/users/login", checkAuthenticated, (req, res) => {
   res.render("login")
})

app.get("/users/logout", (req, res) => {
   req.logOut();
   req.flash("success_msg", "You've successfully logged out")
   res.redirect("/users/login")
})

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
   // in dashboard, there is a variable called "user"
   res.render("dashboard", { user: req.user.name })
})

app.post("/users/register", async (req, res) => {
   let {name, email, password, password2} = req.body
   console.log({name, email,password,password2})
   // error check and validations are below:
   errors = []
   if (!name || !email || !password || ! password2) {
      errors.push({message: "Please enter all fields"})
   }
   if (password.length < 6) {
      errors.push({message: "Password should be at least 6 characters"})
   }
   if (password != password2) {
      errors.push({message: "Passwords do not match"})
   }
   if (errors.length > 0) {
      res.render("register", {errors})
   }
   else{
      // Form validation passed
      let hashedPassword = await bcrypt.hash(password, 10)

      pool.query(`SELECT * FROM users WHERE email = $1`,
                  [email],
                  (err, results) =>
                  {
                     if (err) {
                        throw err
                     }
                     if (results.rows.length > 0) {
                        errors.push({message: "Email already registered"})
                        res.render("register", {errors})
                     }
                     else{
                        pool.query(`INSERT INTO users (name, email, password)
                                    VALUES ($1, $2, $3)
                                    RETURNING id, password`,
                                    [name, email, hashedPassword],
                                    (err, results) =>{
                                       if (err) {
                                          throw err
                                       }
                                       console.log(results.rows)
                                       req.flash("success_msg", "You've successfully registered, please login")
                                       res.redirect("/users/login")
                                    })
                     }
                  })
   }
})

app.post("/users/login", passport.authenticate('local', {
   successRedirect: "/users/dashboard",
   failureRedirect:"/users/login",
   failureFlash: true
}))

function checkAuthenticated(req, res, next) {
   if (req.isAuthenticated()) {
      return res.redirect("/users/dashboard")
   }
   next()
}

function checkNotAuthenticated(req, res, next) {
   if (req.isAuthenticated()) {
      next()
   }
   res.redirect("/users/login")
}

app.listen(PORT, () => console.log(`Server is Listening on port ${PORT} ...`));