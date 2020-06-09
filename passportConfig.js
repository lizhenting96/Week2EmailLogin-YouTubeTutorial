const LocalStrategy = require("passport-local").Strategy
const {pool} = require("./dbConfig")
const bcypt = require("bcrypt")

function initialize(passport) {
   // a call back function used in passport.use
   const authenticateUser = (email, password, done) => {
      pool.query(`SELECT * FROM users WHERE email = $1`,
                  [email],
                  (err, results) =>{
                     if (err) {
                        throw err
                     }
                     console.log(results.rows)
                     if (results.rows.length > 0) {
                        const user = results.rows[0]
                        // compare the input password with the hashedPassword in DB
                        // if they match, isMatch = true
                        bcypt.compare(password, user.password, (err, isMatch) => {
                           if (err) {
                              throw err
                           }
                           if (isMatch) {
                              // null means no app error, and done will return user and store it in the session cookies for us
                              return done(null, user)
                           }
                           else {
                              // no app error, but password not match, so instead of returning user, return false and pass a message
                              return done(null, false, {message: "Password is not correct"})
                           }
                        })
                     }
                     else{
                        // if there is no user found in DB
                        return done(null, false, {message: "Email is not registered"})
                     }
                  })
   }

   passport.use(new LocalStrategy({
      usernameField: "email",
      passwordField: "password"
   }, authenticateUser))

   passport.serializeUser((user, done) => done(null, user.id))
   passport.deserializeUser((id, done) => {
      pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
         if (err) {
            throw err
         }
         return done(null, results.rows[0])
      })
   })
}

module.exports = initialize