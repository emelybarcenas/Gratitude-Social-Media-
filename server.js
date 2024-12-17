require ("dotenv").config()
const jwt = require("jsonwebtoken")
const express = require("express")
const db = require("better-sqlite3")("app.db")
const bcrypt = require("bcrypt")
const cookieParser = require('cookie-parser')

db.pragma("journal_mode = WAL")
//database setup here
const createTable = db.transaction(() =>{
db.prepare(`
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )    
    `).run()
})

createTable()

//database setup ends here
const app = express()

app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {
res.locals.errors = []
//try to decode incoming cookie
try{
const decoded = jwt.verify(req.cookies.GratitudeApp, process.env.JWTSECRET)
req.user = decoded
}catch(err){
    req.user = false
}
res.locals.user = req.user
console.log(req.user)
next()
})

app.get("/", (req, res) => {
    if (req.user){
        return res.render("dashboard")
    }
res.render("homepage")
})

app.get("/login", (req, res) =>{
    res.render("login")
})

app.post("/register", (req, res) =>{
const errors = []
let inputusername = req.body.username;
let password = req.body.password;
if (typeof inputusername !== "string") inputusername = ""

inputusername = inputusername.trim()

//Username validation
if (!inputusername){ errors.push ("You must enter a username")}
if(inputusername && inputusername.length < 3) { errors.push("Username must be at least 3 characters")}
if(inputusername && inputusername.length > 12) { errors.push("Username cannot exceed 12 characters")}
if(inputusername && !inputusername.match(/^[a-zA-Z0-9]+$/)){errors.push("Username contains invalid characters")}
//Password validation
if (!password){ errors.push ("You must enter a password")}
if(!password && password.length < 8) { errors.push("Password must be at least 8 characters")}
if(!password && password.length > 20) { errors.push("Password cannot exceed 20 characters")} 
//If no errors, render homepage
if (errors.length){
return res.render("homepage", {errors})
}
const user = db.prepare("SELECT * FROM users WHERE username = ?").get(inputusername)
if (user){
    errors.push("Username already taken.")
    return res.render("homepage", {errors: errors})
}
// save the new user into a database
const salt = bcrypt.genSaltSync(10)
password = bcrypt.hashSync(password, salt)

//Getting information from entry
const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
const result = ourStatement.run(inputusername, password)
const lookUpStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
const ourUser = lookUpStatement.get(result.lastInsertRowid)

// log the user in by giving them a cookie
const tokenValue = jwt.sign({ exp: Math.floor(Date.now()/1000) + 60 * 60 * 24, userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)
res.cookie ("GratitudeApp", tokenValue, {
    httpOnly : true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
})


res.send("Thank you")
})

app.listen(3000, () =>{
    console.log("Server is running")
})