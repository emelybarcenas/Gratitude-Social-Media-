require ("dotenv").config()
const jwt = require("jsonwebtoken")
const sanitizeHTML = require("sanitize-html")
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

db.prepare(`
    CREATE TABLE IF NOT EXISTS posts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER, 
    FOREIGN KEY (authorid) REFERENCES users (id)
    )`).run()
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

//Render dashboard if logged in, render homepage if logged out
app.get("/", (req, res) => {
    if (req.user){
        const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ?")
        const posts = postsStatement.all(req.user.userid)
        return res.render("dashboard", {posts})
    }
res.render("homepage")
})
app.get("/logout", (req, res) => {
    res.clearCookie("GratitudeApp")
    res.redirect("/")
})

app.get("/login", (req, res) =>{
    res.render("login")
})

app.post("/login", (req, res) =>{
    
    let errors = []
   
    let inputusername = req.body.username;
    let password = req.body.password;
   
    //Input validation when trying to log in 
    if (typeof inputusername !== "string") inputusername = ""
    if (typeof password !== "string") inputusername = ""
    if (inputusername.trim() == "") errors = ["Invalid username/password."]
    if (inputusername.trim() == "") errors = ["Invalid username/password."]

    if(errors.length){
        return res.render("login",{errors})
    }
    //Checking if username and password are in database

    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(inputusername)

    if (!userInQuestion){
         errors = ["Invalid username/password"]
         return res.render("login", {errors})
    }

    //Checking if password matches what is in the database
    const matchOrNot = bcrypt.compareSync(password,userInQuestion.password)
    if (!matchOrNot){
        errors = ["Invalid username/password"]
        return res.render("login", {errors})
   }

   //Give them a cookie 
   const tokenValue = jwt.sign({ exp: Math.floor(Date.now()/1000) + 60 * 60 * 24, userid: userInQuestion.id, username: userInQuestion.username}, process.env.JWTSECRET)
   res.cookie ("GratitudeApp", tokenValue, {
       httpOnly : true,
       secure: true,
       sameSite: "strict",
       maxAge: 1000 * 60 * 60 * 24
   })

   res.redirect("/")

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

//Check if username exists already
 const usernameStatement = db. prepare("SELECT * FROM users WHERE username =?")
 const usernameCheck = usernameStatement.get(inputusername)

 if(usernameCheck) errors.push("Username is already taken.")

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


res.redirect("/")
})

function mustBeLoggedIn(req, res, next){
    if(req.user){
        return next()
    }
    return res.redirect("/")
}

app.get("/create-post", mustBeLoggedIn, (req, res) =>{
    res.render("create-post")
})
//Validate post
function sharedPostValidation(req){
const errors = []

let inputTitle = req.body.title
let inputBody = req.body.body

//Checking if not a string
if (typeof inputTitle !== "string") inputTitle = ""
if (typeof inputBody !== "string") inputBody = ""

//Sanitize out html 
inputTitle = sanitizeHTML(inputTitle.trim(),{allowedTags: [], allowedAttributes: {}})
inputBody = sanitizeHTML(inputBody.trim(),{allowedTags: [], allowedAttributes: {}})

//Checking if input empty
if (!inputTitle){
    errors.push("You must provide a title.")
}
if(!inputBody){
    errors.push("You must provide content.")
}
return errors
}

app.get("/post/:id", (req, res) => {
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)
    if (!post){
        return res.redirect("/")
    }
        // Log the post object to verify it contains the expected data
        console.log(post); 
        const isAuthor = post.authorid === req.user.userid
    res.render("single-post", {post, isAuthor})

})
app.post("/create-post", mustBeLoggedIn, (req, res) =>{
    const errors = sharedPostValidation(req)
    
    if(errors.length){
        return res.render("create-post", {errors})
    }
    
    //Save into database
    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?) ")
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const realPost = getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${realPost.id}`)

})

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) =>{  
    // Look up post in question  
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")  
    const post = statement.get(req.params.id)  
   
    // If not author, redirect to homepage  
    if (post.authorid !== req.user.userid || !post) {  
       return res.redirect("/"); // Redirect if user is not logged in or is not the author  
    }  
   
    res.render("edit-post", {post})  
 })  
   

 app.post("/edit-post/:id", mustBeLoggedIn, (req, res) =>{  
    // Look up post in question  
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")  
    const post = statement.get(req.params.id)  
   
    // If not author, redirect to homepage  
    if (post.authorid !== req.user.userid || !post) {  
       return res.redirect("/"); // Redirect if user is not logged in or is not the author  
    }  
   
    // Update post  
    const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")  
    updateStatement.run(req.body.title, req.body.body, req.params.id)  
   
    res.redirect("/post/" + req.params.id) // Redirect to the updated post  
 })
app.post("/delete-post/:id", mustBeLoggedIn, (req, res) =>{
     
    // Look up post in question  
     const statement = db.prepare("SELECT * FROM posts WHERE id = ?")  
     const post = statement.get(req.params.id)  
    
     // If not author, redirect to homepage  
     if (post.authorid !== req.user.userid || !post) {  
        return res.redirect("/"); // Redirect if user is not logged in or is not the author  
     }  

     const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?")
     deleteStatement.run(req.params.id)

     res.redirect("/")
})
app.listen(3000, () =>{
    console.log("Server is running")
})